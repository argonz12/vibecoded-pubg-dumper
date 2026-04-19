#include "dumper.h"
#include <cstdio>

static uint32_t align_up(uint32_t val, uint32_t alignment) {
	if (alignment == 0) return val;
	return (val + alignment - 1) & ~(alignment - 1);
}

bool dumper::read_pe_headers(uint64_t mod_base) {
	mod_base_ = mod_base;

	// read DOS header
	uint16_t mz = proc_.read<uint16_t>(mod_base);
	if (mz != 0x5A4D) {
		printf("[-] bad MZ at base 0x%llX: 0x%04X\n", mod_base, mz);
		return false;
	}

	e_lfanew_ = proc_.read<uint32_t>(mod_base + 0x3C);
	printf("[*] e_lfanew: 0x%X\n", e_lfanew_);

	// verify PE signature
	uint32_t pe_sig = proc_.read<uint32_t>(mod_base + e_lfanew_);
	if (pe_sig != 0x00004550) {
		printf("[-] bad PE sig: 0x%08X\n", pe_sig);
		return false;
	}

	uint64_t coff = mod_base + e_lfanew_ + 4;
	num_sections_ = proc_.read<uint16_t>(coff + 2);
	optional_hdr_size_ = proc_.read<uint16_t>(coff + 16);

	uint64_t opt_hdr = coff + 20;
	uint16_t magic = proc_.read<uint16_t>(opt_hdr);
	is_pe64_ = (magic == 0x20B);

	section_align_ = proc_.read<uint32_t>(opt_hdr + 32);
	file_align_ = proc_.read<uint32_t>(opt_hdr + 36);
	size_of_image_ = proc_.read<uint32_t>(opt_hdr + 56);

	printf("[*] PE%s, %u sections, SizeOfImage=0x%X\n",
		is_pe64_ ? "32+" : "32", num_sections_, size_of_image_);
	printf("[*] section align=0x%X, file align=0x%X\n", section_align_, file_align_);

	return true;
}

bool dumper::read_sections(uint64_t mod_base) {
	uint64_t coff = mod_base + e_lfanew_ + 4;
	uint64_t opt_hdr = coff + 20;
	uint64_t sec_table = opt_hdr + optional_hdr_size_;

	sections_.clear();
	for (uint32_t i = 0; i < num_sections_; i++) {
		uint64_t sec_off = sec_table + (i * 40);

		remote_section sec{};
		// read name
		proc_.read_raw(sec_off, sec.name, 8);
		sec.name[8] = '\0';
		sec.vsize = proc_.read<uint32_t>(sec_off + 8);
		sec.va = proc_.read<uint32_t>(sec_off + 12);
		sec.raw_size = proc_.read<uint32_t>(sec_off + 16);
		sec.raw_ptr = proc_.read<uint32_t>(sec_off + 20);
		sec.chars = proc_.read<uint32_t>(sec_off + 36);

		printf("    [%2u] %-8s  VA=0x%08X  VSize=0x%08X  Chars=0x%08X\n",
			i, sec.name, sec.va, sec.vsize, sec.chars);

		sections_.push_back(sec);
	}

	return !sections_.empty();
}

bool dumper::read_image(uint64_t mod_base) {
	// allocate full image buffer
	image_.resize(size_of_image_, 0);

	// read headers first (up to first section VA or SizeOfHeaders)
	uint32_t hdr_size = sections_.empty() ? 0x1000 : sections_[0].va;
	printf("[*] reading headers (%u bytes)...\n", hdr_size);
	if (!proc_.read_raw(mod_base, image_.data(), hdr_size)) {
		printf("[!] failed to read headers, trying page by page...\n");
		// read page by page — some pages may be unreadable
		for (uint32_t off = 0; off < hdr_size; off += 0x1000) {
			proc_.read_raw(mod_base + off, image_.data() + off, min((uint32_t)0x1000, hdr_size - off));
		}
	}

	// read each section from its VA
	for (size_t i = 0; i < sections_.size(); i++) {
		auto& sec = sections_[i];
		uint32_t read_size = sec.vsize;

		// clamp to image bounds
		if (sec.va + read_size > size_of_image_)
			read_size = size_of_image_ - sec.va;

		printf("[*] reading %-8s @ 0x%08X (%u bytes)...\n", sec.name, sec.va, read_size);

		// read in 1MB chunks — handles partial reads gracefully
		uint32_t chunk_size = 0x100000;
		uint32_t bytes_read = 0;
		uint32_t failed_pages = 0;

		for (uint32_t off = 0; off < read_size; off += chunk_size) {
			uint32_t to_read = min(chunk_size, read_size - off);
			if (proc_.read_raw(mod_base + sec.va + off, image_.data() + sec.va + off, to_read)) {
				bytes_read += to_read;
			} else {
				// try page by page for partial reads
				for (uint32_t pg = 0; pg < to_read; pg += 0x1000) {
					uint32_t pg_size = min((uint32_t)0x1000, to_read - pg);
					if (proc_.read_raw(mod_base + sec.va + off + pg, image_.data() + sec.va + off + pg, pg_size))
						bytes_read += pg_size;
					else
						failed_pages++;
				}
			}
		}

		if (failed_pages > 0)
			printf("[!] %-8s: %u pages unreadable\n", sec.name, failed_pages);
		else
			printf("[+] %-8s: ok (%u bytes)\n", sec.name, bytes_read);
	}

	return true;
}

void dumper::fix_headers() {
	if (image_.size() < e_lfanew_ + 4)
		return;

	auto read_u16 = [&](uint32_t off) -> uint16_t {
		return *(uint16_t*)(image_.data() + off);
	};
	auto read_u32 = [&](uint32_t off) -> uint32_t {
		return *(uint32_t*)(image_.data() + off);
	};
	auto write_u16 = [&](uint32_t off, uint16_t val) {
		*(uint16_t*)(image_.data() + off) = val;
	};
	auto write_u32 = [&](uint32_t off, uint32_t val) {
		*(uint32_t*)(image_.data() + off) = val;
	};
	auto write_u64 = [&](uint32_t off, uint64_t val) {
		*(uint64_t*)(image_.data() + off) = val;
	};

	uint32_t coff = e_lfanew_ + 4;
	uint32_t opt_hdr = coff + 20;
	uint32_t sec_table = opt_hdr + optional_hdr_size_;

	// for a memory dump, each section's raw data starts at its VA in the file
	// so we remap RawPtr = VA and RawSize = aligned VSize
	for (uint32_t i = 0; i < num_sections_; i++) {
		uint32_t sec_off = sec_table + (i * 40);
		uint32_t va = read_u32(sec_off + 12);
		uint32_t vsize = read_u32(sec_off + 8);

		// set raw pointer to VA (flat dump layout)
		write_u32(sec_off + 20, va); // RawPtr = VA
		write_u32(sec_off + 16, align_up(vsize, file_align_)); // RawSize = aligned VSize
	}

	// fix ImageBase to the actual runtime base
	if (is_pe64_) {
		write_u64(opt_hdr + 24, mod_base_);
		printf("[+] ImageBase -> 0x%llX\n", mod_base_);
	} else {
		write_u32(opt_hdr + 28, (uint32_t)mod_base_);
	}

	// strip ASLR
	uint16_t dll_chars = read_u16(opt_hdr + 70);
	dll_chars &= ~0x0040; // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
	write_u16(opt_hdr + 70, dll_chars);

	// force LARGE_ADDRESS_AWARE
	uint16_t chars = read_u16(coff + 18);
	chars |= 0x0020;
	write_u16(coff + 18, chars);

	// zero checksum
	write_u32(opt_hdr + 64, 0);

	// recalc SizeOfHeaders
	uint32_t hdr_end = sec_table + (num_sections_ * 40);
	uint32_t new_size_of_headers = align_up(hdr_end, file_align_);
	write_u32(opt_hdr + 60, new_size_of_headers);

	printf("[+] headers fixed — ASLR stripped, raw pointers remapped\n");
}

bool dumper::write_output(const std::string& path) {
	// create output directory if needed
	auto parent = std::filesystem::path(path).parent_path();
	if (!parent.empty())
		std::filesystem::create_directories(parent);

	std::ofstream file(path, std::ios::binary);
	if (!file.is_open()) {
		printf("[-] failed to create output file: %s\n", path.c_str());
		return false;
	}

	file.write((const char*)image_.data(), image_.size());
	file.close();

	printf("[+] wrote %llu bytes to: %s\n", (uint64_t)image_.size(), path.c_str());
	return true;
}

bool dumper::dump_to_file(const std::string& output_path) {
	uint64_t base = proc_.base();
	printf("[*] dumping main module from base 0x%llX\n\n", base);

	if (!read_pe_headers(base))
		return false;

	if (!read_sections(base))
		return false;

	printf("\n");
	if (!read_image(base))
		return false;

	printf("\n");
	fix_headers();

	printf("\n");
	return write_output(output_path);
}

bool dumper::dump_module(const char* mod_name, const std::string& output_path) {
	uint64_t base = proc_.get_module_base(mod_name);
	if (!base) {
		printf("[-] module '%s' not found\n", mod_name);
		return false;
	}
	printf("[*] dumping module '%s' from base 0x%llX\n\n", mod_name, base);

	// temporarily override base for this dump
	uint64_t saved = mod_base_;
	mod_base_ = base;

	if (!read_pe_headers(base))
		return false;

	if (!read_sections(base))
		return false;

	printf("\n");
	if (!read_image(base))
		return false;

	printf("\n");
	fix_headers();

	printf("\n");
	bool ok = write_output(output_path);

	mod_base_ = saved;
	return ok;
}
