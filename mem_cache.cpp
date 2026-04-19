#include "mem_cache.h"
#include "ue4_types.h"
#include <cstdio>
#include <algorithm>

bool mem_cache::cache_gobjects(uint64_t array_ptr, int32_t count) {
	if (!array_ptr || count <= 0) return false;

	gobjects_base_ = array_ptr;
	gobjects_count_ = count;

	size_t total = static_cast<size_t>(count) * FUOBJECTITEM_SIZE;
	gobjects_buf_.resize(total, 0);

	printf("[*] caching GObjects array: %d items (%.1f MB)...\n",
		count, total / (1024.0 * 1024.0));

	// read in 4MB chunks
	constexpr size_t CHUNK = 4 * 1024 * 1024;
	size_t bytes_ok = 0;

	for (size_t off = 0; off < total; off += CHUNK) {
		size_t to_read = min(CHUNK, total - off);
		if (proc_.read_raw(array_ptr + off, gobjects_buf_.data() + off, to_read))
			bytes_ok += to_read;
		else {
			// page-by-page fallback
			for (size_t pg = 0; pg < to_read; pg += 0x1000) {
				size_t pg_sz = min(static_cast<size_t>(0x1000), to_read - pg);
				if (proc_.read_raw(array_ptr + off + pg, gobjects_buf_.data() + off + pg, pg_sz))
					bytes_ok += pg_sz;
			}
		}
	}

	printf("[+] GObjects cached: %.1f MB (%.0f%% ok)\n",
		total / (1024.0 * 1024.0), bytes_ok * 100.0 / total);
	return bytes_ok > total / 2; // pass if at least half readable
}

bool mem_cache::cache_fnamepool_chunks(uint64_t chunks_ptr, int max_blocks) {
	if (!chunks_ptr) return false;

	fname_block_ptrs_.resize(max_blocks, 0);

	// read all block pointers at once (8 bytes each)
	size_t total = max_blocks * 8;
	if (!proc_.read_raw(chunks_ptr, fname_block_ptrs_.data(), total)) {
		// fallback: read individually
		for (int i = 0; i < max_blocks; i++)
			fname_block_ptrs_[i] = proc_.read<uint64_t>(chunks_ptr + 8ull * i);
	}

	int valid = 0;
	for (auto& p : fname_block_ptrs_)
		if (p) valid++;

	printf("[+] FNamePool: %d / %d block pointers cached\n", valid, max_blocks);
	return valid > 0;
}

bool mem_cache::cache_object(uint64_t addr, size_t size) {
	if (!addr) return false;

	if (obj_cache_.count(addr)) return true; // already cached

	std::vector<uint8_t> buf(size, 0);
	if (!proc_.read_raw(addr, buf.data(), size))
		return false;

	obj_cache_.emplace(addr, std::move(buf));
	return true;
}

int mem_cache::cache_all_objects(size_t obj_read_size) {
	if (gobjects_buf_.empty()) return 0;

	printf("[*] bulk-caching %d objects (%.0f bytes each)...\n",
		gobjects_count_, (double)obj_read_size);

	int cached = 0, null_cnt = 0;

	for (int32_t i = 0; i < gobjects_count_; i++) {
		if (i % 100000 == 0 && i > 0)
			printf("[*] cache progress: %d / %d (%d cached)\n", i, gobjects_count_, cached);

		uint64_t obj_ptr = get_object_ptr(i);
		if (!obj_ptr) { null_cnt++; continue; }

		// check pending kill
		int32_t flags = get_object_flags(i);
		if (flags & PENDING_KILL_FLAG) continue;

		if (cache_object(obj_ptr, obj_read_size))
			cached++;
	}

	printf("[+] cached %d objects (%d null, %zu total blobs)\n",
		cached, null_cnt, obj_cache_.size());
	return cached;
}

uint64_t mem_cache::get_object_ptr(int32_t index) const {
	if (index < 0 || index >= gobjects_count_ || gobjects_buf_.empty())
		return 0;
	size_t off = static_cast<size_t>(index) * FUOBJECTITEM_SIZE + fobj_item::object;
	if (off + 8 > gobjects_buf_.size()) return 0;
	return *reinterpret_cast<const uint64_t*>(gobjects_buf_.data() + off);
}

int32_t mem_cache::get_object_flags(int32_t index) const {
	if (index < 0 || index >= gobjects_count_ || gobjects_buf_.empty())
		return 0;
	size_t off = static_cast<size_t>(index) * FUOBJECTITEM_SIZE + fobj_item::flags;
	if (off + 4 > gobjects_buf_.size()) return 0;
	return *reinterpret_cast<const int32_t*>(gobjects_buf_.data() + off);
}

uint64_t mem_cache::get_fname_block_ptr(int32_t block_idx) const {
	if (block_idx < 0 || block_idx >= static_cast<int32_t>(fname_block_ptrs_.size()))
		return 0;
	return fname_block_ptrs_[block_idx];
}

const uint8_t* mem_cache::find_in_cache(uint64_t addr, size_t size) const {
	// check GObjects buffer first
	if (addr >= gobjects_base_ && gobjects_base_ != 0) {
		size_t off = static_cast<size_t>(addr - gobjects_base_);
		if (off + size <= gobjects_buf_.size())
			return gobjects_buf_.data() + off;
	}

	// check object cache
	// find the blob whose base address is <= addr and contains addr+size
	for (auto& [base, data] : obj_cache_) {
		if (addr >= base && addr + size <= base + data.size()) {
			return data.data() + (addr - base);
		}
	}

	return nullptr;
}

bool mem_cache::read(uint64_t addr, void* buf, size_t size) const {
	// try cache first
	{
		const uint8_t* cached = find_in_cache(addr, size);
		if (cached) {
			memcpy(buf, cached, size);
			return true;
		}
	}

	// cache miss — read from driver
	return proc_.read_raw(addr, buf, size);
}

size_t mem_cache::total_cached_bytes() const {
	size_t total = gobjects_buf_.size();
	total += fname_block_ptrs_.size() * 8;
	for (auto& [_, data] : obj_cache_)
		total += data.size();
	return total;
}
