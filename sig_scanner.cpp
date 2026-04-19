#include "sig_scanner.h"
#include "deps/zydis/amalgamated-dist/Zydis.h"
#include <cstdio>
#include <cstring>

sig_scanner::sig_scanner(const uint8_t* image, size_t image_size, uint64_t image_base)
	: image_(image), image_size_(image_size), image_base_(image_base) {
	parse_pe_sections();
}

void sig_scanner::parse_pe_sections() {
	if (image_size_ < 0x40) return;
	uint32_t e_lfanew = *reinterpret_cast<const uint32_t*>(image_ + 0x3C);
	if (e_lfanew + 4 >= image_size_) return;

	uint32_t coff = e_lfanew + 4;
	uint16_t num_sections = *reinterpret_cast<const uint16_t*>(image_ + coff + 2);
	uint16_t opt_size = *reinterpret_cast<const uint16_t*>(image_ + coff + 16);
	uint32_t sec_table = coff + 20 + opt_size;

	for (uint16_t i = 0; i < num_sections; i++) {
		uint32_t sec_off = sec_table + i * 40;
		if (sec_off + 40 > image_size_) break;

		char name[9]{};
		memcpy(name, image_ + sec_off, 8);

		if (strcmp(name, ".text") == 0) {
			text_rva_ = *reinterpret_cast<const uint32_t*>(image_ + sec_off + 12);
			text_size_ = *reinterpret_cast<const uint32_t*>(image_ + sec_off + 8);
			printf("[*] sig_scanner: .text at RVA 0x%X, size 0x%X\n", text_rva_, text_size_);
			return;
		}
	}
	printf("[!] sig_scanner: .text section not found\n");
}

// ── ida-style sig scan ──

std::vector<sig_match> sig_scanner::scan(const char* ida_sig) const {
	std::vector<uint8_t> pattern;
	std::vector<bool> mask;

	const char* cur = ida_sig;
	while (*cur) {
		if (*cur == ' ') { cur++; continue; }
		if (*cur == '?') {
			pattern.push_back(0);
			mask.push_back(false);
			cur++;
			if (*cur == '?') cur++;
			continue;
		}
		uint8_t byte = static_cast<uint8_t>(strtoul(cur, nullptr, 16));
		pattern.push_back(byte);
		mask.push_back(true);
		cur += 2;
	}

	std::vector<sig_match> results;
	if (pattern.empty() || text_size_ == 0) return results;

	const uint8_t* text = image_ + text_rva_;
	size_t scan_end = text_size_ - pattern.size();

	for (size_t i = 0; i <= scan_end; i++) {
		bool match = true;
		for (size_t j = 0; j < pattern.size(); j++) {
			if (mask[j] && text[i + j] != pattern[j]) {
				match = false;
				break;
			}
		}
		if (match) {
			sig_match m;
			m.rva = text_rva_ + static_cast<uint32_t>(i);
			m.abs_addr = image_base_ + m.rva;
			results.push_back(m);
		}
	}
	return results;
}

sig_match sig_scanner::scan_first(const char* ida_sig) const {
	auto results = scan(ida_sig);
	if (results.empty()) return {0, 0};
	return results[0];
}

uint64_t sig_scanner::resolve_rip_rel(uint64_t insn_rva, int disp_offset, int insn_len) const {
	if (insn_rva + disp_offset + 4 > image_size_) return 0;
	int32_t disp = *reinterpret_cast<const int32_t*>(image_ + insn_rva + disp_offset);
	return insn_rva + insn_len + disp;
}

// ── zydis instruction decoder ──

void sig_scanner::decode_range(uint64_t start_rva, size_t len,
	const std::function<bool(const insn_info&)>& visitor) const {

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	const uint8_t* code = image_ + start_rva;
	size_t offset = 0;
	ZydisDecodedInstruction insn;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

	while (offset < len) {
		if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code + offset, len - offset,
			&insn, operands))) {
			offset++;
			continue;
		}

		insn_info info{};
		info.addr = start_rva + offset;
		info.len = static_cast<uint8_t>(insn.length);
		info.mnemonic = insn.mnemonic;
		info.has_imm = false;
		info.has_disp = false;
		info.is_rip_rel = false;
		info.mem_base_reg = 0;

		for (uint8_t i = 0; i < insn.operand_count_visible; i++) {
			if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				info.imm = operands[i].imm.value.s;
				info.has_imm = true;
			}
			if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
				if (operands[i].mem.disp.has_displacement) {
					info.disp = static_cast<int32_t>(operands[i].mem.disp.value);
					info.has_disp = true;
				}
				info.mem_base_reg = static_cast<uint8_t>(operands[i].mem.base);
				if (operands[i].mem.base == ZYDIS_REGISTER_RIP) {
					info.is_rip_rel = true;
				}
			}
			if (i == 0 && operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER) {
				info.op0_reg = static_cast<uint8_t>(operands[i].reg.value);
			}
		}

		if (!visitor(info)) break;
		offset += insn.length;
	}
}

// ── phase 1: resolve GObjects ──
// find: shr reg, ?? / and reg, ???? / shl reg, ?? / or / xor reg, ????
// pattern (register-independent via wildcards):
//   C1 E8 ?? 25 ?? ?? ?? ?? C1 E1 ?? 0B C1 35 ?? ?? ?? ??
// then extract InternalIndex decrypt constants + global RVAs

bool sig_scanner::resolve_gobjects(scan_results& out) const {
	if (text_size_ == 0) return false;

	// wildcarded GObjects decrypt pattern — no hardcoded constants
	auto match = scan_first(
		"C1 E8 ?? 25 ?? ?? ?? ?? C1 E1 ?? 0B C1 35 ?? ?? ?? ??");

	if (!match.rva) {
		printf("[-] gobjects decrypt pattern not found\n");
		return false;
	}

	printf("[+] GObjects decrypt pattern at RVA 0x%llX\n", match.rva);

	// extract InternalIndex constants directly from matched bytes
	extract_index_decrypt(match.rva, out);

	// walk forward from the match to find:
	//   cmp reg, cs:qword_XXX            → gobjects_count
	//   jge / mov rdx, cs:qword_XXX      → gobjects_array
	//   mov r8, cs:qword_XXX             → xe_secondary
	//   mov ecx, IMM32                   → gobjects_xe_key
	//   mov rax, cs:qword_XXX + call rax → xe_decrypt_fn
	uint64_t fwd_start = match.rva + 18;
	size_t fwd_len = 128;

	bool found_count = false;
	bool found_array = false;

	decode_range(fwd_start, fwd_len, [&](const insn_info& info) -> bool {
		// first RIP-rel MOV before the CMP is xe_secondary (mov r8, cs:qword)
		if (info.mnemonic == ZYDIS_MNEMONIC_MOV && info.is_rip_rel && !found_count && !out.xe_secondary_rva) {
			out.xe_secondary_rva = static_cast<uint64_t>(
				static_cast<int64_t>(info.addr + info.len) + info.disp);
		}

		// CMP with RIP-relative → gobjects_count
		if (info.mnemonic == ZYDIS_MNEMONIC_CMP && info.is_rip_rel && !found_count) {
			out.gobjects_count_rva = static_cast<uint64_t>(
				static_cast<int64_t>(info.addr + info.len) + info.disp);
			printf("    gobjects_count RVA: 0x%llX\n", out.gobjects_count_rva);
			found_count = true;
		}

		// MOV with RIP-relative after count → gobjects_array
		if (info.mnemonic == ZYDIS_MNEMONIC_MOV && info.is_rip_rel && found_count && !found_array) {
			out.gobjects_array_rva = static_cast<uint64_t>(
				static_cast<int64_t>(info.addr + info.len) + info.disp);
			printf("    gobjects_array RVA: 0x%llX\n", out.gobjects_array_rva);
			found_array = true;
		}

		// MOV ECX, imm32 → xe key
		if (info.mnemonic == ZYDIS_MNEMONIC_MOV && info.has_imm && found_array && !out.gobjects_xe_key) {
			uint32_t v = static_cast<uint32_t>(info.imm & 0xFFFFFFFF);
			if (v > 0x10000) {
				out.gobjects_xe_key = v;
				printf("    gobjects xe_key: 0x%08X\n", v);
			}
		}

		// MOV RAX, [RIP+disp] after the xe key → xe_decrypt_fn
		if (info.mnemonic == ZYDIS_MNEMONIC_MOV && info.is_rip_rel && out.gobjects_xe_key && !out.xe_decrypt_fn_rva) {
			out.xe_decrypt_fn_rva = static_cast<uint64_t>(
				static_cast<int64_t>(info.addr + info.len) + info.disp);
			printf("    xe_decrypt_fn RVA: 0x%llX\n", out.xe_decrypt_fn_rva);
			return false; // done
		}

		return true;
	});

	out.gobjects_valid = found_count && found_array;
	return out.gobjects_valid;
}

// ── extract InternalIndex decrypt constants from matched pattern ──

bool sig_scanner::extract_index_decrypt(uint64_t pattern_rva, scan_results& out) const {
	// directly read constants from the matched bytes
	// pattern: C1 E8 [shr] 25 [mask4] C1 E1 [shl] 0B C1 35 [xor2_4]
	//          0  1   2    3  4..7    8  9   10   11 12 13 14..17
	const uint8_t* p = image_ + pattern_rva;
	out.index_decrypt.shr_val = p[2];
	out.index_decrypt.shr_mask = *reinterpret_cast<const uint32_t*>(p + 4);
	out.index_decrypt.shl_val = p[10];
	out.index_decrypt.xor2 = *reinterpret_cast<const uint32_t*>(p + 14);

	// walk backward ~64 bytes to find XOR1 and ROT
	uint64_t back_start = pattern_rva > 64 ? pattern_rva - 64 : text_rva_;
	size_t back_len = pattern_rva - back_start;

	uint32_t last_xor1 = 0;
	uint8_t last_rot = 0;
	bool found_xor = false, found_rot = false;

	decode_range(back_start, back_len, [&](const insn_info& info) -> bool {
		// XOR with large imm32 → XOR1 candidate
		if (info.mnemonic == ZYDIS_MNEMONIC_XOR && info.has_imm) {
			uint32_t v = static_cast<uint32_t>(info.imm & 0xFFFFFFFF);
			if (v > 0x10000) {
				last_xor1 = v;
				found_xor = true;
			}
		}
		// ROR with imm8 → ROT
		if (info.mnemonic == ZYDIS_MNEMONIC_ROR && info.has_imm) {
			last_rot = static_cast<uint8_t>(info.imm);
			found_rot = true;
		}
		return true;
	});

	if (found_xor && found_rot) {
		out.index_decrypt.xor1 = last_xor1;
		out.index_decrypt.rot = last_rot;
		out.index_decrypt.valid = true;
		printf("[+] InternalIndex decryptor: XOR1=0x%08X, ROT=%d, SHR=%d, MASK=0x%08X, SHL=%d, XOR2=0x%08X\n",
			last_xor1, last_rot, out.index_decrypt.shr_val,
			out.index_decrypt.shr_mask, out.index_decrypt.shl_val, out.index_decrypt.xor2);
	} else {
		printf("[-] failed to extract InternalIndex XOR1/ROT from context\n");
	}

	return out.index_decrypt.valid;
}

// ── phase 2: resolve FNamePool ──
// find the getter by its prologue, then extract globals + xe keys
// the getter has: cache check (mov rax, [rip+X] / test / jnz), then
// mov rdx, [rip+X] (encrypted global), mov ecx, IMM32 (xe key),
// mov rax, [rip+X] (xe fn ptr), call rax

bool sig_scanner::resolve_fnamepool(scan_results& out) const {
	if (text_size_ == 0) return false;

	auto match = scan_first(
		"48 89 5C 24 18 48 89 74 24 20 57 48 83 EC 20 48 8B F9 E8");

	if (!match.rva) {
		printf("[-] FNamePool getter prologue not found\n");
		return false;
	}

	printf("[+] FNamePool getter at RVA 0x%llX\n", match.rva);

	uint64_t fn_start = match.rva;
	size_t fn_len = 512;

	int xe_key_count = 0;
	bool found_enc_global = false;
	bool found_xe_fn = false;

	// skip prologue + xe init calls + TLS setup (~100 bytes)
	uint64_t body_start = fn_start + 60;

	// the function body starts with:
	//   mov rax, cs:qword_XXX  ← xe cache check (into RAX for test/jnz)
	//   test rax, rax
	//   jnz (fast path)
	//   mov rdx, cs:qword_XXX  ← encrypted global (into RDX = 2nd arg for xe call)
	//   mov ecx, IMM32         ← xe key (into ECX = 1st arg)
	//   mov rax, cs:qword_XXX  ← xe fn ptr
	//   call rax
	//
	// key fix: only accept RIP-rel MOV into RDX for the encrypted global
	// (the cache check uses RAX, which we skip)

	decode_range(body_start, fn_len - 60, [&](const insn_info& info) -> bool {
		// mov rdx, [rip+disp] → encrypted FNamePool global
		// must be RDX (2nd arg in xe calling convention)
		if (info.mnemonic == ZYDIS_MNEMONIC_MOV && info.is_rip_rel && !found_enc_global
			&& info.op0_reg == ZYDIS_REGISTER_RDX) {
			uint64_t target = static_cast<uint64_t>(
				static_cast<int64_t>(info.addr + info.len) + info.disp);
			if (target > 0x1000000) {
				out.fnamepool_enc_global_rva = target;
				printf("    fnamepool encrypted global RVA: 0x%llX\n", target);
				found_enc_global = true;
			}
		}

		// mov ecx, imm32 → xe key (collect up to 3)
		if (info.mnemonic == ZYDIS_MNEMONIC_MOV && info.has_imm && !info.has_disp) {
			uint32_t v = static_cast<uint32_t>(info.imm & 0xFFFFFFFF);
			if (v > 0x10000 && xe_key_count < 3) {
				out.fnamepool_xe_keys[xe_key_count] = v;
				printf("    fnamepool xe_key[%d]: 0x%08X\n", xe_key_count, v);
				xe_key_count++;
			}
		}

		// mov rax, [rip+disp] after encrypted global → xe fn ptr
		if (info.mnemonic == ZYDIS_MNEMONIC_MOV && info.is_rip_rel && found_enc_global && !found_xe_fn
			&& info.op0_reg == ZYDIS_REGISTER_RAX) {
			uint64_t target = static_cast<uint64_t>(
				static_cast<int64_t>(info.addr + info.len) + info.disp);
			if (target > 0x1000000 && target != out.fnamepool_enc_global_rva) {
				out.fnamepool_xe_fn_rva = target;
				printf("    fnamepool xe_fn RVA: 0x%llX\n", target);
				found_xe_fn = true;
			}
		}

		if (found_enc_global && xe_key_count >= 2 && found_xe_fn)
			return false;

		return true;
	});

	out.fnamepool_valid = found_enc_global;
	return out.fnamepool_valid;
}

// ── reusable 32-bit xe decrypt constant extractor ──
// given the RVA of a matched SHR/AND/SHL/OR pattern:
//   C1 E8 [shr] 25 [mask4] C1 E1 [shl] 0B C1
// extracts all 6 constants: XOR1, ROT (backward), SHR, MASK, SHL (from bytes), XOR2 (forward)

bool sig_scanner::extract_decrypt32(uint64_t pattern_rva, xe_decrypt32& dec) const {
	const uint8_t* p = image_ + pattern_rva;
	// pattern: C1 E8 [shr] 25 [mask4] C1 E1 [shl] 0B C1
	//          0  1   2    3  4..7    8  9   10   11 12
	dec.shr_val = p[2];
	dec.shr_mask = *reinterpret_cast<const uint32_t*>(p + 4);
	dec.shl_val = p[10];

	// find XOR2: decode forward from pattern + 13 (after OR EAX,ECX)
	// might be direct (xor eax, imm32) or indirect (xor reg, reg; xor reg, imm32)
	bool found_xor2 = false;
	decode_range(pattern_rva + 13, 24, [&](const insn_info& info) -> bool {
		if (info.mnemonic == ZYDIS_MNEMONIC_XOR && info.has_imm) {
			uint32_t v = static_cast<uint32_t>(info.imm & 0xFFFFFFFF);
			if (v > 0x1000) {
				dec.xor2 = v;
				found_xor2 = true;
				return false;
			}
		}
		return true;
	});

	// find XOR1 and ROT: walk backward ~64 bytes
	uint64_t back_start = pattern_rva > 64 ? pattern_rva - 64 : text_rva_;
	size_t back_len = pattern_rva - back_start;

	uint32_t last_xor1 = 0;
	uint8_t last_rot = 0;
	bool found_xor = false, found_rot = false;

	decode_range(back_start, back_len, [&](const insn_info& info) -> bool {
		if (info.mnemonic == ZYDIS_MNEMONIC_XOR && info.has_imm) {
			uint32_t v = static_cast<uint32_t>(info.imm & 0xFFFFFFFF);
			if (v > 0x10000) {
				last_xor1 = v;
				found_xor = true;
			}
		}
		if (info.mnemonic == ZYDIS_MNEMONIC_ROR && info.has_imm) {
			last_rot = static_cast<uint8_t>(info.imm);
			found_rot = true;
		}
		return true;
	});

	if (found_xor && found_rot && found_xor2) {
		dec.xor1 = last_xor1;
		dec.rot = last_rot;
		dec.valid = true;
	}

	return dec.valid;
}

// ── phase 3: resolve all UObject field decryptors ──
// anchors on the OuterPrivate decrypt loop which reads UObject+0x28 in a loop:
//   mov rax,[reg+28h]; xor; ror; and(sign-ext); shl; xor; xor; jnz
// after the loop: FName.Number decrypt, FName.Index decrypt, then ClassPrivate

bool sig_scanner::resolve_field_decryptors(scan_results& out) const {
	if (text_size_ == 0) return false;

	// find OuterPrivate decrypt loop by structural pattern
	auto outer_match = scan_first(
		"48 8B ?? 28 48 33 ?? 48 8B ?? 48 C1 ?? ?? 48 83 ?? ?? 48 C1 ?? ?? ?? 33 ?? 48 33 ?? 75");

	if (!outer_match.rva) {
		printf("[-] OuterPrivate loop pattern not found\n");
		return false;
	}

	printf("[+] OuterPrivate loop at RVA 0x%llX\n", outer_match.rva);

	// ---- OuterPrivate constants ----
	// extract ROR/AND/SHL from the loop body (29 bytes)
	decode_range(outer_match.rva, 30, [&](const insn_info& info) -> bool {
		if (info.mnemonic == ZYDIS_MNEMONIC_ROR && info.has_imm)
			out.outer_decrypt.rot = static_cast<uint8_t>(info.imm);
		if (info.mnemonic == ZYDIS_MNEMONIC_AND && info.has_imm)
			out.outer_decrypt.and_mask = static_cast<uint64_t>(info.imm);
		if (info.mnemonic == ZYDIS_MNEMONIC_SHL && info.has_imm)
			out.outer_decrypt.shl_val = static_cast<uint8_t>(info.imm);
		return true;
	});

	// walk backward ~40 bytes for two MOVABS (XOR1, XOR2)
	uint64_t back_start = outer_match.rva > 40 ? outer_match.rva - 40 : text_rva_;
	size_t back_len = outer_match.rva - back_start;

	uint64_t outer_imm64[2] = {};
	int outer_imm_count = 0;

	decode_range(back_start, back_len, [&](const insn_info& info) -> bool {
		if (info.mnemonic == ZYDIS_MNEMONIC_MOV && info.has_imm && !info.has_disp && !info.is_rip_rel) {
			uint64_t v = static_cast<uint64_t>(info.imm);
			if (v > 0xFFFFFFFFull && outer_imm_count < 2)
				outer_imm64[outer_imm_count++] = v;
		}
		return true;
	});

	if (outer_imm_count >= 2) {
		out.outer_decrypt.xor1 = outer_imm64[0];
		out.outer_decrypt.xor2 = outer_imm64[1];
		out.outer_decrypt.valid = true;
		printf("[+] OuterPrivate: XOR1=0x%llX, ROT=%d, AND=0x%llX, SHL=%d, XOR2=0x%llX\n",
			out.outer_decrypt.xor1, out.outer_decrypt.rot,
			out.outer_decrypt.and_mask, out.outer_decrypt.shl_val, out.outer_decrypt.xor2);
	} else {
		printf("[-] OuterPrivate: failed to find MOVABS constants (found %d)\n", outer_imm_count);
	}

	// ---- FName.Number and FName.Index ----
	// after the JNZ (loop end), two 32-bit decrypt sequences follow:
	//   xor ecx, XOR1 → ror reg, ROT → shr eax, N → and eax, MASK → shl ecx, N → or → xor reg, XOR2
	// pattern length = 29 bytes, JNZ = byte 28 (2-byte insn), post-loop starts at +30
	uint64_t post_loop = outer_match.rva + 30;

	struct decrypt32_state {
		xe_decrypt32 dec;
		bool got_xor1 = false, got_rot = false, got_shr = false;
		bool got_mask = false, got_shl = false, got_xor2 = false;
	};

	decrypt32_state seqs[2]; // [0] = FName.Number, [1] = FName.Index
	int cur_seq = -1;

	decode_range(post_loop, 120, [&](const insn_info& info) -> bool {
		// xor reg, imm32 → either starts new sequence (XOR1) or finishes current (XOR2)
		if (info.mnemonic == ZYDIS_MNEMONIC_XOR && info.has_imm) {
			uint32_t v = static_cast<uint32_t>(info.imm & 0xFFFFFFFF);
			if (v > 0x1000) {
				if (cur_seq >= 0 && seqs[cur_seq].got_shl && !seqs[cur_seq].got_xor2) {
					seqs[cur_seq].dec.xor2 = v;
					seqs[cur_seq].got_xor2 = true;
					seqs[cur_seq].dec.valid = true;
				} else if (cur_seq < 1) {
					cur_seq++;
					seqs[cur_seq].dec.xor1 = v;
					seqs[cur_seq].got_xor1 = true;
				}
			}
		}

		if (cur_seq < 0 || cur_seq > 1) return true;
		auto& s = seqs[cur_seq];

		// ror reg, imm8
		if (info.mnemonic == ZYDIS_MNEMONIC_ROR && info.has_imm && s.got_xor1 && !s.got_rot) {
			s.dec.rot = static_cast<uint8_t>(info.imm);
			s.got_rot = true;
		}
		// shr reg, imm (D1 opcode for shift-by-1 may not report has_imm)
		if (info.mnemonic == ZYDIS_MNEMONIC_SHR && s.got_rot && !s.got_shr) {
			s.dec.shr_val = info.has_imm ? static_cast<uint8_t>(info.imm) : 1;
			s.got_shr = true;
		}
		// and reg, imm32
		if (info.mnemonic == ZYDIS_MNEMONIC_AND && info.has_imm && s.got_shr && !s.got_mask) {
			s.dec.shr_mask = static_cast<uint32_t>(info.imm & 0xFFFFFFFF);
			s.got_mask = true;
		}
		// shl reg, imm8
		if (info.mnemonic == ZYDIS_MNEMONIC_SHL && info.has_imm && s.got_mask && !s.got_shl) {
			s.dec.shl_val = static_cast<uint8_t>(info.imm);
			s.got_shl = true;
		}

		if (cur_seq >= 1 && seqs[1].got_xor2)
			return false;

		return true;
	});

	if (seqs[0].dec.valid) {
		out.fname_number_decrypt = seqs[0].dec;
		printf("[+] FName.Number: XOR1=0x%08X, ROT=%d, SHR=%d, MASK=0x%08X, SHL=%d, XOR2=0x%08X\n",
			out.fname_number_decrypt.xor1, out.fname_number_decrypt.rot,
			out.fname_number_decrypt.shr_val, out.fname_number_decrypt.shr_mask,
			out.fname_number_decrypt.shl_val, out.fname_number_decrypt.xor2);
	} else {
		printf("[-] FName.Number extraction failed\n");
	}

	if (seqs[1].dec.valid) {
		out.fname_index_decrypt = seqs[1].dec;
		printf("[+] FName.Index: XOR1=0x%08X, ROT=%d, SHR=%d, MASK=0x%08X, SHL=%d, XOR2=0x%08X\n",
			out.fname_index_decrypt.xor1, out.fname_index_decrypt.rot,
			out.fname_index_decrypt.shr_val, out.fname_index_decrypt.shr_mask,
			out.fname_index_decrypt.shl_val, out.fname_index_decrypt.xor2);
	} else {
		printf("[-] FName.Index extraction failed\n");
	}

	// ---- ClassPrivate (64-bit type A) ----
	// after FName decrypts + a CALL, three MOVABS set up constants: XOR1, MASK, XOR2
	// then the loop body has ROR/SHR/SHL with 64-bit regs
	uint64_t class_start = post_loop + 80;
	size_t class_len = 256;

	uint64_t class_imm64[3] = {};
	int class_imm_count = 0;
	uint8_t class_rot = 0, class_shr = 0, class_shl = 0;
	bool found_class_rot = false, found_class_shr = false, found_class_shl = false;

	decode_range(class_start, class_len, [&](const insn_info& info) -> bool {
		// movabs reg, imm64
		if (info.mnemonic == ZYDIS_MNEMONIC_MOV && info.has_imm && !info.has_disp && !info.is_rip_rel) {
			uint64_t v = static_cast<uint64_t>(info.imm);
			if (v > 0xFFFFFFFFull && class_imm_count < 3)
				class_imm64[class_imm_count++] = v;
		}
		// ror reg, imm8 (64-bit: len >= 4 due to REX prefix)
		if (info.mnemonic == ZYDIS_MNEMONIC_ROR && info.has_imm && class_imm_count >= 3 && info.len >= 4) {
			if (!found_class_rot) { class_rot = static_cast<uint8_t>(info.imm); found_class_rot = true; }
		}
		// shr reg, imm8 (64-bit)
		if (info.mnemonic == ZYDIS_MNEMONIC_SHR && class_imm_count >= 3 && info.len >= 4) {
			if (!found_class_shr) {
				class_shr = info.has_imm ? static_cast<uint8_t>(info.imm) : 1;
				found_class_shr = true;
			}
		}
		// shl reg, imm8 (64-bit, after SHR)
		if (info.mnemonic == ZYDIS_MNEMONIC_SHL && info.has_imm && found_class_shr && info.len >= 4) {
			if (!found_class_shl) { class_shl = static_cast<uint8_t>(info.imm); found_class_shl = true; }
		}
		if (found_class_rot && found_class_shr && found_class_shl)
			return false;
		return true;
	});

	if (class_imm_count >= 3 && found_class_rot && found_class_shr && found_class_shl) {
		out.class_decrypt.xor1 = class_imm64[0];
		out.class_decrypt.shr_mask = class_imm64[1];
		out.class_decrypt.xor2 = class_imm64[2];
		out.class_decrypt.rot = class_rot;
		out.class_decrypt.shr_val = class_shr;
		out.class_decrypt.shl_val = class_shl;
		out.class_decrypt.valid = true;
		printf("[+] ClassPrivate: XOR1=0x%llX, ROT=%d, SHR=%d, MASK=0x%llX, SHL=%d, XOR2=0x%llX\n",
			out.class_decrypt.xor1, out.class_decrypt.rot,
			out.class_decrypt.shr_val, out.class_decrypt.shr_mask,
			out.class_decrypt.shl_val, out.class_decrypt.xor2);
	} else {
		printf("[-] ClassPrivate extraction failed (imms=%d, rot=%d, shr=%d, shl=%d)\n",
			class_imm_count, found_class_rot, found_class_shr, found_class_shl);
	}

	return out.outer_decrypt.valid && seqs[0].dec.valid && seqs[1].dec.valid
		&& out.class_decrypt.valid;
}

// ── main resolution entry point ──

bool sig_scanner::resolve_all(scan_results& out) const {
	printf("[*] sig_scanner: resolving all patterns from PE dump...\n\n");

	bool ok = true;

	if (!resolve_gobjects(out)) {
		printf("[-] GObjects resolution failed\n");
		ok = false;
	}
	printf("\n");

	if (!resolve_fnamepool(out)) {
		printf("[-] FNamePool resolution failed\n");
		ok = false;
	}
	printf("\n");

	if (!resolve_field_decryptors(out)) {
		printf("[-] field decryptor resolution failed\n");
		ok = false;
	}
	printf("\n");

	// use xe_decrypt_fn from GObjects if FNamePool didn't find its own
	if (!out.fnamepool_xe_fn_rva && out.xe_decrypt_fn_rva) {
		out.fnamepool_xe_fn_rva = out.xe_decrypt_fn_rva;
		printf("[*] using GObjects xe_fn for FNamePool\n");
	}

	out.decryptors_valid = out.index_decrypt.valid
		&& out.fname_index_decrypt.valid
		&& out.fname_number_decrypt.valid
		&& out.class_decrypt.valid
		&& out.outer_decrypt.valid;

	printf("[*] sig_scanner summary:\n");
	printf("    gobjects:  %s (count=0x%llX, array=0x%llX)\n",
		out.gobjects_valid ? "OK" : "FAIL", out.gobjects_count_rva, out.gobjects_array_rva);
	printf("    fnamepool: %s (global=0x%llX)\n",
		out.fnamepool_valid ? "OK" : "FAIL", out.fnamepool_enc_global_rva);
	printf("    xe_fn:     0x%llX\n", out.xe_decrypt_fn_rva);
	printf("    index_dec: %s (XOR1=0x%08X, ROT=%d, XOR2=0x%08X)\n",
		out.index_decrypt.valid ? "OK" : "FAIL",
		out.index_decrypt.xor1, out.index_decrypt.rot, out.index_decrypt.xor2);
	printf("    fname_idx: %s (XOR1=0x%08X, ROT=%d, XOR2=0x%08X)\n",
		out.fname_index_decrypt.valid ? "OK" : "FAIL",
		out.fname_index_decrypt.xor1, out.fname_index_decrypt.rot, out.fname_index_decrypt.xor2);
	printf("    fname_num: %s (XOR1=0x%08X, ROT=%d, XOR2=0x%08X)\n",
		out.fname_number_decrypt.valid ? "OK" : "FAIL",
		out.fname_number_decrypt.xor1, out.fname_number_decrypt.rot, out.fname_number_decrypt.xor2);
	printf("    class_dec: %s (XOR1=0x%llX, ROT=%d, XOR2=0x%llX)\n",
		out.class_decrypt.valid ? "OK" : "FAIL",
		out.class_decrypt.xor1, out.class_decrypt.rot, out.class_decrypt.xor2);
	printf("    outer_dec: %s (XOR1=0x%llX, ROT=%d, XOR2=0x%llX)\n",
		out.outer_decrypt.valid ? "OK" : "FAIL",
		out.outer_decrypt.xor1, out.outer_decrypt.rot, out.outer_decrypt.xor2);

	return ok;
}
