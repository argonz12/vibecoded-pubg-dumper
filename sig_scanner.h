#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <functional>
#include <intrin.h>

// pattern scanner for the local PE dump
// uses ida-style signatures with wildcards for constants
// Zydis extracts actual values from matched code

struct sig_match {
	uint64_t rva;      // offset from image base in the dump
	uint64_t abs_addr; // dump_base + rva
};

// ── runtime decryptors ──
// populated by Zydis analysis of the dumped PE
// formula (32-bit fields):
//   v = enc ^ xor1
//   rotated = ROR(v, rot)
//   shifted = (v << shl_val) | ((v >> shr_val) & shr_mask)
//   result  = rotated ^ shifted ^ xor2

struct xe_decrypt32 {
	uint32_t xor1 = 0;
	uint32_t xor2 = 0;
	uint32_t shr_mask = 0;
	uint8_t rot = 0;
	uint8_t shr_val = 0;
	uint8_t shl_val = 0;
	bool valid = false;

	int32_t decrypt(uint32_t enc) const {
		uint32_t v = enc ^ xor1;
		uint32_t rotated = _rotr(v, rot);
		uint32_t shifted = (v << shl_val) | ((v >> shr_val) & shr_mask);
		return static_cast<int32_t>(rotated ^ shifted ^ xor2);
	}
};

// 64-bit type A: same structure as 32-bit (ClassPrivate)
struct xe_decrypt64a {
	uint64_t xor1 = 0;
	uint64_t xor2 = 0;
	uint64_t shr_mask = 0;
	uint8_t rot = 0;
	uint8_t shr_val = 0;
	uint8_t shl_val = 0;
	bool valid = false;

	uint64_t decrypt(uint64_t enc) const {
		uint64_t v = enc ^ xor1;
		uint64_t rotated = _rotr64(v, rot);
		uint64_t shifted = (v << shl_val) | ((v >> shr_val) & shr_mask);
		return rotated ^ shifted ^ xor2;
	}
};

// 64-bit type B: and-mask before shift (OuterPrivate)
struct xe_decrypt64b {
	uint64_t xor1 = 0;
	uint64_t xor2 = 0;
	uint64_t and_mask = 0;
	uint8_t rot = 0;
	uint8_t shl_val = 0;
	bool valid = false;

	uint64_t decrypt(uint64_t enc) const {
		uint64_t v = enc ^ xor1;
		uint64_t rotated = _rotr64(v, rot);
		uint64_t shifted = (v & and_mask) << shl_val;
		return rotated ^ shifted ^ xor2;
	}
};

// ── all resolved values from scanning the dumped PE ──
struct scan_results {
	// GObjects globals
	uint64_t gobjects_count_rva = 0;
	uint64_t gobjects_array_rva = 0;

	// xe function pointers
	uint64_t xe_decrypt_fn_rva = 0;    // qword holding xe_decrypt_read fn ptr
	uint64_t xe_secondary_rva = 0;     // qword holding xe cached-path fn ptr
	uint32_t gobjects_xe_key = 0;      // ecx arg for GObjects xe call

	// FNamePool
	uint64_t fnamepool_enc_global_rva = 0; // encrypted outermost pointer global
	uint64_t fnamepool_xe_fn_rva = 0;      // xe fn ptr used by FNamePool code
	uint32_t fnamepool_xe_keys[3] = {};    // xe keys for each chain level

	// UObject field decryptors
	xe_decrypt32 index_decrypt;        // InternalIndex (+0x08)
	xe_decrypt32 fname_index_decrypt;  // FName.ComparisonIndex (+0x20)
	xe_decrypt32 fname_number_decrypt; // FName.Number (+0x1C)
	xe_decrypt64a class_decrypt;       // ClassPrivate (+0x10)
	xe_decrypt64b outer_decrypt;       // OuterPrivate (+0x28)

	bool gobjects_valid = false;
	bool fnamepool_valid = false;
	bool decryptors_valid = false;
};

class sig_scanner {
public:
	sig_scanner(const uint8_t* image, size_t image_size, uint64_t image_base);

	// ida-style pattern scan on .text section
	std::vector<sig_match> scan(const char* ida_sig) const;
	sig_match scan_first(const char* ida_sig) const;

	// resolve RIP-relative operand
	uint64_t resolve_rip_rel(uint64_t insn_rva, int disp_offset, int insn_len) const;

	// main entry: resolve everything dynamically from the PE
	bool resolve_all(scan_results& out) const;

	const uint8_t* image() const { return image_; }
	size_t size() const { return image_size_; }
	uint64_t base() const { return image_base_; }

	const uint8_t* image_;
	size_t image_size_;
	uint64_t image_base_;

	uint32_t text_rva_ = 0;
	uint32_t text_size_ = 0;

	void parse_pe_sections();

	// phase 1: find GObjects decrypt pattern → extract constants + RVAs + xe fn
	bool resolve_gobjects(scan_results& out) const;

	// phase 2: find FNamePool getter → extract encrypted global + xe keys
	bool resolve_fnamepool(scan_results& out) const;

	// phase 3: extract InternalIndex decrypt constants from matched code
	bool extract_index_decrypt(uint64_t pattern_rva, scan_results& out) const;

	// reusable: extract any 32-bit xe decrypt constants from matched SHR/AND/SHL pattern
	bool extract_decrypt32(uint64_t pattern_rva, xe_decrypt32& dec) const;

	// phase 4: find FName/Class/Outer decrypt function → extract all field decrypt constants
	bool resolve_field_decryptors(scan_results& out) const;

	// zydis helpers
	struct insn_info {
		uint64_t addr;
		uint8_t len;
		uint16_t mnemonic;
		int64_t imm;
		int32_t disp;
		uint16_t op0_reg;
		uint8_t mem_base_reg;
		bool has_imm;
		bool has_disp;
		bool is_rip_rel;
	};

	void decode_range(uint64_t start_rva, size_t len,
		const std::function<bool(const insn_info&)>& visitor) const;
};
