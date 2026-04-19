#pragma once
#include "process.h"
#include "xenuine.h"
#include "ue4_types.h"
#include "mem_cache.h"
#include "sig_scanner.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <functional>
#include <fstream>
#include <mutex>
#include <atomic>
#include <memory>

// external SDK dumper for PUBG (Xenuine encrypted UE4)
// copies xe decrypt stub from target process and calls it locally
// to resolve GObjects array, FNamePool entries, and UObject fields
//
// v2 improvements:
//   - local memory cache (bulk-read objects once, analyze offline)
//   - sig scanner with Zydis (extract decrypt params from dumped PE)
//   - proper BoolProperty handling (FieldSize/ByteOffset/ByteMask/FieldMask)
//   - multithreaded package processing

class sdk_dumper {
public:
	sdk_dumper(process& proc) : proc_(proc), cache_(proc) {}
	~sdk_dumper();

	// set the dumped PE image for sig scanning
	void set_pe_image(const uint8_t* image, size_t size, uint64_t base);

	// full SDK dump — writes per-package headers + combined file to output_dir
	bool dump(const std::string& output_dir);

private:
	process& proc_;
	mem_cache cache_;
	std::unique_ptr<sig_scanner> scanner_;
	scan_results scan_; // dynamically resolved values from PE

	// ── xe decrypt stub ──
	void* xe_stub_ = nullptr;
	uint64_t xe_stub_addr_ = 0;

	using xe_read_fn = uint64_t(__fastcall*)(uint32_t key, uint64_t encrypted);
	xe_read_fn xe_read_ = nullptr;

	bool init_xe_stub();
	uint64_t xe_call(uint32_t key, uint64_t arg = 0);

	// ── GObjects ──
	int32_t gobjects_count_ = 0;
	uint64_t gobjects_array_ = 0;

	bool init_gobjects();
	uint64_t get_object_ptr(int32_t index);

	// ── FNamePool ──
	uint64_t fnamepool_ = 0;
	uint64_t fnamepool_chunks_ = 0;

	bool init_fnamepool();
	std::string resolve_fname(int32_t index);
	std::string resolve_fname_from_raw(uint32_t enc_number, uint32_t enc_index);

	// ── UProperty layout (found at runtime) ──
	int32_t uprop_element_size_ = -1;
	int32_t uprop_array_dim_    = -1;
	int32_t uprop_offset_       = -1;  // Offset_Internal (plain int32)
	int32_t uprop_prop_flags_   = -1;

	// ── UObject helpers ──
	struct obj_info {
		uint64_t addr;
		int32_t  index;
		uint64_t class_ptr;
		uint64_t outer_ptr;
		std::string name;
		int32_t  fname_number;
	};

	bool read_uobject(uint64_t addr, obj_info& out);
	std::string get_object_name(uint64_t addr);
	std::string get_full_name(uint64_t addr);
	std::string get_class_name(uint64_t addr);
	std::string get_object_path(uint64_t addr);
	uint32_t read_property_offset(uint64_t prop_ptr);

	// ── property info ──
	struct prop_info {
		std::string name;
		std::string type_str;   // "int32", "float", "struct FVector", etc.
		uint32_t offset;        // Offset_Internal (decrypted)
		int32_t  element_size;
		int32_t  array_dim;
		uint64_t prop_flags;
		bool     is_bool_bitfield; // BoolProperty with FieldMask != 0xFF
		bool     is_native_bool;   // BoolProperty with FieldMask == 0xFF
		uint8_t  bool_field_size;  // UBoolProperty::FieldSize
		uint8_t  bool_byte_offset; // UBoolProperty::ByteOffset
		uint8_t  bool_byte_mask;   // UBoolProperty::ByteMask
		uint8_t  bool_field_mask;  // UBoolProperty::FieldMask
	};

	// ── function info ──
	struct func_info {
		std::string name;
		uint32_t func_flags;
		uint64_t func_ptr;       // native function pointer (RVA)
		std::vector<prop_info> params;
		std::string return_type;
	};

	// ── class/struct info ──
	struct class_info {
		uint64_t addr;
		std::string name;
		std::string type_prefix;        // "U", "A", "F" (struct), "E" (enum)
		std::string package_name;
		std::string super_name;
		int32_t  struct_size;
		int32_t  super_size;
		std::vector<prop_info> properties;
		std::vector<func_info> functions;
	};

	// walk FField/UField property chain and collect prop_info
	std::vector<prop_info> walk_properties(uint64_t struct_addr);
	std::string resolve_prop_type(uint64_t prop_addr, uint64_t cast_flags);
	std::string resolve_prop_type_from_class(uint64_t prop_addr, const std::string& class_name);
	uint64_t get_prop_cast_flags(uint64_t prop_addr);

	// property offset calibration
	bool find_uprop_offsets();

	// walk UFunction children
	std::vector<func_info> walk_functions(uint64_t struct_addr);
	std::string format_func_flags(uint32_t flags);

	// build class_info for a UClass/UScriptStruct
	class_info build_class_info(uint64_t addr);

	// formatting
	void emit_class_header(std::ostream& out, const class_info& ci);
	std::string struct_prefix(const std::string& class_type_name);

	// ── caches ──
	std::unordered_map<uint64_t, std::string> name_cache_;
	std::unordered_map<int32_t, std::string>  fname_cache_;
	std::unordered_map<uint64_t, class_info>  class_cache_;

	// thread-safe fname cache for parallel package processing
	mutable std::mutex fname_mutex_;
	mutable std::mutex name_mutex_;
	mutable std::mutex class_mutex_;
};
