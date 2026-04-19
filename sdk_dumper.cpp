#include "sdk_dumper.h"
#include <cstdio>
#include <fstream>
#include <filesystem>

sdk_dumper::~sdk_dumper() {
	if (xe_stub_)
		VirtualFree(xe_stub_, 0, MEM_RELEASE);
}

void sdk_dumper::set_pe_image(const uint8_t* image, size_t size, uint64_t base) {
	scanner_ = std::make_unique<sig_scanner>(image, size, base);
	printf("[+] sig scanner initialized (image base: 0x%llX, size: %.1f MB)\n",
		base, size / (1024.0 * 1024.0));
}

// ── xe decrypt stub setup ──

bool sdk_dumper::init_xe_stub() {
	uint64_t base = proc_.base();

	// xe_decrypt_read pointer resolved by sig scanner
	if (!scan_.xe_decrypt_fn_rva) {
		printf("[-] xe_decrypt_fn RVA not resolved by sig scanner\n");
		return false;
	}

	xe_stub_addr_ = proc_.read<uint64_t>(base + scan_.xe_decrypt_fn_rva);
	if (!xe_stub_addr_) {
		printf("[-] xe_decrypt_read pointer is null (RVA=0x%llX)\n", scan_.xe_decrypt_fn_rva);
		return false;
	}

	printf("[*] xe decrypt fn at: 0x%llX\n", xe_stub_addr_);

	// read the raw function bytes from the target
	uint8_t raw[256]{};
	if (!proc_.read_raw(xe_stub_addr_, raw, sizeof(raw))) {
		printf("[-] failed to read xe stub bytes\n");
		printf("[*] trying page-aligned read...\n");

		// fall back: read the whole page containing the function
		uint64_t page_base = xe_stub_addr_ & ~0xFFFull;
		size_t page_off = static_cast<size_t>(xe_stub_addr_ - page_base);
		uint8_t page[0x1000]{};
		if (!proc_.read_raw(page_base, page, sizeof(page))) {
			printf("[-] page-aligned read also failed\n");
			return false;
		}
		memcpy(raw, page + page_off, min(sizeof(raw), sizeof(page) - page_off));
	}

	printf("[*] first 16 bytes:");
	for (int i = 0; i < 16; i++) printf(" %02X", raw[i]);
	printf("\n");

	// verify LEA RAX,[RIP+disp32] opcode: 48 8D 05 xx xx xx xx
	if (raw[0] != 0x48 || raw[1] != 0x8D || raw[2] != 0x05) {
		printf("[-] xe stub doesn't start with LEA RAX,[RIP+X]: %02X %02X %02X\n",
			raw[0], raw[1], raw[2]);
		return false;
	}

	// resolve the absolute address the LEA was computing
	// LEA RAX,[RIP+disp32] — RIP points past the 7-byte instruction
	int32_t disp = *reinterpret_cast<int32_t*>(raw + 3);
	uint64_t abs_addr = xe_stub_addr_ + disp + 7;
	printf("[*] LEA resolves to absolute: 0x%llX (disp=0x%X)\n", abs_addr, disp);

	// allocate local RWX buffer
	// original: 7-byte LEA - 10-byte MOV RAX,imm64 (+3 bytes expansion)
	constexpr size_t alloc_size = 512;
	xe_stub_ = VirtualAlloc(nullptr, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!xe_stub_) {
		printf("[-] VirtualAlloc for xe stub failed\n");
		return false;
	}
	memset(xe_stub_, 0xCC, alloc_size); // INT3 fill

	auto* buf = static_cast<uint8_t*>(xe_stub_);

	// patch: replace 7-byte LEA RAX,[RIP+disp32] with 10-byte MOV RAX,imm64
	buf[0] = 0x48; // REX.W
	buf[1] = 0xB8; // MOV RAX, imm64
	memcpy(buf + 2, &abs_addr, 8);

	// copy remaining function bytes after the LEA (skip 7, paste at 10)
	// rest of the function is pure register math (no RIP-relative refs)
	memcpy(buf + 10, raw + 7, sizeof(raw) - 7);

	// the xe function signature: uint64_t fn(uint32_t key, uint64_t encrypted)
	// NOTE: the function ignores the key (mov rcx,rdx overwrites it)
	// so xe_call(0, encrypted_value) works
	xe_read_ = reinterpret_cast<xe_read_fn>(buf);

	printf("[+] xe stub patched (LEA -> MOV RAX, 0x%llX)\n", abs_addr);
	printf("[*] patched bytes:");
	for (int i = 0; i < 20; i++) printf(" %02X", buf[i]);
	printf("\n");
	return true;
}

uint64_t sdk_dumper::xe_call(uint32_t key, uint64_t arg) {
	if (!xe_read_)
		return 0;
	return xe_read_(key, arg);
}

// ── GObjects init ──

bool sdk_dumper::init_gobjects() {
	uint64_t base = proc_.base();

	if (!scan_.gobjects_count_rva || !scan_.gobjects_array_rva) {
		printf("[-] GObjects RVAs not resolved by sig scanner\n");
		return false;
	}

	gobjects_count_ = proc_.read<int32_t>(base + scan_.gobjects_count_rva);
	if (gobjects_count_ <= 0 || gobjects_count_ > 1000000) {
		printf("[-] invalid gobjects count: %d (at RVA 0x%llX)\n",
			gobjects_count_, scan_.gobjects_count_rva);
		return false;
	}

	printf("[+] gobjects count: %d\n", gobjects_count_);

	uint64_t enc_array = proc_.read<uint64_t>(base + scan_.gobjects_array_rva);
	printf("[*] gobjects array (encrypted): 0x%llX\n", enc_array);

	uint32_t xe_key = scan_.gobjects_xe_key ? scan_.gobjects_xe_key : 0;
	gobjects_array_ = xe_call(xe_key, enc_array);
	if (!gobjects_array_ || gobjects_array_ > 0x00007FFFFFFFFFFFull) {
		printf("[-] gobjects array decrypt failed: 0x%llX\n", gobjects_array_);
		// try without key
		gobjects_array_ = xe_call(0, enc_array);
		if (!gobjects_array_ || gobjects_array_ > 0x00007FFFFFFFFFFFull) {
			printf("[-] still failed: 0x%llX\n", gobjects_array_);
			return false;
		}
	}

	// verify by reading first FUObjectItem
	uint64_t first_obj = proc_.read<uint64_t>(gobjects_array_);
	if (!first_obj) {
		printf("[-] first FUObjectItem.Object is null\n");
		return false;
	}

	printf("[+] gobjects array: 0x%llX (first obj: 0x%llX)\n", gobjects_array_, first_obj);
	return true;
}

uint64_t sdk_dumper::get_object_ptr(int32_t index) {
	if (index < 0 || index >= gobjects_count_)
		return 0;
	uint64_t item_addr = gobjects_array_ + static_cast<uint64_t>(index) * FUOBJECTITEM_SIZE;
	return proc_.read<uint64_t>(item_addr + fobj_item::object);
}

// ── FNamePool init ──

bool sdk_dumper::init_fnamepool() {
	uint64_t base = proc_.base();

	if (!scan_.fnamepool_enc_global_rva) {
		printf("[-] FNamePool encrypted global RVA not resolved\n");
		return false;
	}

	// 3-level xe-encrypted pointer chain
	// 1. read encrypted ptr from global → xe_call → address
	// 2. read value at decoded address → xe_call → next address
	// 3. repeat → pool pointer
	uint64_t enc3 = proc_.read<uint64_t>(base + scan_.fnamepool_enc_global_rva);
	uint64_t dec3 = xe_call(0, enc3);
	printf("[*] fnamepool chain: enc3=0x%llX → dec3=0x%llX\n", enc3, dec3);

	if (!dec3 || dec3 > 0x00007FFFFFFFFFFFull) {
		printf("[-] fnamepool outer decrypt failed\n");
		return false;
	}

	uint64_t enc2 = proc_.read<uint64_t>(dec3);  // read value stored at middle slot
	uint64_t dec2 = xe_call(0, enc2);  // - game-memory address of qword_E750
	printf("[*] fnamepool chain: enc2=0x%llX - dec2=0x%llX\n", enc2, dec2);

	if (!dec2 || dec2 > 0x00007FFFFFFFFFFFull) {
		printf("[-] fnamepool middle decrypt failed\n");
		return false;
	}

	uint64_t enc1 = proc_.read<uint64_t>(dec2);  // read value stored at inner slot
	fnamepool_ = xe_call(0, enc1);  // - actual pool pointer
	printf("[*] fnamepool chain: enc1=0x%llX - pool=0x%llX\n", enc1, fnamepool_);

	if (!fnamepool_ || fnamepool_ > 0x00007FFFFFFFFFFFull) {
		printf("[-] fnamepool inner decrypt failed\n");
		return false;
	}

	// pool structure (from IDA): 3 xe-encrypted qwords
	//   pool[0] = xe(1212074527, data)
	//   pool[1] = xe(1212074875, data)
	//   pool[2] = xe(1212074826, blocks_array_ptr)  ← this is what we need
	// pool + 16 = pool[2] = encrypted blocks array pointer
	uint64_t enc_chunks = proc_.read<uint64_t>(fnamepool_ + 16);
	fnamepool_chunks_ = xe_call(0, enc_chunks);
	printf("[*] blocks array: enc=0x%llX - dec=0x%llX\n", enc_chunks, fnamepool_chunks_);

	if (!fnamepool_chunks_ || fnamepool_chunks_ > 0x00007FFFFFFFFFFFull) {
		printf("[-] fnamepool blocks decrypt failed\n");
		return false;
	}

	// dump first few block pointers (these are PLAIN pointers)
	printf("[*] block pointers (plain):\n");
	for (int i = 0; i < 8; i++) {
		uint64_t bp = proc_.read<uint64_t>(fnamepool_chunks_ + 8ull * i);
		printf("    blocks[%d] = 0x%llX\n", i, bp);
	}

	// verify: resolve FName 0 (should be "None")
	std::string test = resolve_fname(0);
	printf("[*] fname[0] = \"%s\"\n", test.c_str());

	if (test == "None")
		printf("[+] FNamePool 0 valid!\n");

	return true;
}

std::string sdk_dumper::resolve_fname(int32_t index) {
	if (index < 0)
		return "<invalid>";

	// cap index to sane range — FNamePool shouldn't have millions of entries
	if (index > 2000000) {
		return "<invalid>";
	}

	auto it = fname_cache_.find(index);
	if (it != fname_cache_.end())
		return it->second;

	// decompose: block_idx = index / chunk_size, entry_off = index % chunk_size
	int32_t block_idx = index / static_cast<int32_t>(fname::chunk_size);
	int32_t entry_off = index % static_cast<int32_t>(fname::chunk_size);

	// blocks[block_idx] = plain pointer to an array of 8-byte entry pointers
	uint64_t block_ptr = proc_.read<uint64_t>(fnamepool_chunks_ + 8ull * block_idx);
	if (!block_ptr) {
		fname_cache_[index] = "<null_block>";
		return "<null_block>";
	}

	// entry pointer at block[entry_off] (8-byte stride, plain pointer)
	uint64_t entry_ptr = proc_.read<uint64_t>(block_ptr + 8ull * entry_off);
	if (!entry_ptr) {
		fname_cache_[index] = "<null_entry>";
		return "<null_entry>";
	}

	// FNameEntry layout (from IDA sub_7FF6A43CC210):
	//   +00: xe-encrypted header qword (bit 0 = wide flag after decrypt)
	//   +16: null-terminated string data
	uint64_t enc_hdr = proc_.read<uint64_t>(entry_ptr);
	uint64_t hdr = xe_call(0, enc_hdr);
	bool is_wide = (hdr & 1) != 0;

	std::string result;
	if (is_wide) {
		wchar_t buf[256]{};
		proc_.read_raw(entry_ptr + 16, buf, sizeof(buf) - 2);
		for (int i = 0; i < 255 && buf[i]; i++)
			result += static_cast<char>(buf[i] < 128 ? buf[i] : '?');
	} else {
		char buf[256]{};
		proc_.read_raw(entry_ptr + 16, buf, sizeof(buf) - 1);
		result = buf;
	}

	fname_cache_[index] = result;
	return result;
}

std::string sdk_dumper::resolve_fname_from_raw(uint32_t enc_number, uint32_t enc_index) {
	int32_t index = scan_.fname_index_decrypt.decrypt(enc_index);
	int32_t number = scan_.fname_number_decrypt.decrypt(enc_number);
	std::string name = resolve_fname(index);
	if (number > 0)
		name += "_" + std::to_string(number - 1);
	return name;
}

bool sdk_dumper::read_uobject(uint64_t addr, obj_info& out) {
	if (!addr)
		return false;

	if (addr < 0x10000 || addr > 0x7FFFFFFFFFFF || (addr & 0x7) != 0)
		return false;

	uint8_t raw[UOBJECT_SIZE];
	if (!proc_.read_raw(addr, raw, sizeof(raw)))
		return false;

	out.addr = addr;

	uint32_t enc_idx = *reinterpret_cast<uint32_t*>(raw + uobj::internal_index);
	out.index = scan_.index_decrypt.decrypt(enc_idx);

	uint64_t enc_class = *reinterpret_cast<uint64_t*>(raw + uobj::class_private);
	out.class_ptr = scan_.class_decrypt.decrypt(enc_class);

	uint32_t enc_fname_num = *reinterpret_cast<uint32_t*>(raw + uobj::fname_number);
	uint32_t enc_fname_idx = *reinterpret_cast<uint32_t*>(raw + uobj::fname_index);
	out.fname_number = scan_.fname_number_decrypt.decrypt(enc_fname_num);
	int32_t fname_idx = scan_.fname_index_decrypt.decrypt(enc_fname_idx);

	uint64_t enc_outer = *reinterpret_cast<uint64_t*>(raw + uobj::outer_private);
	out.outer_ptr = scan_.outer_decrypt.decrypt(enc_outer);

	out.name = resolve_fname(fname_idx);
	if (out.fname_number > 0)
		out.name += "_" + std::to_string(out.fname_number - 1);

	return true;
}

uint32_t sdk_dumper::read_property_offset(uint64_t prop_ptr) {
	if (uprop_offset_ == -2) {
		// XE scattered-byte decrypt (Offset_Internal is encrypted)
		uint8_t buf[0x91]{};
		if (!proc_.read_raw(prop_ptr, buf, sizeof(buf)))
			return 0;

		uint32_t enc = static_cast<uint32_t>(buf[0x50])
			| (static_cast<uint32_t>(buf[0x3C]) << 8)
			| (static_cast<uint32_t>(buf[0x70]) << 16)
			| (static_cast<uint32_t>(buf[0x90]) << 24);

		return xe_offset::decrypt_offset_internal(enc, prop_ptr);
	}
	if (uprop_offset_ >= 0)
		return proc_.read<int32_t>(prop_ptr + uprop_offset_);
	return 0;
}

std::string sdk_dumper::get_object_name(uint64_t addr) {
	auto it = name_cache_.find(addr);
	if (it != name_cache_.end())
		return it->second;

	obj_info info;
	if (!read_uobject(addr, info))
		return "<invalid>";

	name_cache_[addr] = info.name;
	return info.name;
}

std::string sdk_dumper::get_class_name(uint64_t addr) {
	obj_info info;
	if (!read_uobject(addr, info))
		return "<unknown>";
	return get_object_name(info.class_ptr);
}

std::string sdk_dumper::get_object_path(uint64_t addr) {
	obj_info info;
	if (!read_uobject(addr, info))
		return "<invalid>";

	std::string path = info.name;
	uint64_t outer = info.outer_ptr;

	for (int depth = 0; depth < 64 && outer; depth++) {
		obj_info outer_info;
		if (!read_uobject(outer, outer_info))
			break;
		path = outer_info.name + "." + path;
		outer = outer_info.outer_ptr;
	}

	return path;
}

std::string sdk_dumper::get_full_name(uint64_t addr) {
	obj_info info;
	if (!read_uobject(addr, info))
		return "<invalid>";

	std::string class_name = get_object_name(info.class_ptr);
	std::string path = get_object_path(addr);

	return class_name + " " + path;
}

// ── property type resolution ──

uint64_t sdk_dumper::get_prop_cast_flags(uint64_t prop_addr) {
	// FField::Class at +0x08 - FFieldClass*
	uint64_t fclass = proc_.read<uint64_t>(prop_addr + ffield::class_ptr);
	if (!fclass) return 0;
	// FFieldClass::CastFlags at +0x10
	return proc_.read<uint64_t>(fclass + ffieldclass::cast_flags);
}

std::string sdk_dumper::resolve_prop_type(uint64_t prop_addr, uint64_t cf) {
	using namespace propflags;

	if (cf & BoolProperty)    return "bool";
	if (cf & ByteProperty)    return "uint8";
	if (cf & Int8Property)    return "int8";
	if (cf & Int16Property)   return "int16";
	if (cf & UInt16Property)  return "uint16";
	if (cf & IntProperty)     return "int32";
	if (cf & UInt32Property)  return "uint32";
	if (cf & Int64Property)   return "int64";
	if (cf & UInt64Property)  return "uint64";
	if (cf & FloatProperty)   return "float";
	if (cf & DoubleProperty)  return "double";
	if (cf & NameProperty)    return "struct FName";
	if (cf & StrProperty)     return "struct FString";
	if (cf & TextProperty)    return "struct FText";

	if (cf & StructProperty) {
		// try to read the inner UScriptStruct* (at prop + 0x48 typical for StructProperty)
		// but 0x48 overlaps with offset area — read carefully
		// StructProperty::Struct is typically at FProperty_base_size + 0x00
		// For PUBG FProperty base = 0x48 bytes, then extra fields start
		// Dumper-7 finds this dynamically; let's try prop + 0x78 (common for UE4.25+)
		uint64_t inner_struct = proc_.read<uint64_t>(prop_addr + 0x78);
		if (inner_struct) {
			std::string sname = get_object_name(inner_struct);
			if (!sname.empty() && sname[0] != '<')
				return "struct F" + sname;
		}
		return "struct F";
	}

	if (cf & ObjectProperty) {
		uint64_t prop_class = proc_.read<uint64_t>(prop_addr + 0x78);
		if (prop_class) {
			std::string cname = get_object_name(prop_class);
			if (!cname.empty() && cname[0] != '<')
				return "struct " + struct_prefix(cname) + cname + "*";
		}
		return "struct F*";
	}

	if (cf & ClassProperty)      return "class UClass*";
	if (cf & InterfaceProperty)  return "struct TScriptInterface";
	if (cf & ArrayProperty)      return "struct TArray<>";
	if (cf & MapProperty)        return "struct TMap<>";
	if (cf & SetProperty)        return "struct TSet<>";
	if (cf & DelegateProperty)   return "struct FDelegate";
	if (cf & MulticastDelegateProperty) return "struct FMulticastDelegate";
	if (cf & SoftObjectProperty) return "struct TSoftObjectPtr";
	if (cf & WeakObjectProperty) return "struct TWeakObjectPtr";
	if (cf & LazyObjectProperty) return "struct TLazyObjectPtr";
	if (cf & EnumProperty)       return "enum class ";
	if (cf & SoftClassProperty)  return "struct TSoftClassPtr";

	return "char";
}

// resolve type from UProperty class name (old property system)
std::string sdk_dumper::resolve_prop_type_from_class(uint64_t prop_addr, const std::string& cls) {
	if (cls == "BoolProperty")      return "bool";
	if (cls == "ByteProperty")      return "uint8";
	if (cls == "Int8Property")      return "int8";
	if (cls == "Int16Property")     return "int16";
	if (cls == "UInt16Property")    return "uint16";
	if (cls == "IntProperty")       return "int32";
	if (cls == "UInt32Property")    return "uint32";
	if (cls == "Int64Property")     return "int64";
	if (cls == "UInt64Property")    return "uint64";
	if (cls == "FloatProperty")     return "float";
	if (cls == "DoubleProperty")    return "double";
	if (cls == "NameProperty")      return "struct FName";
	if (cls == "StrProperty")       return "struct FString";
	if (cls == "TextProperty")      return "struct FText";

	if (cls == "StructProperty") {
		// UStructProperty::Struct is at UProperty_base + 0x00
		// UProperty = 0x98 bytes total, inner struct ptr is at offset 0x78 typically
		uint64_t inner_struct = proc_.read<uint64_t>(prop_addr + 0x78);
		if (inner_struct) {
			std::string sname = get_object_name(inner_struct);
			if (!sname.empty() && sname[0] != '<')
				return "struct F" + sname;
		}
		return "struct F";
	}

	if (cls == "ObjectProperty" || cls == "ObjectPropertyBase") {
		uint64_t prop_class = proc_.read<uint64_t>(prop_addr + 0x78);
		if (prop_class) {
			std::string cname = get_object_name(prop_class);
			if (!cname.empty() && cname[0] != '<')
				return "struct " + struct_prefix(cname) + cname + "*";
		}
		return "struct F*";
	}

	if (cls == "ClassProperty")          return "class UClass*";
	if (cls == "SoftClassProperty")      return "struct TSoftClassPtr";
	if (cls == "InterfaceProperty")      return "struct TScriptInterface";
	if (cls == "ArrayProperty")          return "struct TArray<>";
	if (cls == "MapProperty")            return "struct TMap<>";
	if (cls == "SetProperty")            return "struct TSet<>";
	if (cls == "DelegateProperty")       return "struct FDelegate";
	if (cls == "MulticastDelegateProperty" ||
	    cls == "MulticastInlineDelegateProperty" ||
	    cls == "MulticastSparseDelegateProperty")
	                                     return "struct FMulticastDelegate";
	if (cls == "WeakObjectProperty")     return "struct TWeakObjectPtr";
	if (cls == "LazyObjectProperty")     return "struct TLazyObjectPtr";
	if (cls == "SoftObjectProperty")     return "struct TSoftObjectPtr";
	if (cls == "EnumProperty")           return "enum class ";
	if (cls == "AssetObjectProperty")    return "struct FSoftObjectPath";
	if (cls == "AssetClassProperty")     return "struct FSoftClassPath";

	return "char";
}

// ── walk properties ──
std::vector<sdk_dumper::prop_info> sdk_dumper::walk_properties(uint64_t struct_addr) {
	std::vector<prop_info> props;

	// PUBG uses old UProperty system (UObject-derived, in UField Children chain)
	// Walk Children (UField chain) — UProperty objects
	uint64_t ufield_child = proc_.read<uint64_t>(struct_addr + ustruct::children);
	int field_count = 0;
	while (ufield_child && field_count++ < 2048) {
		obj_info fi;
		if (read_uobject(ufield_child, fi)) {
			std::string cls_name = get_object_name(fi.class_ptr);

			// only process property-like children, skip UFunctions here
			if (cls_name.find("Property") != std::string::npos) {
				prop_info pi{};
				pi.name = fi.name;
				pi.offset = read_property_offset(ufield_child);
				pi.element_size = (uprop_element_size_ >= 0)
					? proc_.read<int32_t>(ufield_child + uprop_element_size_)
					: 0;
				pi.array_dim = (uprop_array_dim_ >= 0)
					? proc_.read<int32_t>(ufield_child + uprop_array_dim_)
					: 1;
				pi.prop_flags = (uprop_prop_flags_ >= 0)
					? proc_.read<uint64_t>(ufield_child + uprop_prop_flags_)
					: 0;
				if (pi.array_dim <= 0) pi.array_dim = 1;

				// resolve type from UProperty class name
				pi.type_str = resolve_prop_type_from_class(ufield_child, cls_name);

				// BoolProperty: read extra fields to distinguish native vs bitfield
				pi.is_bool_bitfield = false;
				pi.is_native_bool = false;
				pi.bool_field_size = 0;
				pi.bool_byte_offset = 0;
				pi.bool_byte_mask = 0;
				pi.bool_field_mask = 0;

				if (cls_name == "BoolProperty") {
					pi.bool_field_size  = proc_.read<uint8_t>(ufield_child + uboolprop::field_size);
					pi.bool_byte_offset = proc_.read<uint8_t>(ufield_child + uboolprop::byte_offset);
					pi.bool_byte_mask   = proc_.read<uint8_t>(ufield_child + uboolprop::byte_mask);
					pi.bool_field_mask  = proc_.read<uint8_t>(ufield_child + uboolprop::field_mask);

					if (pi.bool_field_mask == 0xFF) {
						// native bool — full byte, uses FieldSize for actual storage size
						pi.is_native_bool = true;
						if (pi.element_size <= 0)
							pi.element_size = pi.bool_field_size;
					} else {
						// bitfield bool — packed into a byte with other bools
						pi.is_bool_bitfield = true;
						// for bitfields, offset should account for ByteOffset
						if (pi.offset != 0xFFFFFFFF && pi.offset != 0xFFFFFF9F)
							pi.offset += pi.bool_byte_offset;
					}

					// sanity check: if offset looks like garbage, try reconstructing from
					// the prior property's offset + size (struct alignment)
					if (pi.offset > 0x100000 && pi.offset != 0xFFFFFFFF) {
						printf("[!] BoolProperty '%s' has garbage offset 0x%x — marking for fixup\n",
								pi.name.c_str(), pi.offset);
						pi.offset = 0xFFFFFFFF; // will be fixed up relative to neighbors
					}
				}

				props.push_back(std::move(pi));
			}
		}
		uint64_t next_field = proc_.read<uint64_t>(ufield_child + ufield::next);
		if (next_field == ufield_child) break;
		ufield_child = next_field;
	}

	return props;
}
// ── walk functions ──

std::string sdk_dumper::format_func_flags(uint32_t flags) {
	std::string s;
	auto add = [&](const char* name) { if (!s.empty()) s += "|"; s += name; };
	if (flags & efunc::FUNC_Final)       add("Final");
	if (flags & efunc::FUNC_Net)         add("Net");
	if (flags & efunc::FUNC_NetReliable) add("NetReliable");
	if (flags & efunc::FUNC_Static)      add("Static");
	if (flags & efunc::FUNC_Native)      add("Native");
	if (flags & efunc::FUNC_Event)       add("Event");
	if (flags & efunc::FUNC_Public)      add("Public");
	if (flags & efunc::FUNC_Protected)   add("Protected");
	if (flags & efunc::FUNC_Private)     add("Private");
	if (flags & efunc::FUNC_HasOutParms) add("HasOutParms");
	if (flags & efunc::FUNC_HasDefaults) add("HasDefaults");
	if (flags & efunc::FUNC_Const)       add("Const");
	if (flags & efunc::FUNC_BlueprintCallable) add("BlueprintCallable");
	if (flags & efunc::FUNC_BlueprintEvent)    add("BlueprintEvent");
	if (flags & efunc::FUNC_BlueprintAuthorityOnly) add("BlueprintAuthorityOnly");
	return s.empty() ? "" : s;
}

std::vector<sdk_dumper::func_info> sdk_dumper::walk_functions(uint64_t struct_addr) {
	std::vector<func_info> funcs;

	uint64_t child = proc_.read<uint64_t>(struct_addr + ustruct::children);
	int func_count = 0;
	while (child && func_count++ < 512) {
		obj_info fi;
		if (read_uobject(child, fi)) {
			std::string cls_name = get_object_name(fi.class_ptr);
			if (cls_name == "Function") {
				func_info fn{};
				fn.name = fi.name;
				fn.func_flags = proc_.read<uint32_t>(child + ufunc::function_flags);
				uint64_t native_ptr = proc_.read<uint64_t>(child + ufunc::exec_function);
				fn.func_ptr = native_ptr ? (native_ptr - proc_.base()) : 0;

				fn.params = walk_properties(child);

				funcs.push_back(std::move(fn));
			}
		}
		uint64_t next_child = proc_.read<uint64_t>(child + ufield::next);
		if (next_child == child) break;
		child = next_child;
	}

	return funcs;
}

// ── build class info ──

std::string sdk_dumper::struct_prefix(const std::string& class_type_name) {
	// Actor-derived - A, everything else - U
	// Can't perfectly determine this externally, use heuristic
	if (class_type_name == "Actor" || class_type_name.find("Actor") == 0)
		return "A";
	return "U";
}
// ── build class info ──

sdk_dumper::class_info sdk_dumper::build_class_info(uint64_t addr) {
	auto it = class_cache_.find(addr);
	if (it != class_cache_.end())
		return it->second;

	class_info ci{};
	ci.addr = addr;

	obj_info obj;
	if (!read_uobject(addr, obj)) return ci;

	// bail if the object itself looks bogus — encrypted fields didn't decrypt properly
	if (obj.name.empty() || obj.name.find("<invalid>") != std::string::npos ||
		obj.name.find("<null") != std::string::npos) {
		return ci;
	}

	ci.name = obj.name;

	// determine type prefix
	std::string cls_type = get_object_name(obj.class_ptr);
	if (cls_type.empty() || cls_type.find("<invalid>") != std::string::npos ||
		cls_type.find("<null") != std::string::npos) {
		// class pointer decrypted to garbage — skip this object entirely
		return ci;
	}
	if (cls_type == "ScriptStruct") {
		ci.type_prefix = "F";
	} else {
		ci.type_prefix = "U"; // default, will be fixed for Actor-derived below
	}

	// package name (outermost)
	obj_info outer;
	uint64_t outer_ptr = obj.outer_ptr;
	ci.package_name = "";
	{
		std::unordered_set<uint64_t> visited;
		int outer_count = 0;
		while (outer_ptr && outer_count++ < 32) {
			if (visited.count(outer_ptr)) break; // cycle detection
			visited.insert(outer_ptr);
			if (!read_uobject(outer_ptr, outer)) break;
			if (outer.name.size() > 512) break; // sanity check — real package names are short
			ci.package_name = outer.name;
			outer_ptr = outer.outer_ptr;
		}
	}
	// sanitize package name: "/Script/Engine" → "Engine"
	{
		auto pos = ci.package_name.rfind('/');
		if (pos != std::string::npos)
			ci.package_name = ci.package_name.substr(pos + 1);
	}

	// struct size
	ci.struct_size = proc_.read<int32_t>(addr + ustruct::properties_size);

	// sanity: struct size should be reasonable (0..1MB)
	if (ci.struct_size < 0 || ci.struct_size > 0x100000) {
		printf("[!] build_class_info: '%s' has insane struct_size 0x%x — skipping\n",
			ci.name.c_str(), ci.struct_size);
		return ci;
	}

	// super struct
	uint64_t super = proc_.read<uint64_t>(addr + ustruct::super_struct);
	ci.super_size = 0;
	if (super) {
		obj_info super_obj;
		if (read_uobject(super, super_obj) &&
			super_obj.name.find("<invalid>") == std::string::npos &&
			super_obj.name.find("<null") == std::string::npos) {
			ci.super_name = super_obj.name;
			ci.super_size = proc_.read<int32_t>(super + ustruct::properties_size);

			// check if super chain includes Actor - use 'A' prefix
			uint64_t walk = super;
			std::unordered_set<uint64_t> super_visited;
			for (int d = 0; d < 32 && walk; d++) {
				if (super_visited.count(walk)) break; // cycle in super chain
				super_visited.insert(walk);
				std::string sn = get_object_name(walk);
				if (sn.empty() || sn.find("<invalid>") != std::string::npos ||
					sn.find("<null") != std::string::npos)
					break; // walked into garbage
				if (sn == "Actor") { ci.type_prefix = "A"; break; }
				walk = proc_.read<uint64_t>(walk + ustruct::super_struct);
			}
		}
	}

	ci.properties = walk_properties(addr);
	ci.functions = walk_functions(addr);

	class_cache_[addr] = ci;
	return ci;
}

// ── emit formatted header ──

void sdk_dumper::emit_class_header(std::ostream& out, const class_info& ci) {
	// comment header
	std::string class_type = (ci.type_prefix == "F") ? "ScriptStruct" : "Class";
	out << "// " << class_type << " " << ci.package_name << "." << ci.name << "\n";
	out << "// Size: 0x" << std::hex << ci.struct_size
		<< " (Inherited: 0x" << ci.super_size << ")" << std::dec << "\n";

	// struct definition
	std::string prefix = ci.type_prefix;
	std::string struct_name = prefix + ci.name;
	out << "struct " << struct_name;
	if (!ci.super_name.empty()) {
		// detect super prefix
		std::string super_prefix = "U";
		// walk up to check Actor
		if (ci.type_prefix == "A" || ci.super_name == "Actor") super_prefix = "A";
		if (ci.type_prefix == "F") super_prefix = "F";
		out << " : " << super_prefix << ci.super_name;
	} else {
		out << " : UObject";
	}
	out << " {\n";

	// sort properties by offset
	auto sorted = ci.properties;
	std::sort(sorted.begin(), sorted.end(), [](const prop_info& a, const prop_info& b) {
		return a.offset < b.offset;
	});

	// track current offset for padding
	uint32_t cur_offset = ci.super_size;

	for (auto& p : sorted) {
		uint32_t off = p.offset;
		int32_t size = p.element_size * p.array_dim;
		if (size <= 0) size = 1; // bool bitfield or unknown

		// pad if gap
		if (off > cur_offset && off != 0xFFFFFFFF && off < 0x100000) {
			uint32_t gap = off - cur_offset;
			if (gap > 0 && gap < 0x10000) {
				char pad[128];
				snprintf(pad, sizeof(pad), "\tchar pad_%X[0x%x]; // 0x%x(0x%x)\n",
					cur_offset, gap, cur_offset, gap);
				out << pad;
				cur_offset = off;
			}
		}

		// property line
		char line[512];
		if (p.is_bool_bitfield) {
			// bitfield bool — packed bit within a byte
			// FieldMask indicates which bit (0x01, 0x02, 0x04, etc.)
			if (off != 0xFFFFFFFF && off < 0x100000) {
				snprintf(line, sizeof(line), "\tbool %s : 1; // 0x%x(0x01) mask=0x%02x\n",
					p.name.c_str(), off, p.bool_field_mask);
			} else {
				snprintf(line, sizeof(line), "\tbool %s : 1; // ?(0x01) mask=0x%02x\n",
					p.name.c_str(), p.bool_field_mask);
			}
		} else if (p.is_native_bool) {
			// native bool — full byte(s)
			int32_t bsz = p.bool_field_size > 0 ? p.bool_field_size : 1;
			if (off != 0xFFFFFFFF && off < 0x100000) {
				snprintf(line, sizeof(line), "\tbool %s[0x%02x]; // 0x%x(0x%02x)\n",
					p.name.c_str(), bsz, off, bsz);
			} else {
				snprintf(line, sizeof(line), "\tbool %s[0x%02x]; // ?(0x%02x)\n",
					p.name.c_str(), bsz, bsz);
			}
		} else if (off == 0xFFFFFFFF || off >= 0x100000) {
			snprintf(line, sizeof(line), "\t%s %s[0x%02x]; // ?(0x%02x)\n",
				p.type_str.c_str(), p.name.c_str(), size, size);
		} else {
			snprintf(line, sizeof(line), "\t%s %s[0x%02x]; // 0x%x(0x%02x)\n",
				p.type_str.c_str(), p.name.c_str(), size,
				off, size);
		}
		out << line;

		if (off != 0xFFFFFFFF && off < 0x100000 && size > 0)
			cur_offset = off + size;
	}

	// pad to struct_size
	if (cur_offset < (uint32_t)ci.struct_size && ci.struct_size > 0) {
		uint32_t gap = ci.struct_size - cur_offset;
		if (gap > 0 && gap < 0x100000) {
			char pad[128];
			snprintf(pad, sizeof(pad), "\tchar pad_%X[0x%x]; // 0x%x(0x%x)\n",
				cur_offset, gap, cur_offset, gap);
			out << pad;
		}
	}

	// functions
	if (!ci.functions.empty()) {
		out << "\n";
		for (auto& fn : ci.functions) {
			// return type
			std::string ret = "void";
			if (!fn.return_type.empty()) ret = fn.return_type;

			out << "\t" << ret << " " << fn.name << "(";

			// params
			bool first = true;
			for (auto& p : fn.params) {
				if (p.prop_flags & 0x0000000000000004ull) { // CPF_ReturnParm
					continue; // skip return param in arg list
				}
				if (!first) out << ", ";
				first = false;
				out << p.type_str;
				if (p.element_size > 0 && p.type_str != "bool")
					out << "*";
				out << " " << p.name;
			}

			out << "); // Function " << ci.package_name << "." << ci.name << "." << fn.name;
			out << " // " << format_func_flags(fn.func_flags);
			if (fn.func_ptr)
				out << " // @ game+0x" << std::hex << fn.func_ptr << std::dec;
			out << "\n";
		}
	}

	out << "};\n\n";
}

// ── UProperty offset finder ──
// Scans Color struct's B/G/R/A UProperty objects for known values:
//   Color.B: Offset_Internal=0, ElementSize=1, ArrayDim=1
//   Color.G: Offset_Internal=1, ElementSize=1, ArrayDim=1
//   Guid.C:  Offset_Internal=8, ElementSize=4, ArrayDim=1
bool sdk_dumper::find_uprop_offsets() {
	printf("[*] calibrating UProperty field offsets...\n");

	// find Color ScriptStruct
	uint64_t color_addr = 0;
	uint64_t guid_addr = 0;
	for (int32_t i = 0; i < gobjects_count_ && i < 500000; i++) {
		if (i % 50000 == 0 && i > 0)
			printf("[*] calibration scan: %d / %d\n", i, gobjects_count_);
		uint64_t addr = get_object_ptr(i);
		if (!addr) continue;
		obj_info info;
		if (!read_uobject(addr, info)) continue;
		std::string cls = get_object_name(info.class_ptr);
		if (cls == "ScriptStruct") {
			if (info.name == "Color" && !color_addr) color_addr = addr;
			if (info.name == "Guid" && !guid_addr) guid_addr = addr;
		}
		if (color_addr && guid_addr) break;
	}

	if (!color_addr || !guid_addr) {
		printf("[-] could not find Color/Guid ScriptStruct\n");
		return false;
	}

	// walk Color children to find B, G, R, A UProperty objects
	uint64_t prop_b = 0, prop_g = 0, prop_r = 0, prop_a = 0;
	uint64_t walk = proc_.read<uint64_t>(color_addr + ustruct::children);
	while (walk) {
		obj_info fi;
		if (read_uobject(walk, fi)) {
			if (fi.name == "B") prop_b = walk;
			if (fi.name == "G") prop_g = walk;
			if (fi.name == "R") prop_r = walk;
			if (fi.name == "A") prop_a = walk;
		}
		walk = proc_.read<uint64_t>(walk + ufield::next);
	}

	// walk Guid children to find C (Offset_Internal=8, ElementSize=4)
	uint64_t prop_guid_c = 0;
	walk = proc_.read<uint64_t>(guid_addr + ustruct::children);
	while (walk) {
		obj_info fi;
		if (read_uobject(walk, fi)) {
			if (fi.name == "C") prop_guid_c = walk;
		}
		walk = proc_.read<uint64_t>(walk + ufield::next);
	}

	if (!prop_b || !prop_g) {
		printf("[-] could not find Color.B / Color.G UProperty objects\n");
		return false;
	}

	printf("[*] Color.B=0x%llX, Color.G=0x%llX, Color.R=0x%llX, Color.A=0x%llX, Guid.C=0x%llX\n",
		prop_b, prop_g, prop_r, prop_a, prop_guid_c);

	// read 0x100 bytes from each calibration property
	constexpr int SZ = 0x100;
	uint8_t buf_b[SZ]{}, buf_g[SZ]{}, buf_r[SZ]{}, buf_a[SZ]{};
	proc_.read_raw(prop_b, buf_b, SZ);
	proc_.read_raw(prop_g, buf_g, SZ);
	if (prop_r) proc_.read_raw(prop_r, buf_r, SZ);
	if (prop_a) proc_.read_raw(prop_a, buf_a, SZ);

	printf("[*] hexdump Color.B UProperty:\n");
	for (int row = 0; row < SZ; row += 16) {
		printf("  +0x%02X:", row);
		for (int c = 0; c < 16; c++) printf(" %02X", buf_b[row + c]);
		printf("\n");
	}
	printf("[*] hexdump Color.G UProperty:\n");
	for (int row = 0; row < SZ; row += 16) {
		printf("  +0x%02X:", row);
		for (int c = 0; c < 16; c++) printf(" %02X", buf_g[row + c]);
		printf("\n");
	}

	uint8_t buf_c[SZ]{};
	bool have_guid_c = false;
	if (prop_guid_c) {
		proc_.read_raw(prop_guid_c, buf_c, SZ);
		have_guid_c = true;
	}

	// stronger calibration: use B=0, G=1, R=2, A=3, Guid.C=8
	// this eliminates false positives from coincidental matches
	printf("\n[*] running full calibration scan (B=0, G=1, R=2, A=3, Guid.C=8)...\n");

	for (int off = 0x30; off < SZ - 4; off += 4) {
		int32_t vb = *reinterpret_cast<int32_t*>(buf_b + off);
		int32_t vg = *reinterpret_cast<int32_t*>(buf_g + off);

		// ElementSize: B=1, G=1 (and R=1, A=1, Guid.C=4)
		if (vb == 1 && vg == 1) {
			bool elem_confirmed = true;
			if (prop_r) elem_confirmed &= (*reinterpret_cast<int32_t*>(buf_r + off) == 1);
			if (prop_a) elem_confirmed &= (*reinterpret_cast<int32_t*>(buf_a + off) == 1);
			if (have_guid_c) elem_confirmed &= (*reinterpret_cast<int32_t*>(buf_c + off) == 4);
			if (elem_confirmed && uprop_element_size_ < 0) {
				printf("  [+] ElementSize CONFIRMED at offset 0x%X\n", off);
				uprop_element_size_ = off;
			}
		}

		// ArrayDim: B=1, G=1, R=1, A=1, Guid.C=1 (and NOT the same offset as ElementSize)
		if (vb == 1 && vg == 1 && off != uprop_element_size_) {
			bool arr_confirmed = true;
			if (prop_r) arr_confirmed &= (*reinterpret_cast<int32_t*>(buf_r + off) == 1);
			if (prop_a) arr_confirmed &= (*reinterpret_cast<int32_t*>(buf_a + off) == 1);
			if (have_guid_c) arr_confirmed &= (*reinterpret_cast<int32_t*>(buf_c + off) == 1);
			if (arr_confirmed && uprop_array_dim_ < 0) {
				printf("  [+] ArrayDim CONFIRMED at offset 0x%X\n", off);
				uprop_array_dim_ = off;
			}
		}

		// Offset_Internal: B=0, G=1, R=2, A=3, Guid.C=8 — strongest check
		if (vb == 0 && vg == 1) {
			bool off_confirmed = true;
			if (prop_r) off_confirmed &= (*reinterpret_cast<int32_t*>(buf_r + off) == 2);
			if (prop_a) off_confirmed &= (*reinterpret_cast<int32_t*>(buf_a + off) == 3);
			if (have_guid_c) off_confirmed &= (*reinterpret_cast<int32_t*>(buf_c + off) == 8);
			if (off_confirmed && uprop_offset_ < 0) {
				printf("  [+] Offset_Internal CONFIRMED at offset 0x%X (PLAIN — not encrypted!)\n", off);
				uprop_offset_ = off;
			}
		}
	}

	printf("[*] UProperty calibration results:\n");
	printf("    ElementSize:     0x%X\n", uprop_element_size_);
	printf("    ArrayDim:        0x%X\n", uprop_array_dim_);
	printf("    Offset_Internal: 0x%X\n", uprop_offset_);
	printf("    PropertyFlags:   0x%X\n", uprop_prop_flags_);

	// if plain Offset_Internal not found, test the XE scattered-byte decrypt
	if (uprop_offset_ < 0 && prop_b && prop_g) {
		printf("[*] Offset_Internal not found as plain int32 — testing XE scattered-byte decrypt...\n");
		uprop_offset_ = -2; // temporarily enable XE mode for testing
		uint32_t test_b = read_property_offset(prop_b);
		uint32_t test_g = read_property_offset(prop_g);
		printf("    Color.B decrypt => %d (expected 0)\n", test_b);
		printf("    Color.G decrypt => %d (expected 1)\n", test_g);
		if (prop_guid_c) {
			uint32_t test_c = read_property_offset(prop_guid_c);
			printf("    Guid.C  decrypt => %d (expected 8)\n", test_c);
			if (test_b == 0 && test_g == 1 && test_c == 8) {
				printf("[+] XE scattered-byte Offset_Internal decrypt CONFIRMED!\n");
				uprop_offset_ = -2; // sentinel: use XE decrypt
			}
		} else if (test_b == 0 && test_g == 1) {
			printf("[+] XE scattered-byte Offset_Internal decrypt looks correct\n");
			// uprop_offset_ already -2
		} else {
			uprop_offset_ = -1; // reset — XE decrypt didn't work either
		}
	}

	if (uprop_element_size_ < 0) {
		printf("[-] UProperty calibration failed — ElementSize not found\n");
		return false;
	}
	if (uprop_offset_ < 0 && uprop_offset_ != -2) {
		printf("[-] UProperty calibration failed — Offset_Internal not found\n");
		return false;
	}

	return true;
}

// ── main dump routine ──

bool sdk_dumper::dump(const std::string& output_dir) {
	std::filesystem::create_directories(output_dir);

	// run sig scanner first to resolve all dynamic addresses
	if (scanner_) {
		printf("[*] sig scanner: resolving patterns from PE dump...\n\n");
		if (!scanner_->resolve_all(scan_)) {
			printf("[!] sig scanner incomplete — some patterns not found\n");
		}
		printf("\n");
	} else {
		printf("[-] no PE image for sig scanning — cannot resolve addresses\n");
		return false;
	}

	printf("[*] initializing xe decrypt stub...\n");
	if (!init_xe_stub())
		return false;

	printf("[*] initializing GObjects...\n");
	if (!init_gobjects())
		return false;

	printf("[*] initializing FNamePool...\n");
	if (!init_fnamepool())
		return false;

	// bulk-cache GObjects array into local memory
	printf("[*] caching GObjects array locally...\n");
	if (!cache_.cache_gobjects(gobjects_array_, gobjects_count_)) {
		printf("[!] GObjects cache failed — will use live driver reads\n");
	}

	// bulk-cache FNamePool block pointers
	if (fnamepool_chunks_) {
		printf("[*] caching FNamePool block pointers...\n");
		cache_.cache_fnamepool_chunks(fnamepool_chunks_);
	}

	printf("[*] calibrating UProperty offsets...\n");
	if (!find_uprop_offsets())
		return false;

	// bulk-cache all valid object blobs (the big win — one driver pass)
	printf("[*] bulk-caching all object blobs...\n");
	int cached = cache_.cache_all_objects(0xA0); // 0xA0 covers UObject + UField + UProperty base
	printf("[+] cached %d objects (%.1f MB total)\n",
		cached, cache_.total_cached_bytes() / (1024.0 * 1024.0));

	// ── phase 1: collect all objects ──
	printf("[*] collecting %d objects...\n", gobjects_count_);

	struct obj_entry {
		int32_t  index;
		uint64_t addr;
		std::string full_name;
		std::string class_name;
		std::string package_name;
		uint64_t class_ptr;
	};

	std::vector<obj_entry> all_objects;
	std::unordered_set<uint64_t> class_addrs;  // UClass/UScriptStruct addresses to dump
	std::map<std::string, std::vector<uint64_t>> package_classes; // package - classes

	int valid = 0, null_cnt = 0, fail_cnt = 0;
	for (int32_t i = 0; i < gobjects_count_; i++) {
		if (i % 50000 == 0 && i > 0)
			printf("[*] scanning: %d / %d (%d valid)\n", i, gobjects_count_, valid);

		// use cache for object pointer lookup
		uint64_t addr = cache_.gobjects_count() > 0
			? cache_.get_object_ptr(i)
			: get_object_ptr(i);
		if (!addr) { null_cnt++; continue; }

		// check pending kill from cache
		if (cache_.gobjects_count() > 0) {
			int32_t flags = cache_.get_object_flags(i);
			if (flags & PENDING_KILL_FLAG) continue;
		} else {
			uint64_t item_addr = gobjects_array_ + static_cast<uint64_t>(i) * FUOBJECTITEM_SIZE;
			int32_t flags = proc_.read<int32_t>(item_addr + fobj_item::flags);
			if (flags & PENDING_KILL_FLAG) continue;
		}

		obj_info info;
		if (!read_uobject(addr, info)) { fail_cnt++; continue; }

		std::string cls_name = get_object_name(info.class_ptr);

		// record classes and script structs for SDK output
		if (cls_name == "Class" || cls_name == "ScriptStruct") {
			class_addrs.insert(addr);

			// package
			std::string pkg;
			uint64_t outer = info.outer_ptr;
			std::unordered_set<uint64_t> outer_seen;
			int outer_depth = 0;
			while (outer && outer_depth++ < 32) {
				if (outer_seen.count(outer)) break; // cycle
				outer_seen.insert(outer);
				obj_info o;
				if (!read_uobject(outer, o)) break;
				if (o.name.size() > 512 || o.name.find("<invalid>") != std::string::npos) break;
				pkg = o.name;
				if (o.outer_ptr == outer) break; // self-referential
				outer = o.outer_ptr;
			}
			if (pkg.empty()) pkg = "Unknown";
			// sanitize: "/Script/Engine" → "Engine"
			{
				auto pos = pkg.rfind('/');
				if (pos != std::string::npos)
					pkg = pkg.substr(pos + 1);
			}

			package_classes[pkg].push_back(addr);
		}

		std::string full = cls_name + " " + get_object_path(addr);

		obj_entry e;
		e.index = i;
		e.addr = addr;
		e.full_name = full;
		e.class_name = cls_name;
		e.class_ptr = info.class_ptr;
		all_objects.push_back(std::move(e));
		valid++;
	}

	printf("[+] collected %d objects (%d null, %d failed), %zu classes/structs in %zu packages\n",
		valid, null_cnt, fail_cnt, class_addrs.size(), package_classes.size());

	// ── phase 2: ObjectsDump.txt ──
	{
		std::string path = output_dir + "/ObjectsDump.txt";
		std::ofstream f(path);
		int written = 0;
		for (auto& e : all_objects) {
			char line[1024];
			snprintf(line, sizeof(line), "[%06d] <0x%llx> %s\n", e.index, e.addr, e.full_name.c_str());
			f << line;
			written++;
			if (written % 50000 == 0)
				printf("[*] ObjectsDump: %d / %d\n", written, (int)all_objects.size());
		}
		printf("[+] ObjectsDump.txt: %d objects\n", (int)all_objects.size());
	}

	// ── phase 3: NamesDump.txt ──
	{
		std::string path = output_dir + "/NamesDump.txt";
		std::ofstream f(path);
		int name_count = 0;
		for (int32_t i = 0; i < 200000; i++) {
			if (i % 50000 == 0 && i > 0)
				printf("[*] NamesDump: %d / 200000 (%d resolved)\n", i, name_count);
			std::string name = resolve_fname(i);
			if (name.empty() || name[0] == '<') continue;
			char line[1024];
			snprintf(line, sizeof(line), "[%06d] %s\n", i, name.c_str());
			f << line;
			name_count++;
		}
		printf("[+] NamesDump.txt: %d names\n", name_count);
	}

	// ── phase 4: per-package SDK headers + combined file ──
	std::string sdk_dir = output_dir + "/DUMP";
	std::filesystem::create_directories(sdk_dir);

	// generate timestamp for combined filename
	time_t now = time(nullptr);
	tm t{};
	localtime_s(&t, &now);
	char ts[64];
	snprintf(ts, sizeof(ts), "%02d%02d%04d_%d_%02d",
		t.tm_mday, t.tm_mon + 1, t.tm_year + 1900, t.tm_hour, t.tm_min);

	std::string combined_path = output_dir + "/objects_tslgame_dump_" + ts + ".txt";
	std::ofstream combined(combined_path);

	// header comment in combined file
	combined << "// PUBG SDK Dump — TslGame.exe\n";
	combined << "// Generated: " << ts << "\n";
	combined << "// Objects: " << valid << " | Classes/Structs: " << class_addrs.size()
		<< " | Packages: " << package_classes.size() << "\n";
	combined << "// Resolved by sig scanner (dynamic — no hardcoded RVAs):\n";
	combined << "//   gobjects_count RVA: 0x" << std::hex << scan_.gobjects_count_rva << "\n";
	combined << "//   gobjects_array RVA: 0x" << scan_.gobjects_array_rva << "\n";
	combined << "//   xe_decrypt_fn RVA: 0x" << scan_.xe_decrypt_fn_rva << "\n";
	combined << "//   fnamepool_global RVA: 0x" << scan_.fnamepool_enc_global_rva << "\n";
	if (scan_.index_decrypt.valid) {
		combined << "//   InternalIndex: xor " << scan_.index_decrypt.xor1
			<< "h; ror " << (int)scan_.index_decrypt.rot
			<< "; shr " << (int)scan_.index_decrypt.shr_val
			<< "/shl " << (int)scan_.index_decrypt.shl_val
			<< "; xor " << scan_.index_decrypt.xor2 << "h\n";
	}
	combined << "//   UProperty offsets (auto-calibrated): ElementSize=0x" << std::hex
		<< uprop_element_size_ << ", ArrayDim=0x" << uprop_array_dim_
		<< ", Offset_Internal=0x" << uprop_offset_ << "\n";
	combined << std::dec << "\n\n";

	int class_count = 0;
	int pkg_count = 0;

	// parallel package processing — each package builds class_info independently
	// then merges results sequentially for file output
	struct pkg_result {
		std::string pkg_name;
		std::vector<class_info> classes;
	};

	std::vector<pkg_result> pkg_results;
	pkg_results.reserve(package_classes.size());

	// flatten the package map for index-based access
	std::vector<std::pair<std::string, std::vector<uint64_t>>> pkg_list(
		package_classes.begin(), package_classes.end());
	pkg_results.resize(pkg_list.size());

	int total_pkgs = static_cast<int>(pkg_list.size());
	printf("[*] processing %d packages...\n", total_pkgs);

	for (size_t i = 0; i < pkg_list.size(); i++) {
		auto& [pkg, addrs] = pkg_list[i];
		pkg_result result;
		result.pkg_name = pkg;
		for (uint64_t addr : addrs) {
			class_info ci = build_class_info(addr);
			if (!ci.name.empty())
				result.classes.push_back(std::move(ci));
		}
		pkg_results[i] = std::move(result);
		int done = static_cast<int>(i) + 1;
		if (done % 50 == 0 || done == total_pkgs)
			printf("[*] packages: %d / %d\n", done, total_pkgs);
	}

	// write results sequentially (file I/O)
	for (auto& result : pkg_results) {
		pkg_count++;
		std::string pkg_file = sdk_dir + "/" + result.pkg_name + "_classes.h";
		std::ofstream pkg_out(pkg_file);

		for (auto& ci : result.classes) {
			emit_class_header(pkg_out, ci);
			emit_class_header(combined, ci);
			class_count++;
		}
	}

	combined.close();
	printf("[+] SDK dump complete: %d classes across %d packages\n", class_count, pkg_count);
	printf("[+] Combined: %s\n", combined_path.c_str());

	// ── phase 5: output offsets.h to console ──
	// lookup table: class_hint (substring match on name/super), property name, output namespace, output field, comment
	struct offset_lookup {
		const char* class_hint;
		const char* prop_name;
		const char* ns;
		const char* field;
		const char* comment;
	};

	static const offset_lookup lookups[] = {
		// world
		{"World",            "CurrentLevel",            "world",             "current_level",      "xe-encrypted ptr"},
		// player controller
		{"PlayerController", "PlayerCameraManager",     "player_controller", "player_camera_mgr",  nullptr},
		{"PlayerController", "PlayerInput",             "player_controller", "player_input",       nullptr},
		// actor
		{"Actor",            "RootComponent",           "actor",             "root_component",     "xe-encrypted"},
		// pawn
		{"Pawn",             "PlayerState",             "pawn",              "player_state",       "xe-encrypted"},
		// character (engine base)
		{"Character",        "Mesh",                    "character",         "mesh",               nullptr},
		{"Character",        "CharacterMovement",       "character",         "character_movement", "xe-encrypted"},
		// tsl character (class name obfuscated — match by prop name only)
		{nullptr,            "CharacterName",           "character",         "character_name",     "FString"},
		{nullptr,            "AimOffsets",              "character",         "aim_offsets",        nullptr},
		{nullptr,            "VehicleRiderComponent",   "character",         "vehicle_rider",      nullptr},
		{nullptr,            "DBNOHealth",              "character",         "groggy_health",      nullptr},
		// player state
		{"PlayerState",      "Ping",                    "player_state",      "ping",               nullptr},
		{nullptr,            "TeamNumber",              "player_state",      "team_number",        nullptr},
		{nullptr,            "AccountId",               "player_state",      "account_id",         nullptr},
		{nullptr,            "DamageDealtOnEnemy",      "player_state",      "damage_dealt",       nullptr},
		// animation (obfuscated class)
		{nullptr,            "ControlRotation_CP",      "anim",              "control_rotation",   nullptr},
		{nullptr,            "bIsScoping_CP",           "anim",              "is_scoping",         nullptr},
		{nullptr,            "bIsReloading_CP",         "anim",              "is_reloading",       nullptr},
		{nullptr,            "LeanLeftAlpha_CP",        "anim",              "lean_left_alpha",    nullptr},
		{nullptr,            "LeanRightAlpha_CP",       "anim",              "lean_right_alpha",   nullptr},
		// dropped item
		{"DroppedItem",      "Item",                    "item",              "dropped_item",       "xe-encrypted"},
		// game state
		{nullptr,            "NumAliveTeams",           "game_state",        "alive_teams",        nullptr},
		// mesh component
		{"SkeletalMesh",     "AnimScriptInstance",      "mesh_component",    "anim_script",        nullptr},
	};

	struct found_offset {
		std::string ns;
		std::string field;
		uint32_t offset;
		std::string comment;
	};
	std::vector<found_offset> found;

	for (auto& lk : lookups) {
		bool matched = false;
		for (auto& pkg : pkg_results) {
			if (matched) break;
			for (auto& ci : pkg.classes) {
				if (matched) break;
				if (lk.class_hint) {
					if (ci.name.find(lk.class_hint) == std::string::npos &&
						ci.super_name.find(lk.class_hint) == std::string::npos)
						continue;
				}
				for (auto& prop : ci.properties) {
					if (prop.name == lk.prop_name && prop.offset < 0x100000 && prop.offset != 0xFFFFFFFF) {
						found.push_back({ lk.ns, lk.field, prop.offset, lk.comment ? lk.comment : "" });
						matched = true;
						break;
					}
				}
			}
		}
	}

	// group by namespace
	std::map<std::string, std::vector<found_offset*>> by_ns;
	for (auto& fo : found) by_ns[fo.ns].push_back(&fo);

	printf("\n");
	printf("// =========================================================\n");
	printf("// offsets.h — auto-generated from SDK dump\n");
	printf("// only includes offsets resolvable through UE4 reflection.\n");
	printf("// xe-encrypted / native C++ offsets need manual updating.\n");
	printf("// =========================================================\n\n");
	printf("#pragma once\n#include <cstdint>\n\nnamespace offs {\n\n");

	// rva namespace from sig scanner
	printf("namespace rva {\n");
	printf("\tconstexpr uint64_t uworld           = 0x0;          // manual\n");
	printf("\tconstexpr uint64_t xe_decrypt       = 0x%llX;\n", (unsigned long long)scan_.xe_decrypt_fn_rva);
	printf("\tconstexpr uint64_t gnames           = 0x%llX;\n", (unsigned long long)scan_.fnamepool_enc_global_rva);
	printf("\tconstexpr uint64_t gobjects_count   = 0x%llX;\n", (unsigned long long)scan_.gobjects_count_rva);
	printf("\tconstexpr uint64_t gobjects_array   = 0x%llX;\n", (unsigned long long)scan_.gobjects_array_rva);
	printf("}\n\n");

	// emit namespaces in order
	const char* ns_order[] = {
		"world", "player_controller", "actor", "pawn", "character",
		"mesh_component", "player_state", "item", "anim", "game_state"
	};

	for (auto ns : ns_order) {
		auto it = by_ns.find(ns);
		if (it == by_ns.end()) continue;
		printf("namespace %s {\n", ns);
		for (auto* fo : it->second) {
			if (fo->comment.empty())
				printf("\tconstexpr uint64_t %-22s = 0x%X;\n", fo->field.c_str(), fo->offset);
			else
				printf("\tconstexpr uint64_t %-22s = 0x%X;    // %s\n", fo->field.c_str(), fo->offset, fo->comment.c_str());
		}
		printf("}\n\n");
	}

	printf("} // namespace offs\n\n");

	return true;
}
