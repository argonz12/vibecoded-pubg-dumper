#pragma once
#include <cstdint>

// UE4 type layouts for PUBG (with Xenuine encryption)
// all pointer/index fields in UObject are encrypted — decrypted via sig_scanner extracted params

// sizes
constexpr uint32_t UOBJECT_SIZE     = 0x30; // 48 bytes
constexpr uint32_t FUOBJECTITEM_SIZE = 0x18; // 24 bytes

// UObject field offsets (encrypted in memory)
namespace uobj {
	constexpr uint32_t vtable         = 0x00; // void* — class vtable
	constexpr uint32_t internal_index = 0x08; // enc int32 (padded to 8)
	constexpr uint32_t class_private  = 0x10; // enc uint64 — UClass*
	constexpr uint32_t fname_number   = 0x1C; // enc int32 — FName.Number
	constexpr uint32_t fname_index    = 0x20; // enc int32 — FName.ComparisonIndex
	constexpr uint32_t outer_private  = 0x28; // enc uint64 — UObject* outer
}

// FUObjectItem layout (in GObjects array)
namespace fobj_item {
	constexpr uint32_t object         = 0x00; // UObject* (plaintext)
	constexpr uint32_t flags          = 0x08; // int32
	constexpr uint32_t cluster_root   = 0x0C; // int32
	constexpr uint32_t serial_number  = 0x10; // int32
}

constexpr uint32_t PENDING_KILL_FLAG = 0x20000000;

// UField (inherits UObject)
namespace ufield {
	constexpr uint32_t next = 0x30; // UField* Next (plaintext? — check)
}

// UStruct (inherits UField)
// Layout verified by scanning known objects (Struct=0xE8, Class=0x2C0, Color=0x04, Guid=0x10):
//   0x38: Children (confirmed: Color-"B" ByteProperty via UField chain)
//   0x58: PropertiesSize (confirmed: Struct=0xE8, Class=0x2C0, Color=4, Guid=0x10)
//   0x60: SuperStruct (confirmed: Struct-Field, Class-Struct, plain pointer)
// NOTE: PUBG uses OLD UProperty system (UObject-derived), NOT FField/FProperty.
namespace ustruct {
	constexpr uint32_t children        = 0x38; // UField* Children (verified: Color-B ByteProperty)
	constexpr uint32_t children_props  = 0x40; // FField* ChildProperties — NOT USED in PUBG (always null)
	constexpr uint32_t properties_size = 0x58; // int32 PropertiesSize (verified)
	constexpr uint32_t min_alignment   = 0x5C; // int32
	constexpr uint32_t super_struct    = 0x60; // UStruct* SuperStruct (verified, plain pointer)
}

// UClass (inherits UStruct)
namespace uclass {
	// nothing extra needed for basic dump — class info is in UStruct
}

// UEnum
namespace uenum {
	constexpr uint32_t names = 0x48; // TArray<TPair<FName, int64>> Names
}

// FField (new property system, UE 4.25+)
namespace ffield {
	constexpr uint32_t vft          = 0x00; // void* vtable
	constexpr uint32_t class_ptr    = 0x08; // FFieldClass*
	constexpr uint32_t owner        = 0x10; // FFieldVariant (UObject* or FField*)
	constexpr uint32_t next         = 0x20; // FField* Next
	constexpr uint32_t name_private = 0x28; // FName
}

// FFieldClass
namespace ffieldclass {
	constexpr uint32_t name         = 0x00; // FName
	constexpr uint32_t id           = 0x08; // uint64 EFieldClassID
	constexpr uint32_t cast_flags   = 0x10; // uint64 EClassCastFlags
}

// Property cast flags (from FFieldClass::CastFlags)
namespace propflags {
	constexpr uint64_t Int8Property       = 0x0000000000000002ull;
	constexpr uint64_t ByteProperty       = 0x0000000000000040ull;
	constexpr uint64_t IntProperty        = 0x0000000000000080ull;
	constexpr uint64_t FloatProperty      = 0x0000000000000100ull;
	constexpr uint64_t UInt64Property     = 0x0000000000000200ull;
	constexpr uint64_t ClassProperty      = 0x0000000000000400ull;
	constexpr uint64_t UInt32Property     = 0x0000000000000800ull;
	constexpr uint64_t InterfaceProperty  = 0x0000000000001000ull;
	constexpr uint64_t NameProperty       = 0x0000000000002000ull;
	constexpr uint64_t StrProperty        = 0x0000000000004000ull;
	constexpr uint64_t ObjectProperty     = 0x0000000000010000ull;
	constexpr uint64_t BoolProperty       = 0x0000000000020000ull;
	constexpr uint64_t UInt16Property     = 0x0000000000040000ull;
	constexpr uint64_t StructProperty     = 0x0000000000100000ull;
	constexpr uint64_t ArrayProperty      = 0x0000000000200000ull;
	constexpr uint64_t Int64Property      = 0x0000000000400000ull;
	constexpr uint64_t DelegateProperty   = 0x0000000000800000ull;
	constexpr uint64_t MulticastDelegateProperty = 0x0000000002000000ull;
	constexpr uint64_t WeakObjectProperty = 0x0000000008000000ull;
	constexpr uint64_t LazyObjectProperty = 0x0000000010000000ull;
	constexpr uint64_t SoftObjectProperty = 0x0000000020000000ull;
	constexpr uint64_t TextProperty       = 0x0000000040000000ull;
	constexpr uint64_t Int16Property      = 0x0000000080000000ull;
	constexpr uint64_t DoubleProperty     = 0x0000000100000000ull;
	constexpr uint64_t SoftClassProperty  = 0x0000000200000000ull;
	constexpr uint64_t MapProperty        = 0x0000400000000000ull;
	constexpr uint64_t SetProperty        = 0x0000800000000000ull;
	constexpr uint64_t EnumProperty       = 0x0001000000000000ull;
}

// UProperty / FProperty offsets (within the property object)
namespace uprop {
	constexpr uint32_t array_dim   = 0x38; // int32
	constexpr uint32_t element_size = 0x3C; // int32
	constexpr uint32_t prop_flags  = 0x40; // uint64 PropertyFlags
	constexpr uint32_t offset      = 0x4C; // int32 Offset_Internal (ENCRYPTED — use xe_offset::decrypt_offset_internal)
	// sub-property type-specific offsets (after base FProperty fields)
	constexpr uint32_t struct_ptr  = 0x48; // UScriptStruct* (StructProperty - Struct) — NOTE: overlaps with offset area, needs verification
}

// UBoolProperty extra fields (verified from IDA: PropertyBool.cpp, obj+0x9B = FieldMask)
// 4-byte block starting at obj+0x98:
//   +0x98: FieldSize (uint8) — 1 for bitfield, 1/2/4/8 for native
//   +0x99: ByteOffset (uint8) — byte offset within the bool's storage
//   +0x9A: ByteMask (uint8) — byte-level mask
//   +0x9B: FieldMask (uint8) — 0xFF = native bool, otherwise bitfield mask
namespace uboolprop {
	constexpr uint32_t field_size  = 0x98; // uint8
	constexpr uint32_t byte_offset = 0x99; // uint8
	constexpr uint32_t byte_mask   = 0x9A; // uint8
	constexpr uint32_t field_mask  = 0x9B; // uint8
}

// UFunction (inherits UStruct)
namespace ufunc {
	constexpr uint32_t function_flags = 0x98; // uint32 EFunctionFlags — typical for PUBG
	constexpr uint32_t exec_function  = 0xB0; // void* FNativeFuncPtr — typical for PUBG
}

// EFunctionFlags
namespace efunc {
	constexpr uint32_t FUNC_Final       = 0x00000001;
	constexpr uint32_t FUNC_Net         = 0x00000040;
	constexpr uint32_t FUNC_NetReliable = 0x00000080;
	constexpr uint32_t FUNC_Static      = 0x00000200;
	constexpr uint32_t FUNC_Native      = 0x00000400;
	constexpr uint32_t FUNC_Event       = 0x00000800;
	constexpr uint32_t FUNC_Public      = 0x00020000;
	constexpr uint32_t FUNC_Protected   = 0x00040000;
	constexpr uint32_t FUNC_Private     = 0x00080000;
	constexpr uint32_t FUNC_HasOutParms = 0x00400000;
	constexpr uint32_t FUNC_HasDefaults = 0x00800000;
	constexpr uint32_t FUNC_Const       = 0x04000000;
	constexpr uint32_t FUNC_BlueprintCallable = 0x10000000;
	constexpr uint32_t FUNC_BlueprintEvent   = 0x00200000;
	constexpr uint32_t FUNC_BlueprintAuthorityOnly = 0x00100000;
}

// FName entry layout in FNamePool
namespace fname_entry {
	constexpr uint32_t header_size = 2;     // uint16 header
	constexpr uint32_t string_data = 2;     // chars start right after header
	// header bits: bit 0 = wide flag, bits 1..15 = length (shifted right 1? depends on ver)
	// PUBG uses: len in bits [6..15], wide in bit 0
}

// TArray layout
namespace tarray {
	constexpr uint32_t data  = 0x00; // T*
	constexpr uint32_t count = 0x08; // int32
	constexpr uint32_t max   = 0x0C; // int32
}
