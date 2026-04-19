# PUBG Dumper Update Guide

How to update the dumper when PUBG patches break it. Uses IDA MCP for binary analysis.

---

## Architecture Overview

The dumper resolves everything dynamically from the PE dump using `sig_scanner`:
- **GObjects**: pattern-matched `shr/and/shl/or/xor` sequence → extracts decrypt constants + global RVAs
- **FNamePool**: prologue signature → extracts encrypted global RVA + xe keys
- **UProperty offsets**: auto-calibrated via Color.B/G/R/A + Guid.C known values
- **xe_decrypt_read**: function pointer resolved from the code near GObjects

No hardcoded RVAs are used. Field decrypt constants (InternalIndex, FName, ClassPrivate, OuterPrivate) have hardcoded fallbacks that are overridden when sig scanner extracts them.

---

## When Things Break

### 1. Pattern not found (GObjects or FNamePool)

The sig scanner prints which pattern failed. Use IDA to find the new pattern:

**GObjects decrypt pattern** (`C1 E8 ?? 25 ?? ?? ?? ?? C1 E1 ?? 0B C1 35 ?? ?? ?? ??`):
```
mcp_ida-pro-mcp_find_bytes: "C1 E8 ?? 25 ?? ?? ?? ?? C1 E1 ?? 0B C1 35 ?? ?? ?? ??"
```
This is the InternalIndex decrypt: `shr eax, N / and eax, MASK / shl ecx, N / or eax, ecx / xor eax, XOR2`.
If the instruction encoding changed (e.g., different register allocation), update the pattern in `sig_scanner.cpp::resolve_gobjects()`.

**FNamePool getter prologue** (`48 89 5C 24 18 48 89 74 24 20 57 48 83 EC 20 48 8B F9 E8`):
```
mcp_ida-pro-mcp_find_bytes: "48 89 5C 24 18 48 89 74 24 20 57 48 83 EC 20 48 8B F9 E8"
```
This is a standard function prologue. If it has multiple matches, look for the one that:
- Has multiple `TlsGetValue` calls (xe init guards)
- Accesses a high-RVA global via `mov rdx, cs:qword_XXX`
- Calls through a function pointer with `mov ecx, IMM32` (xe key)

### 2. Field decrypt constants changed

If the dumper runs but produces garbage names/indexes, the decrypt constants may have shifted.

**To find InternalIndex decrypt constants:**
```
mcp_ida-pro-mcp_decompile: <address of UWorld::Tick>
```
Look for the pattern:
```c
v = enc ^ XOR1;
result = ((v << SHL) | ((v >> SHR) & MASK)) ^ XOR2 ^ ROR(v, ROT);
```
The sig scanner extracts these automatically from the matched bytes + nearby Zydis analysis.

**To find FName.Index / FName.Number / ClassPrivate / OuterPrivate:**
These are in functions that read UObject fields. Find them by:
```
mcp_ida-pro-mcp_find_bytes: "48 B8"   (mov rax, imm64 — the XOR1 constant for 64-bit)
```
Or decompile any function that accesses UObject fields and look for the XOR/ROT/SHIFT pattern.

Current hardcoded fallbacks in `sdk_dumper.cpp::read_uobject()`:
- InternalIndex: XOR1=0x58BB1540, ROT=18, SHR=2, MASK=0x3FFF0000, SHL=30, XOR2=0x3358DE8B
- FName.Index: XOR1=0x07360F24, ROT=23(ROL), SHR=7, MASK=0x1FF0000, SHL=25, XOR2=0xB621EC05
- FName.Number: XOR1=0x221A03AC, ROT=17, SHR=1, MASK=0x7FFF0000, SHL=31, XOR2=0x12082DD7
- ClassPrivate: XOR1=0xE2986D8D91154221, ROT=44, SHR=12, MASK=0xFFFFF00000000, SHL=52, XOR2=0xEA2AD6C171F53EBB
- OuterPrivate: XOR1=0xAAC9936D813E8C38, ROT=6, AND_MASK=0xFFFFFFFFFFFFFFC0, SHL=26, XOR2=0x7A716E485910E57F

### 3. Offset_Internal scattered-byte decrypt broken

The 50-case switch in `xenuine.h::xe_offset::decrypt_offset_internal()` uses version-specific constants. If UProperty offsets come out wrong after calibration succeeds for ElementSize/ArrayDim but fails for Offset_Internal:

1. Find the Offset_Internal accessor function in IDA
2. Decompile it — look for the `(base >> 16) ^ base ^ ...` selector followed by a large switch
3. Update the 50 cases in `xe_offset::decrypt_offset_internal()`

Note: if calibration finds Offset_Internal as a plain int32 (which it does in recent versions), the switch is never used.

### 4. FNamePool structure changed

If names resolve to garbage after FNamePool init succeeds:
```
mcp_ida-pro-mcp_decompile: <FNamePool getter address>
```
Check:
- `fname::chunk_size` (0x3E4C) — entries per chunk
- `fname::chunks_offset` (16) — offset from pool to blocks array
- `fname::string_offset` (16) — offset from entry to char data
- Block pointer stride (currently 8 bytes — plain pointers)
- Entry header format (currently xe-encrypted qword, bit 0 = wide flag)

---

## IDA MCP Quick Reference

Useful commands for updating:

```
# check binary is loaded and analysis done
mcp_ida-pro-mcp_server_health

# find a byte pattern (wildcards supported)
mcp_ida-pro-mcp_find_bytes: "C1 E8 ?? 25 ?? ?? ?? ??"

# decompile a function at address
mcp_ida-pro-mcp_decompile: 0x7FF7XXXXXXXX

# disassemble a range
mcp_ida-pro-mcp_disasm: 0x7FF7XXXXXXXX, count=30

# find xrefs to an address
mcp_ida-pro-mcp_xrefs_to: 0x7FF7XXXXXXXX

# list functions matching a pattern
mcp_ida-pro-mcp_lookup_funcs: "UWorld"
```

---

## File Responsibilities

| File | Purpose |
|------|---------|
| `sig_scanner.h/cpp` | Pattern scanning + Zydis constant extraction |
| `xenuine.h` | Structural layouts + Offset_Internal fallback switch |
| `sdk_dumper.h/cpp` | Main dump logic — uses `scan_results` from sig scanner |
| `ue4_types.h` | UObject/UField/UStruct/FField struct offsets |
| `process.h/cpp` | Driver-backed memory access |
| `mem_cache.h/cpp` | Local memory cache for bulk reads |
| `dumper.h/cpp` | PE dump + process management wrapper |

---

## Typical Update Workflow

1. Get a fresh TslGame.exe dump (the dumper does this automatically)
2. Load dump in IDA, wait for auto-analysis
3. If dumper fails at sig scanner: use IDA MCP to find the new pattern and update `sig_scanner.cpp`
4. If dumper produces garbage: use IDA MCP to extract new decrypt constants and update fallbacks in `sdk_dumper.cpp::read_uobject()`
5. If Offset_Internal breaks: decompile the accessor and update the 50-case switch in `xenuine.h`
6. Build and test
