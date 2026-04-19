#pragma once
#include <cstdint>

// xenuine-encrypted UE4 structural layouts
// all RVAs and decrypt constants are resolved dynamically by sig_scanner
//
// UObject layout (all fields encrypted):
//   +0x00: vtable ptr (8)
//   +0x08: InternalIndex (enc int32, padded to 0x10)
//   +0x10: ClassPrivate (enc uint64)
//   +0x18: padding (4)
//   +0x1C: FName.Number (enc int32)
//   +0x20: FName.ComparisonIndex (enc int32)
//   +0x24: padding (4)
//   +0x28: OuterPrivate (enc uint64)
//   +0x30: total UObject header = 48 bytes

// ── FNamePool constants (structural — unlikely to change between updates) ──
namespace fname {

constexpr uint32_t chunk_size    = 0x3E4C;  // 15948 entries per chunk
constexpr uint32_t chunks_offset = 16;      // pool + 16 = blocks[] array start
constexpr uint32_t string_offset = 16;      // entry + 16 = char data (after xe-encrypted header)
// header (qword): xe-encrypted, bit 0 = wide flag after decrypt

} // namespace fname

// ── Offset_Internal scattered-byte decrypt (50-case switch) ──
// this is a calibration fallback: the dumper first tries detecting Offset_Internal
// as a plain int32 via Color/Guid calibration. only if that fails do we use this.
// these constants are version-specific — if they're wrong, the calibration
// will catch it and print diagnostics. use IDA MCP to update.
namespace xe_offset {

inline uint32_t decrypt_offset_internal(uint32_t enc, uint64_t prop_ptr) {
	uint64_t base = prop_ptr + 100;
	uint64_t v128 = (base >> 16) ^ base ^ (((base >> 16) ^ base) >> 8);
	uint32_t sel = static_cast<uint32_t>(v128 % 50);

	auto make_v213 = [](uint32_t hi, uint32_t lo) -> uint32_t {
		return ((hi & 0xFFFF) << 16) | (lo & 0xFFFF);
	};

	switch (sel) {
	case 0:  return 955508617u * (enc ^ 0x799B20EFu) + 1366695136u;
	case 1:  return static_cast<uint32_t>(-1107694519 * static_cast<int>(_rotr(enc, 16)) + 477622602);
	case 2:  return (enc ^ 0x7CBA833Eu) - 477622601u;
	case 3:  return _rotr(static_cast<uint32_t>(-1107694519 * static_cast<int>(_rotr(enc, 16))), 15);
	case 4:  return ~_rotr(enc ^ 0x7FD9D893u, 16);
	case 5:  return _rotr(enc, 16) ^ 0xFFFF0000u;
	case 6:  return _rotr(enc - 2097597339u, 16) ^ 0xE3880EBBu;
	case 7: {
		uint32_t t = (static_cast<uint32_t>(static_cast<uint16_t>(enc >> 16)) << 19)
			| static_cast<uint8_t>((((enc >> 16) | (enc << 16)) >> 19))
			| (((enc >> 16) | (enc << 16)) & 0xF807FF00u);
		uint32_t hi = static_cast<uint16_t>(t >> 16) ^ 0xEBCu;
		return make_v213(hi, hi ^ t);
	}
	case 8: {
		uint32_t t = _rotr(enc - 2045210569u, 29);
		return (static_cast<uint8_t>(t) << 21) | static_cast<uint8_t>(t >> 21) | (t & 0xE01FFF00u);
	}
	case 9: {
		uint32_t t = (static_cast<uint8_t>(enc >> 16) << 13)
			| static_cast<uint8_t>((((enc >> 16) | (enc << 16)) >> 13))
			| ((((enc >> 16) | (enc << 16)) & 0xFFE01F00u));
		return _rotr(t, 16);
	}
	case 10: {
		uint32_t t = (static_cast<uint8_t>(enc >> 16) << 19)
			| static_cast<uint8_t>((((enc >> 16) | (enc << 16)) >> 19))
			| (((enc >> 16) | (enc << 16)) & 0xF807FF00u);
		uint32_t hi = static_cast<uint16_t>(t >> 16) ^ 0xEBCu;
		return make_v213(hi, hi ^ t);
	}
	case 11: return (enc ^ 0xFFFFu) + 668682831u;
	case 12: {
		uint32_t hi = ((enc - 1940437029u) >> 16) ^ 0xD83Cu;
		return make_v213(hi, hi ^ (enc + 0x47DBu)) - 477622591u;
	}
	case 13: return _rotr(enc ^ 0xA48EA896u, 25);
	case 14: return ~_rotr(enc - 1638740713u, 16);
	case 15: return enc ^ 0x3DB955C3u;
	case 16: {
		uint32_t t = (static_cast<uint8_t>(enc) << 23) | static_cast<uint8_t>(enc >> 23) | (enc & 0x807FFF00u);
		return t ^ 0xE388F13Au;
	}
	case 17: {
		uint32_t t = 1130671833u * (enc ^ 0xFFFFu);
		uint32_t hi = 3782u ^ static_cast<uint16_t>(t >> 16);
		return make_v213(hi, hi ^ t);
	}
	case 18: {
		uint8_t lo = static_cast<uint8_t>(enc >> 9);
		uint32_t t = (static_cast<uint8_t>(enc) << 9) | lo | (enc & 0xFFFE0100u);
		uint32_t x = t ^ 0xFFFFu;
		return (static_cast<uint8_t>(~(enc >> 9)) << 15) | static_cast<uint8_t>(x >> 15) | (x & 0xFF807F00u);
	}
	case 19: {
		uint32_t t = (static_cast<uint8_t>(enc) << 13) | static_cast<uint8_t>(enc >> 13) | (enc & 0xFFE01F00u);
		return _rotr(t, 27) - 477622581u;
	}
	case 20: {
		uint32_t t = (static_cast<uint8_t>(enc) << 11) | static_cast<uint8_t>(enc >> 11) | (enc & 0xFFF80700u);
		return static_cast<uint32_t>(-185754139 * static_cast<int>(_rotr(t, 16)));
	}
	case 21: return 477622581u - (enc + 1704696564u);
	case 22: return ~_rotr(enc ^ 0xFFFFu, 16);
	case 23: {
		uint32_t t = (static_cast<uint8_t>(enc + 34) << 19)
			| static_cast<uint8_t>((enc + 1652309794u) >> 19)
			| ((enc + 1652309794u) & 0xF807FF00u);
		return _rotr(t, 4);
	}
	case 24: {
		uint32_t t = (static_cast<uint8_t>(enc) << 15) | static_cast<uint8_t>(enc >> 15) | (enc & 0xFF807F00u);
		return ~_rotr(t, 16);
	}
	case 25: return ~_rotr((enc + 1495149484u) ^ 0x6DE64A39u, 16);
	case 26: {
		uint8_t lo = static_cast<uint8_t>(enc >> 17);
		uint32_t t = (static_cast<uint8_t>(enc) << 17) | lo | (enc & 0xFE01FF00u);
		uint32_t hi = static_cast<uint16_t>(t >> 16) ^ 0xCCB2u;
		return make_v213(hi, hi ^ (lo | (enc & 0xFF00u))) ^ 0xE3880ECFu;
	}
	case 27: return ~_rotr(enc - 1695731499u, 16);
	case 28: {
		uint32_t t = static_cast<uint32_t>(-static_cast<int>(enc) - 558942989);
		return (static_cast<uint8_t>(t) << 9) | static_cast<uint8_t>(t >> 9) | (t & 0xFFFE0100u);
	}
	case 29: return ~_rotr((enc + 1495149484u) ^ 0x6DE64A39u, 16);
	case 30: return 851723965u * (enc ^ 0xFFFF0000u);
	case 31: return 851723965u * enc - 44760802u;
	case 32: return (enc ^ 0xFFFF0000u) - 477622571u;
	case 33: {
		uint32_t hi = static_cast<uint16_t>(enc >> 16) ^ 0x8BF8u;
		return _rotr(~make_v213(hi, hi ^ enc), 14);
	}
	case 34: return ~_rotr(~enc, 16);
	case 35: return ~_rotr((enc + 1495149484u) ^ 0x6DE64A39u, 16);
	case 36: return _rotr(~enc, 25) ^ 0xE3880ED9u;
	case 37: {
		uint32_t hi = static_cast<uint16_t>(enc >> 16) ^ 0x439Cu;
		uint32_t v = make_v213(hi, hi ^ enc);
		uint32_t t = (static_cast<uint8_t>(v) << 9) | static_cast<uint8_t>(v >> 9) | (v & 0xFFFE0100u);
		uint32_t h2 = static_cast<uint16_t>(t >> 16) ^ 3802u;
		return make_v213(h2, h2 ^ t);
	}
	case 38: {
		uint32_t hi = static_cast<uint16_t>(enc >> 16) ^ 0x9F6Eu;
		return _rotr(make_v213(hi, hi ^ enc) + 1807565307u, 16);
	}
	case 39: {
		uint32_t hi = static_cast<uint16_t>(enc >> 16) ^ 0x9F6Eu;
		return _rotr(make_v213(hi, hi ^ enc) + 1807565307u, 16);
	}
	case 40: {
		uint32_t t = static_cast<uint32_t>(-1107694519 * static_cast<int>(enc));
		uint32_t hi = static_cast<uint16_t>(-16088 ^ static_cast<int>(t >> 16));
		return static_cast<uint32_t>(-1107694519 * static_cast<int>(make_v213(hi, hi ^ t)));
	}
	case 41: {
		uint32_t hi = static_cast<uint16_t>(enc >> 16) ^ 0xFB40u;
		return make_v213(hi, hi ^ enc) + 559952247u;
	}
	case 42: return static_cast<uint32_t>(-185754139 * static_cast<int>(enc) - 1844818083);
	case 43: return _rotr(_rotr(enc, 20) ^ 0x9E133EAFu, 24);
	case 44: return ~_rotr(851723965u * enc + 358040100u, 16);
	case 45: return static_cast<uint32_t>((-869532003 * static_cast<int>(_rotr(enc, 31))) ^ 0xFFFF);
	case 46: return static_cast<uint32_t>((-1107694519 * static_cast<int>(enc)) ^ 0xE388F11Cu);
	case 47: {
		uint32_t t = static_cast<uint32_t>(-869532003 * static_cast<int>(_rotr(enc, 11)));
		uint32_t hi = static_cast<uint16_t>(t >> 16) ^ 3812u;
		return make_v213(hi, hi ^ t);
	}
	case 48: {
		uint32_t x = enc ^ 0xC48BBC9Fu;
		uint32_t t = (static_cast<uint8_t>(x >> 16) << 13)
			| static_cast<uint8_t>((((x >> 16) | (x << 16)) >> 13))
			| ((((x >> 16) | (x << 16)) & 0xFFE01F00u));
		return t;
	}
	case 49: return ~_rotr(_rotr(enc, 22), 16);
	default: return 0;
	}
}

} // namespace xe_offset
