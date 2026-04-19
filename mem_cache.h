#pragma once
#include "process.h"
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <cstring>

// local memory cache — bulk-reads GObjects array and FNamePool blocks
// from the driver once, then serves all subsequent reads from local copies.
// dramatically reduces driver calls during SDK analysis.

class mem_cache {
public:
	mem_cache(process& proc) : proc_(proc) {}

	// phase 1: cache the full GObjects array (count * FUOBJECTITEM_SIZE bytes)
	bool cache_gobjects(uint64_t array_ptr, int32_t count);

	// phase 2: cache FNamePool chunks (block pointers + entry data)
	bool cache_fnamepool_chunks(uint64_t chunks_ptr, int max_blocks = 512);

	// phase 3: cache individual object blobs (read object + property data in one shot)
	// called per-object, stored in addr-indexed map
	bool cache_object(uint64_t addr, size_t size = 0x100);

	// bulk cache: read all valid objects from the GObjects array (one big pass)
	int cache_all_objects(size_t obj_read_size = 0x100);

	// read from cache (falls back to driver if not cached)
	bool read(uint64_t addr, void* buf, size_t size) const;

	template<typename T>
	T read_val(uint64_t addr) const {
		T val{};
		read(addr, &val, sizeof(T));
		return val;
	}

	// direct reads from cached GObjects array
	uint64_t get_object_ptr(int32_t index) const;
	int32_t get_object_flags(int32_t index) const;

	// direct reads from cached FNamePool
	uint64_t get_fname_block_ptr(int32_t block_idx) const;

	// stats
	int32_t gobjects_count() const { return gobjects_count_; }
	size_t cached_objects() const { return obj_cache_.size(); }
	size_t total_cached_bytes() const;

private:
	process& proc_;

	// GObjects array cache (contiguous buffer)
	std::vector<uint8_t> gobjects_buf_;
	uint64_t gobjects_base_ = 0;
	int32_t gobjects_count_ = 0;

	// FNamePool block pointers cache
	std::vector<uint64_t> fname_block_ptrs_;

	// object blob cache: addr → {data}
	std::unordered_map<uint64_t, std::vector<uint8_t>> obj_cache_;

	// helper: find which cached blob contains the given address
	const uint8_t* find_in_cache(uint64_t addr, size_t size) const;
};
