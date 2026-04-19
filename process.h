#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <tlhelp32.h>
#include "../comm_exmp_client/c_driver.h"

// driver-backed memory access wrapper
class process {
public:
	bool attach(const char* proc_name);
	void detach();

	uint64_t base() const { return base_; }
	uint32_t pid() const { return pid_; }
	bool valid() const { return ready_; }

	bool read_raw(uint64_t addr, void* buf, size_t size) const;
	bool write_raw(uint64_t addr, const void* buf, size_t size) const;

	template<typename T>
	T read(uint64_t addr) const {
		T val{};
		read_raw(addr, &val, sizeof(T));
		return val;
	}

	template<typename T>
	bool write(uint64_t addr, const T& val) const {
		return write_raw(addr, &val, sizeof(T));
	}

	std::vector<uint8_t> read_bytes(uint64_t addr, size_t size) const;
	std::string read_string(uint64_t addr, size_t max_len = 256) const;

	// follows pointer chain: base -> [base+off0] -> [prev+off1] -> ...
	uint64_t read_chain(uint64_t base, std::initializer_list<uint64_t> offsets) const;

	// module enumeration
	uint64_t get_module_base(const char* mod_name) const;

	// pattern scan in remote process memory
	uint64_t pattern_scan(uint64_t start, size_t size, const char* ida_sig) const;

private:
	bool ready_ = false;
	uint32_t pid_ = 0;
	uint64_t base_ = 0;
};
