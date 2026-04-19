#include "process.h"
#include <cstdio>

bool process::attach(const char* proc_name) {
	auto& drv = c_driver::get();

	if (!drv.is_ready()) {
		printf("[*] initializing driver...\n");
		if (!drv.init(proc_name, "UnrealWindow", "PUBG: BATTLEGROUNDS ")) {
			printf("[-] driver init failed\n");
			return false;
		}
	}

	// find the real game window - PID
	HWND hwnd = FindWindowA("UnrealWindow", "PUBG: BATTLEGROUNDS ");
	if (!hwnd) {
		printf("[-] couldn't find game window\n");
		return false;
	}

	DWORD wnd_pid = 0;
	GetWindowThreadProcessId(hwnd, &wnd_pid);
	if (!wnd_pid) {
		printf("[-] GetWindowThreadProcessId failed\n");
		return false;
	}

	pid_ = wnd_pid;	
	printf("[*] game window PID: %u\n", pid_);

	// get base via driver
	base_ = drv.get_base(pid_);
	if (!base_)
		base_ = drv.get_module_base(pid_);
	if (!base_) {
		printf("[-] driver couldn't resolve base for pid %u\n", pid_);
		return false;
	}

	ready_ = true;
	return true;
}

void process::detach() {
	ready_ = false;
	pid_ = 0;
	base_ = 0;
}

bool process::read_raw(uint64_t addr, void* buf, size_t size) const {
	if (!ready_) return false;
	return c_driver::get().read_memory(pid_, addr, buf, size);
}

bool process::write_raw(uint64_t addr, const void* buf, size_t size) const {
	if (!ready_) return false;
	return c_driver::get().write_memory(pid_, addr, buf, size);
}

std::vector<uint8_t> process::read_bytes(uint64_t addr, size_t size) const {
	std::vector<uint8_t> buf(size);
	if (!read_raw(addr, buf.data(), size))
		buf.clear();
	return buf;
}

std::string process::read_string(uint64_t addr, size_t max_len) const {
	std::string buf(max_len, '\0');
	if (!read_raw(addr, buf.data(), max_len)) {
		buf.clear();
		return buf;
	}
	auto pos = buf.find('\0');
	if (pos != std::string::npos)
		buf.resize(pos);
	return buf;
}

uint64_t process::read_chain(uint64_t base, std::initializer_list<uint64_t> offsets) const {
	uint64_t addr = base;
	for (auto off : offsets) {
		addr = read<uint64_t>(addr);
		if (!addr) return 0;
		addr += off;
	}
	return addr;
}

uint64_t process::get_module_base(const char* mod_name) const {
	// driver only gives main module — for other modules fall back to snapshot
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
	if (snap == INVALID_HANDLE_VALUE)
		return 0;

	MODULEENTRY32 me{};
	me.dwSize = sizeof(me);
	uint64_t result = 0;

	if (Module32First(snap, &me)) {
		do {
			if (_stricmp(me.szModule, mod_name) == 0) {
				result = (uint64_t)me.modBaseAddr;
				break;
			}
		} while (Module32Next(snap, &me));
	}

	CloseHandle(snap);
	return result;
}

// ida-style sig scan: "48 8B ?? ?? 48 85 C0"
uint64_t process::pattern_scan(uint64_t start, size_t size, const char* ida_sig) const {
	std::vector<uint8_t> sig_bytes;
	std::vector<bool> sig_mask;

	const char* cur = ida_sig;
	while (*cur) {
		if (*cur == ' ') { cur++; continue; }
		if (*cur == '?') {
			sig_bytes.push_back(0);
			sig_mask.push_back(false);
			cur++;
			if (*cur == '?') cur++;
			continue;
		}
		uint8_t byte = (uint8_t)strtoul(cur, nullptr, 16);
		sig_bytes.push_back(byte);
		sig_mask.push_back(true);
		cur += 2;
	}

	constexpr size_t CHUNK_SIZE = 0x100000;
	size_t sig_len = sig_bytes.size();

	for (size_t offset = 0; offset < size; offset += CHUNK_SIZE - sig_len) {
		size_t read_size = min(CHUNK_SIZE, size - offset);
		auto chunk = read_bytes(start + offset, read_size);
		if (chunk.empty()) continue;

		for (size_t i = 0; i + sig_len <= chunk.size(); i++) {
			bool match = true;
			for (size_t j = 0; j < sig_len; j++) {
				if (sig_mask[j] && chunk[i + j] != sig_bytes[j]) {
					match = false;
					break;
				}
			}
			if (match)
				return start + offset + i;
		}
	}

	return 0;
}
