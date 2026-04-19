#include "process.h"
#include "dumper.h"
#include "sdk_dumper.h"
#include <cstdio>
#include <ctime>
#include <filesystem>

#define TARGET_PROCESS "TslGame.exe"

static std::string make_output_dir() {
	time_t now = time(nullptr);
	tm t{};
	localtime_s(&t, &now);

	char date_buf[32];
	snprintf(date_buf, sizeof(date_buf), "%02d_%02d_%04d_tslgame",
		t.tm_mday, t.tm_mon + 1, t.tm_year + 1900);

	auto dir = std::filesystem::path("dumps") / date_buf;
	std::filesystem::create_directories(dir);
	return dir.string();
}

int main(int argc, char** argv) {
	printf("=== pubg_dumper ===\n\n");

	std::string out_dir = (argc > 1) ? argv[1] : make_output_dir();

	process proc;

	printf("[*] looking for %s...\n", TARGET_PROCESS);
	if (!proc.attach(TARGET_PROCESS)) {
		printf("[-] failed to attach to %s\n", TARGET_PROCESS);
		return 1;
	}

	printf("[+] attached — pid: %u, base: 0x%llX\n\n", proc.pid(), proc.base());

	uint16_t mz = proc.read<uint16_t>(proc.base());
	if (mz != 0x5A4D) {
		printf("[-] can't read MZ at base — wrong process or driver issue\n");
		proc.detach();
		return 1;
	}

	bool ok = true;

	// pe dump (keep dumper alive so sdk_dumper can access the image)
	dumper d(proc);
	{
		std::string pe_path = out_dir + "/TslGame_dump.exe";
		printf("[*] PE dump: %s\n\n", pe_path.c_str());

		if (d.dump_to_file(pe_path))
			printf("\n[+] PE dump complete\n\n");
		else {
			printf("\n[-] PE dump failed\n\n");
			ok = false;
		}
	}

	// sdk dump — pass the dumped PE image for sig scanning
	{
		printf("[*] SDK dump: %s/\n\n", out_dir.c_str());

		sdk_dumper sd(proc);

		// hand the local PE copy to sig scanner
		if (!d.image().empty()) {
			sd.set_pe_image(d.image().data(), d.image().size(), d.image_base());
		}

		if (!sd.dump(out_dir)) {
			printf("\n[-] SDK dump failed\n");
			ok = false;
		}
	}

	proc.detach();
	return ok ? 0 : 1;
}
