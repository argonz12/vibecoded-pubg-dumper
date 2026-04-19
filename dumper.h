#pragma once
#include "process.h"
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>

// pe section info from remote process
struct remote_section {
	char name[9];
	uint32_t va;
	uint32_t vsize;
	uint32_t raw_ptr;
	uint32_t raw_size;
	uint32_t chars;
};

class dumper {
public:
	dumper(process& proc) : proc_(proc) {}

	// dump the full PE from memory, reconstruct headers, write to disk
	bool dump_to_file(const std::string& output_path);

	// dump a specific module by name
	bool dump_module(const char* mod_name, const std::string& output_path);

	// access the in-memory dump (valid after dump_to_file)
	const std::vector<uint8_t>& image() const { return image_; }
	uint64_t image_base() const { return mod_base_; }

private:
	// read PE headers from remote process
	bool read_pe_headers(uint64_t mod_base);

	// get section table from remote memory
	bool read_sections(uint64_t mod_base);

	// read the full image from memory (all sections)
	bool read_image(uint64_t mod_base);

	// fix up the dumped PE headers for IDA compatibility
	void fix_headers();

	// write the final output
	bool write_output(const std::string& path);

	process& proc_;

	// parsed header info
	uint64_t mod_base_ = 0;
	uint32_t e_lfanew_ = 0;
	uint32_t num_sections_ = 0;
	uint32_t optional_hdr_size_ = 0;
	uint32_t size_of_image_ = 0;
	uint32_t section_align_ = 0;
	uint32_t file_align_ = 0;
	bool is_pe64_ = false;

	std::vector<remote_section> sections_;
	std::vector<uint8_t> image_; // the full dumped image
};
