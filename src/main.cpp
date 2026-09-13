// File Integrity Monitor — baseline scanner
//
// Walks a directory, computes a SHA-256 hash of every regular file it finds,
// prints what it saw, and writes a baseline manifest (baseline.csv) that a
// later run can be diffed against.
//
// Usage:
//   fim.exe [path-to-directory]
//   (defaults to the current directory if no argument is given)

#include <algorithm>
#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include <vector>
#include <iterator>
#include <map>
#include <sstream>

#include "picosha2.h"

namespace fs = std::filesystem;

struct FileRecord {
	std::string path;
	uintmax_t size;
	std::string hash;
};

std::string hashFile(const fs::path& path) {
	std::ifstream file(path, std::ios::binary);
	if (!file) {
		return "ERROR_READING_FILE";
	}
	
	std::vector<unsigned char> hash(picosha2::k_digest_size);
	picosha2::hash256(std::istreambuf_iterator<char>(file),
					std::istreambuf_iterator<char>(),
					hash.begin(), hash.end());
	return picosha2::bytes_to_hex_string(hash.begin(), hash.end());
}

std::map<std::string, std::string> loadBaseline(const fs::path& csvPath) {
	std::map<std::string, std::string> baseline{};

	if (!fs::exists(csvPath)) {
		return baseline;
	}
	
	std::ifstream in(csvPath);
	std::string line{};
	std::getline(in, line);

	while (std::getline(in, line)) {
		std::stringstream lineStream{ line };
		std::string pathField{};
		std::string sizeField{};
		std::string hashField{};
			
		std::getline(lineStream, pathField, ',');
		std::getline(lineStream, sizeField, ',');
		std::getline(lineStream, hashField, ',');
		
		baseline[pathField] = hashField;
	}

	return baseline;
}

int main(int argc, char* argv[]) {
	fs::path targetDir{ (argc > 1) ? fs::path(argv[1]) : fs::current_path() };

	if (!fs::exists(targetDir) || !fs::is_directory(targetDir)) {
		std::cerr << "Error: " << targetDir.string() << " is not a valid directory.\n";
		return 1;
	}

	std::cout << "Scanning: " << fs::absolute(targetDir).string() << "\n\n";

	std::map<std::string, std::string> oldBaseline{ loadBaseline(targetDir / "baseline.csv") };
	std::vector<FileRecord> files{};
	for (const auto& entry : fs::recursive_directory_iterator(targetDir)) {
		if (!entry.is_regular_file()) {
			continue;
		}
		if (entry.path() == targetDir / "baseline.csv") {
			continue;
		}

		std::string path{ entry.path().string() };
		uintmax_t size{ entry.file_size() };
		std::string hash{ hashFile(entry.path()) };

		auto it{ oldBaseline.find(path) };
		if (it == oldBaseline.end()) {
			std::cout << "[ADDED] " << path << '\n';
		}
		if (it->second != hash) {
			std::cout << "[MODIFIED] " << path << '\n';
		}

		std::cout << path << '\n'
			<< " size: " << size << '\n'
			<< " hash: " << hash << "\n\n";

		files.push_back({ path, size, hash });
	}

	for (const auto& [path, hash] : oldBaseline) {
		auto found{ std::find_if(files.begin(), files.end(),
			[&path](const FileRecord& record) {
				return record.path == path;
			}) };

		if (found == files.end()) {
			std::cout << "[REMOVED] " << path << '\n';
		}
	}

	std::ofstream out(targetDir / "baseline.csv");
	out << "path,size,sha256\n";
	for (const auto& record : files) {
		out << record.path << "," << record.size << "," << record.hash << '\n';
	}

	return 0;
}
