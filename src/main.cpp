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
#include <Windows.h> 

#include "picosha2.h"

namespace fs = std::filesystem;

struct FileRecord {
	std::string path;
	uintmax_t size;
	std::string hash;
};

// takes a file path, returns a SHA-256 hash for the given file using picoSHA2
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

// takes the path to the csv file, if it doesnt exist yet (first run of this directory) returns empty map
// if the file exists, open it for reading and return a std::map keyed by file path containing each previous
// hash as values to be diffed against
std::map<std::string, std::string> loadBaseline(const fs::path& csvPath) {
	std::map<std::string, std::string> baseline{};

	if (!fs::exists(csvPath)) {
		return baseline;
	}
	
	std::ifstream in(csvPath);
	std::string line{};
	// skip header row
	std::getline(in, line);

	// read one line at a time
	while (std::getline(in, line)) {
		// wrap line in std::stringstream
		std::stringstream lineStream{ line };
		std::string pathField{};
		std::string sizeField{};
		std::string hashField{};
		
		// pull out three fields one at a time
		std::getline(lineStream, pathField, ',');
		std::getline(lineStream, sizeField, ',');
		std::getline(lineStream, hashField, ',');
		
		// store in map keyed by file path with the hash as value
		baseline[pathField] = hashField;
	}

	return baseline;
}

// opens a handle to the directory file, then blocks waiting for filesystem change from the OS, forever
bool openDirectoryHandle(fs::path targetDir) {
	HANDLE handle{ CreateFileW(
		targetDir.wstring().c_str(),
		FILE_LIST_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS,
		nullptr
	) };

	if (handle == INVALID_HANDLE_VALUE) {
		std::cout << "FAILURE" << '\n';
		return false;
	}
	else {
		std::cout << "SUCCESS" << '\n';

		while (true) {
			// the OS writes raw bytes here representing one or more change records
			// we're currently only reading the first one
			BYTE buffer[1024];
			DWORD empty;
			BOOL success{ ReadDirectoryChangesW(
				handle,
				buffer,
				sizeof(buffer),
				TRUE,
				FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
				&empty,
				nullptr,
				nullptr
			) };

			if (!success) {
				std::cout << "ReadDirectoryChangesW failed\n";
			}
			else {
				// LIMITATION: we could return multiple chained entries via NextEntryOffset but this doesn't handle that yet
				FILE_NOTIFY_INFORMATION* info{ reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer) };
				switch (info->Action) {
				case FILE_ACTION_ADDED:
					std::cout << "[ADDED]" << '\n';
					break;
				case FILE_ACTION_REMOVED:
					std::cout << "[REMOVED]" << '\n';
					break;
				case FILE_ACTION_MODIFIED:
					std::cout << "[MODIFIED]" << '\n';
					break;
				case FILE_ACTION_RENAMED_OLD_NAME:
					std::cout << "[RENAMED_OLD_NAME]" << '\n';
					break;
				case FILE_ACTION_RENAMED_NEW_NAME:
					std::cout << "[RENAMED_NEW_NAME]" << '\n';
					break;
				default:
					std::cout << "[UNKNOWN ACTION]" << '\n';
					break;
				}
				std::cout << "Change detected! Bytes returned: " << empty << '\n';
			}
		}
		CloseHandle(handle);
		return true;
	}
}

int main(int argc, char* argv[]) {
	// setup which directory the program operates on
	// run cmd: fim.exe (file directory)
	// if argc > 1 (two arguments) -> targetDir = the path given as the second argument
	// otherwise targetDir = current_path() (the directory where program was launched from)
	fs::path targetDir{ (argc > 1) ? fs::path(argv[1]) : fs::current_path() };

	if (!fs::exists(targetDir) || !fs::is_directory(targetDir)) {
		std::cerr << "Error: " << targetDir.string() << " is not a valid directory.\n";
		return 1;
	}

	std::cout << "Scanning: " << fs::absolute(targetDir).string() << "\n\n";

	// get our old baseline as a std::map for diff logic
	std::map<std::string, std::string> oldBaseline{ loadBaseline(targetDir / "baseline.csv") };
	// hold one FileRecord for every file the scan finds this run
	std::vector<FileRecord> files{};
	// recursively walks targetDir and every subdirectory beneath it
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

		// print notification if current path does not exist in oldBaseline - or if its been modified
		auto it{ oldBaseline.find(path) };
		if (it == oldBaseline.end()) {
			std::cout << "[ADDED] " << path << '\n';
		}
		else if (it->second != hash) {
			std::cout << "[MODIFIED] " << path << '\n';
		}

		std::cout << path << '\n'
			<< " size: " << size << '\n'
			<< " hash: " << hash << "\n\n";

		files.push_back({ path, size, hash });
	}

	// check whether every file in oldBaseline is still present or if its been removed
	for (const auto& [path, hash] : oldBaseline) {
		auto found{ std::find_if(files.begin(), files.end(),
			[&path](const FileRecord& record) {
				return record.path == path;
			}) };

		if (found == files.end()) {
			std::cout << "[REMOVED] " << path << '\n';
		}
	}

	// write baseline.csv on disk to match exactly what the file system looked like at the moment of this scan
	std::ofstream out(targetDir / "baseline.csv");
	out << "path,size,sha256\n";
	for (const auto& record : files) {
		out << record.path << "," << record.size << "," << record.hash << '\n';
	}

	// handoff from setup to realtime watching
	openDirectoryHandle(targetDir);

	return 0;
}
