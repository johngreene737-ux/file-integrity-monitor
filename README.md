# File Integrity Monitor

## What it is and why
A file integrity scanner loosely based on CrowdStrike's Falcon platform. Given a file directory,
it walks through each file, creating a hash for each one and then comparing it against a previous baseline
run of the file system. Uses the hash system to detect changes in files, as well as new or missing files 
from the last run through. This mimics Crowdstrike Falcon at a much smaller scale.

## What it currently does
Performs baseline scanning using SHA-256 hashing. Diff mode compares the previously saved baseline
SHA-256 hash values to report added, modified, and removed files.

## How to build it
Built in Visual Studio using CMake. Using C++ VS workload, open a folder and let CMake configure and build.

## How to run it
Use command line fim.exe [path]. First run will scan files in the given directory and create the baseline.csv
file. Subsequent runs use the previously created baseline to run a diff mode - reporting modified, added, and
removed files.

## What's next / limitations
Next step is real-time monitoring. Instead of running the scan manually each time, we can watch the filesystem
live through ReadDirectoryChangesW. Beyond that, a basic logging/alerting system with timestamps.