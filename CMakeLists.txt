cmake_minimum_required(VERSION 3.15)
project(FileIntegrityMonitor CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Pull in PicoSHA2, a small single-header SHA-256 implementation,
# instead of hand-rolling hashing or fighting with OpenSSL setup on Windows.
include(FetchContent)
FetchContent_Declare(
  picosha2
  GIT_REPOSITORY https://github.com/okdshin/PicoSHA2.git
  GIT_TAG        master
)
FetchContent_MakeAvailable(picosha2)

add_executable(fim src/main.cpp)
target_include_directories(fim PRIVATE ${picosha2_SOURCE_DIR})
