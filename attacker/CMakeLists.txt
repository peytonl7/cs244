cmake_minimum_required(VERSION 3.28.3)
project("CS 244 Attacker" LANGUAGES CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

FetchContent_Declare(
  argparse
  GIT_REPOSITORY "https://github.com/p-ranav/argparse.git"
  GIT_TAG "v3.0")
FetchContent_Declare(
  yaml-cpp
  GIT_REPOSITORY "https://github.com/jbeder/yaml-cpp.git"
  GIT_TAG "0.8.0")
FetchContent_MakeAvailable(argparse yaml-cpp)

add_library(tcp-raw
  src/tcp-raw/interface/interface.cpp
  src/tcp-raw/interface/exceptions.cpp)
target_include_directories(tcp-raw
  PUBLIC include/tcp-raw/)

add_executable(detect-ports
  src/detect-ports/main.cpp)
target_link_libraries(detect-ports
  PRIVATE tcp-raw argparse)