cmake_minimum_required(VERSION 3.28.3)
project("CS 244 Attacker" LANGUAGES CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

option(YAML_CPP_BUILD_TOOLS ON)
FetchContent_Declare(
  argparse
  GIT_REPOSITORY "https://github.com/p-ranav/argparse.git"
  GIT_TAG "v3.0")
FetchContent_Declare(
  yaml-cpp
  GIT_REPOSITORY "https://github.com/jbeder/yaml-cpp.git"
  GIT_TAG "0.8.0")
FetchContent_MakeAvailable(argparse yaml-cpp)

add_library(tcp-packet
  src/tcp-packet/packet.cpp)
target_include_directories(tcp-packet
  PUBLIC include/tcp-packet/)

add_library(tcp-interface
  src/tcp-interface/interface.cpp)
target_include_directories(tcp-interface
  PUBLIC include/tcp-interface/)
target_link_libraries(tcp-interface
  PUBLIC tcp-packet)

add_library(topology
  src/topology/topology.cpp)
target_include_directories(topology
  PUBLIC include/topology/)
target_link_libraries(topology
  PUBLIC tcp-interface yaml-cpp::yaml-cpp)

add_executable(detect-ports
  src/detect-ports/main.cpp
  src/detect-ports/configuration.cpp)
target_include_directories(detect-ports
  PRIVATE include/detect-ports/)
target_link_libraries(detect-ports
  PRIVATE tcp-interface topology argparse::argparse)

add_executable(close-stream
  src/close-stream/main.cpp
  src/close-stream/configuration.cpp)
target_include_directories(close-stream
  PRIVATE include/close-stream/)
target_link_libraries(close-stream
  PRIVATE tcp-interface topology argparse::argparse)

add_executable(hijack-stream
  src/hijack-stream/main.cpp
  src/hijack-stream/configuration.cpp)
target_include_directories(hijack-stream
  PRIVATE include/hijack-stream/)
target_link_libraries(hijack-stream
  PRIVATE tcp-interface topology argparse::argparse)

add_executable(test-out-of-window
  src/test-out-of-window/main.cpp
  src/test-out-of-window/configuration.cpp)
target_include_directories(test-out-of-window
  PRIVATE include/test-out-of-window/)
target_link_libraries(test-out-of-window
  PRIVATE tcp-interface topology argparse::argparse)
