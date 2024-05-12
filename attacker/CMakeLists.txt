cmake_minimum_required(VERSION 3.28.3)
project("CS 244 Attacker" LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
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
  PUBLIC tcp-packet yaml-cpp::yaml-cpp)

add_executable(detect-ports
  src/detect-ports/main.cpp)
target_include_directories(detect-ports
  PRIVATE include/detect-ports/)
target_link_libraries(detect-ports
  PRIVATE tcp-interface topology argparse::argparse)
