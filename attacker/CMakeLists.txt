cmake_minimum_required(VERSION 3.28.3)
project("CS 244 Attacker" LANGUAGES CXX)

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
