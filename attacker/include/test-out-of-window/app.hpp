#pragma once

#include <chrono>

#include "topology.hpp"

struct Configuration {
  Topology topology;

  std::chrono::milliseconds timeout;
  std::chrono::milliseconds packet_delay;
  size_t packet_redundancy;

  static Configuration args(int argc, char **argv);
};
