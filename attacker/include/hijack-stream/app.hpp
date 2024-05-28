/**
  \file app.hpp
  \brief Configuration for the `hijack-stream` application
*/

#pragma once

#include <chrono>

#include "topology.hpp"

/**
  \brief Structure with all the arguments needed for one run of this application
*/
struct Configuration {

  /** \brief The topology of the network to attack */
  Topology topology;

  /** \brief The port of an active connection for attempted hijacking*/
  uint16_t port;

  /** \brief How long to wait between sending and receiving */
  std::chrono::milliseconds timeout;
  /** \brief How long to wait after sending each packet */
  std::chrono::milliseconds packet_delay;
  /** \brief How many time to duplicate packets */
  size_t packet_redundancy;

  /** \brief How long to wait before attempting to reset the connection at the router */
  std::chrono::milliseconds router_timeout;

  /**
    \brief Get the Configuration from command-line arguments
    \details This subroutine will exit on failure
  */
  static Configuration args(int argc, char **argv);
};