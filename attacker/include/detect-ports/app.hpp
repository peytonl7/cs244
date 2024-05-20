/**
  \file app.hpp
  \brief Configuration for the `detect-ports` application
*/

#pragma once

#include <chrono>

#include "tcp-packet.hpp"
#include "topology.hpp"

/**
  \brief Structure with all the arguments needed for one run of this application
*/
struct Configuration {

  /** \brief The topology of the network to attack */
  Topology topology;

  /** \see scan_port_range */
  struct PortRange {
    TCPPacket::Address::Port start;
    TCPPacket::Address::Port end;
  };
  /**
    \brief The range of ports to scan for connections on

    The elements of the pair are the start and end of the range. Both ends are
    inclusive.
  */
  PortRange scan_port_range;

  /** \brief How long to wait between sending and receiving */
  std::chrono::milliseconds timeout;
  /** \brief How long to wait after sending each packet */
  std::chrono::milliseconds packet_delay;
  /** \brief How many time to duplicate packets */
  size_t packet_redundancy;

  /** \brief Whether or not to use control codes */
  bool dumb_terminal;

  /**
    \brief Get the Configuration from command-line arguments
    \details This subroutine will exit on failure
  */
  static Configuration args(int argc, char **argv);
};

/** \brief Possible results of this attack */
enum RunStatus {
  FREE,
  OCCUPIED,
};
