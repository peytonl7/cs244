/**
  \file app.hpp
  \brief Configuration for the `detect-ports` application
*/

#pragma once

#include <chrono>

#include "tcp-interface.hpp"
#include "topology.hpp"

/**
  \brief Structure with all the arguments needed for one run of this application
*/
struct Configuration {

  /** \brief The interface to send on */
  TCPInterface &interface;
  /** \brief The topology of the network to attack */
  const Topology &topology;

  /** \brief The port to scan for connections on */
  TCPPacket::Address::Port scan_port;

  /** \brief How long to wait between sending and receiving */
  std::chrono::milliseconds timeout;
  /** \brief How long to wait after sending each packet */
  std::chrono::milliseconds packet_delay;
  /** \brief How many time to duplicate packets */
  size_t packet_redundancy;
};

/** \brief Possible results of this attack */
enum RunStatus {
  FREE,
  OCCUPIED,
};
