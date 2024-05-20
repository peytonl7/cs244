/**
  \file config.hpp
  \brief Configuration file containing the network topology

  What we do is heavily dependent on the network topology. This file contains a
  structure defining the parameters we're interested in, as well as a way to
  parse it from a file.
*/

#pragma once

#include <stdexcept>

#include "tcp-interface.hpp"
#include "tcp-packet.hpp"

struct Topology {

  /** \brief Our interface onto the network */
  TCPInterface interface;

  /** \brief IP and Port of the server */
  TCPPacket::Address server_addr;

  /**
    \brief IP addresses of the router and the attacker
    \details The port we use is chosen at runtime
  */
  TCPPacket::Address::IP router_ip;
  TCPPacket::Address::IP attacker_ip;

  /**
    \brief TTL of packets sent to the server so they are dropped by the router

    In order to perform the attack, we need the router to route packets to the
    server, but for them to never actually reach. This fields is a TTL value
    that gives packets this property.
  */
  uint8_t server_ttl_drop;

  /**
    \brief Parse a topology from a file
    \param filename The name of the file to parse
    \return The parsed topology
    \throws ParseError If the file is not formatted correctly
  */
  static Topology parse(const std::string &filename);

  /** \brief Exception thrown if a topology file cannot be read */
  class ReadError : public std::runtime_error {
  public:
    ReadError(const std::string &filename, const std::string &message)
        : std::runtime_error("Failed to read topology file `" + filename +
                             "`: " + message) {}
  };
};
