/**
  \file config.hpp
  \brief Configuration file containing the network topology

  What we do is heavily dependent on the network topology. This file contains a
  structure defining the parameters we're interested in, as well as a way to
  parse it from a file.
*/

#pragma once

#include "tcp-packet.hpp"

struct Topology {
  /**
    \brief IP and Port of the server
  */
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
  uint8_t ttl_drop;
};
