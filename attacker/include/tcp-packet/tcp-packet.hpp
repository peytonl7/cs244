/**
  \file tcp-packet.hpp
  \brief High-level structure of a TCP packet

  This module doesn't provide access to all the fields of the packet. Instead,
  it only exposes what is deemed useful to the application. In particular, it's
  forced to operate over IPv4.
*/

#pragma once

#include <cstdint>
#include <limits>
#include <optional>
#include <string>

struct TCPPacket {

  /**
    \brief Structures for source and destination addresses

    The IP address is stored in host-order. This means taking it modulo 256 will
    give the last set of digits in the IP address.
  */
  struct Address {
    uint32_t ip;
    uint16_t port;
  };

  /**
    \brief Fields that are "independent" of the TCP stream
    @{
  */
  Address src;
  Address dst;
  uint8_t ttl = 64;
  uint16_t window_size = std::numeric_limits<uint16_t>::max();
  /** @} */

  /**
    \brief TCP header fields

    If the RST flag is set, only the `seqno` and `ackno` fields are used. All
    the other fields are treated as if they were `false`, and the data is
    treated as if it were empty.

    @{
  */
  uint32_t seqno;
  std::optional<uint32_t> ackno;
  bool syn = false;
  bool fin = false;
  bool rst = false;
  /** @} */

  /**
    \brief The data to send along with the packet

    This data can't be so long as to violate the MTU. We actually set the
    maximum length of the data much lower than the maximum. This is inefficient,
    but it's a good way to ensure that we don't accidentally send too much.
  */
  std::string data{};
  /**
    \brief Maximum length of the `data`
    \details This only applies to packets we send, not received packets
    \see data
  */
  static const size_t MAX_DATA_LENGTH = 256;

  /**
    \brief Serialize this packet into a string of bytes that can be sent
    \return The serialized packet, or nothing if the data is too large
  */
  std::optional<std::string> serialize() const noexcept;

  static std::optional<TCPPacket>
  deserialize(std::string_view data) noexcept;

private:
  /**
    \brief Helper functions for serialization
    \details None of the returned values have their checksums populated
    @{
  */
  std::string serialize_ip_header(size_t data_length) const noexcept;
  std::string serialize_tcp_header(size_t data_length) const noexcept;
  std::string serialize_pseudo_header(size_t data_length) const noexcept;
  /** @} */
};
