#include "yaml-cpp/yaml.h"

#include "tcp-packet.hpp"
#include "topology.hpp"

#include <iostream>
#include <sstream>

namespace {

// Extract a value from a node, handling all the exceptions that might happen
// along the way
template <class T>
T node_as(const std::string &filename, const YAML::Node &node,
          const std::string &node_repr) {
  // Check if the node has a value to begin with
  if (!node.IsDefined())
    throw Topology::ReadError(filename,
                              "could not find node `" + node_repr + "`");
  // Check that the value is a scalar we can work with
  if (!node.IsScalar())
    throw Topology::ReadError(filename,
                              "node `" + node_repr + "` is not a scalar");
  // Try to convert it
  try {
    return node.as<T>();
  } catch (const YAML::TypedBadConversion<T> &e) {
    throw Topology::ReadError(filename,
                              "node `" + node_repr + "` has the wrong type");
  }
}

// Extract an IP address from a node, again handling all the exceptions that
// might happen along the way
TCPPacket::Address::IP node_as_ip(const std::string &filename,
                                  const YAML::Node &node,
                                  const std::string &node_repr) {

  // Get the string representation first
  std::string node_str = node_as<std::string>(filename, node, node_repr);
  std::string_view node_view{node_str};

  // This is the exception to return in case of failure
  Topology::ReadError exc{filename, "node `" + node_repr + "` with `" +
                                        node_str +
                                        "` is not a valid IP address"};

  TCPPacket::Address::IP ret = 0;
  // Parse each of the four octets in turn
  for (size_t i = 0; i < 4; i++) {

    // At the start of this loop, we shouldn't have an empty string. If we do,
    // we ran out of characters and that's a parse error
    if (node_view.empty())
      throw exc;

    // Get a view up to the next dot or the end of the string
    size_t octet_end = node_view.find('.');
    if (octet_end == std::string_view::npos)
      octet_end = node_view.size();
    std::string_view octet_view = node_view.substr(0, octet_end);
    // Move the main view along. Strip off the dot if we found one
    node_view.remove_prefix(octet_end + 1);
    // We shouldn't get an empty view
    if (octet_view.empty())
      throw exc;
    // Assert that the view consists entirely of digits
    if (!std::all_of(octet_view.begin(), octet_view.end(),
                     [](uint8_t c) { return c >= '0' && c <= '9'; }))
      throw exc;

    // Convert the view to a number, and handle any errors
    size_t num_parsed;
    unsigned long octet;
    try {
      octet = std::stoul(std::string{octet_view}, &num_parsed);
    } catch (const std::invalid_argument &e) {
      throw exc;
    } catch (const std::out_of_range &e) {
      throw exc;
    }
    // Assert that we parsed the entire view
    if (num_parsed != octet_view.size())
      std::runtime_error("Failed to parse for an unknown reason");

    // If the number we got doesn't fit in a byte, throw
    if (octet > 255)
      throw exc;
    // Otherwise, shift it in
    ret |= static_cast<TCPPacket::Address::IP>(octet) << (8 * (3 - i));
  }

  return ret;
}

} // namespace

Topology Topology::parse(const std::string &filename) {

  try {

    // Read the file in
    YAML::Node top = YAML::LoadFile(filename);

    // Get the name of the interface to work on
    std::string interface_name =
        node_as<std::string>(filename, top["interface"], "interface");

    return Topology{
        .interface = TCPInterface{interface_name},
        .server_addr =
            {
                .ip = node_as_ip(filename, top["server"]["ip"], "server.ip"),
                .port = node_as<TCPPacket::Address::Port>(
                    filename, top["server"]["port"], "server.port"),
            },
        .router_ip = node_as_ip(filename, top["router"]["ip"], "router.ip"),
        .attacker_ip =
            node_as_ip(filename, top["attacker"]["ip"], "attacker.ip"),
        .server_ttl_drop = node_as<uint8_t>(filename, top["server"]["ttl-drop"],
                                            "server.ttl-drop"),
    };

  } catch (const YAML::BadFile &e) {
    // If the file doesn't exist, ...
    throw ReadError(filename, "failed to open file");

  } catch (const YAML::ParserException &e) {
    // If the file is not valid YAML, ...
    std::stringstream msg_s;
    msg_s << "failed to parse file";
    if (!e.mark.is_null())
      msg_s << " @ (" << e.mark.line + 1 << "," << e.mark.column + 1 << ")";
    msg_s << ": " << e.msg;
    throw ReadError(filename, msg_s.str());
  }

  // If anything else went wrong, ...
  throw std::runtime_error("Failed to parse for an unknown reason");
}
