#include <chrono>
#include <iostream>
#include <limits>
#include <optional>
#include <random>
#include <thread>

#include "tcp-interface.hpp"
#include "tcp-packet.hpp"

#include "app.hpp"

namespace {

void send_pkt(Configuration &config, const TCPPacket &packet);

} // namespace

int main(int argc, char **argv) {
  Configuration config = Configuration::args(argc, argv);
  std::default_random_engine rng_engine{std::random_device{}()};
  std::uniform_int_distribution<uint32_t> isn_dist{
      0u, std::numeric_limits<uint32_t>::max()};
  std::uniform_int_distribution<uint16_t> port_dist{
      49152u, std::numeric_limits<uint16_t>::max()};

  TCPPacket::Address attacker_addr{
      .ip = config.topology.attacker_ip,
      .port = port_dist(rng_engine),
  };
  uint32_t attacker_isn = isn_dist(rng_engine);

  send_pkt(config, TCPPacket{
                       .src = attacker_addr,
                       .dst = config.topology.server_addr,
                       .seqno = attacker_isn,
                       .ackno = std::nullopt,
                       .syn = true,
                   });
  std::optional<TCPPacket> syn_ack = config.topology.interface.receive(
      [&attacker_isn](const TCPPacket &pkt) -> bool {
        return !pkt.rst && pkt.syn && pkt.ackno.has_value() &&
               pkt.ackno.value() == attacker_isn + 1;
      },
      config.timeout);
  if (!syn_ack.has_value()) {
    std::cerr << "Failed to receive SYN-ACK packet" << std::endl;
    return 1;
  }

  uint32_t server_isn = syn_ack->seqno;
  send_pkt(config, TCPPacket{
                       .src = attacker_addr,
                       .dst = config.topology.server_addr,
                       .seqno = attacker_isn + 1,
                       .ackno = server_isn + 1,
                   });

  std::cout << "Performed handshake" << std::endl;
  std::cout << "Window size: " << syn_ack->window_size << std::endl;

  send_pkt(config, TCPPacket{.src = attacker_addr,
                             .dst = config.topology.server_addr,
                             .seqno = attacker_isn + 1 + config.seqno_offset,
                             .ackno = server_isn + 1 + config.ackno_offset,
                             .psh = true});
  std::optional<TCPPacket> res = config.topology.interface.receive(
      [&server_isn](const TCPPacket &pkt) -> bool {
        return pkt.seqno == server_isn + 1;
      },
      config.timeout);
  if (res.has_value()) {
    std::cout << "Got response" << std::endl;
    std::cout << "Ackno: " << res->ackno.value() << " / " << attacker_isn
              << std::endl;
    std::cout << "Delta: " << res->ackno.value() - attacker_isn << std::endl;
  } else {
    std::cout << "No response" << std::endl;
  }

  send_pkt(config,
           TCPPacket{
               .src = attacker_addr,
               .dst = config.topology.server_addr,
               .seqno = attacker_isn + (config.seqno_offset == 0 ? 2 : 1),
               .ackno = server_isn + 1,
               .rst = true,
           });
}

namespace {

void send_pkt(Configuration &config, const TCPPacket &packet) {
  for (size_t i = 0; i < config.packet_redundancy; i++) {
    config.topology.interface.send(packet);
    std::this_thread::sleep_for(config.packet_delay);
  }
}

} // namespace
