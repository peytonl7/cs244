#include <unistd.h>

#include "tcp-interface.hpp"
#include "tcp-packet.hpp"

int main(int argc, char **argv) {

  // Create the interface over which we'll be sending packets. By default, this
  // is `tun0`.
  TCPInterface interface;

  interface.send(TCPPacket {
    .src = { .ip = 0x0af40180, .port = 12345 },
    .dst = { .ip = 0x0af40105, .port = 54321 },
    .seqno = 0xdeadbeef,
    .ackno = std::nullopt,
    .syn = true,
    .fin = false,
    .rst = false,
    .data = "Hello, world!"
  });
}
