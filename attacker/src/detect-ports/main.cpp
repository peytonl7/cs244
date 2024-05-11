#include <unistd.h>

#include "tcp-interface.hpp"
#include "tcp-packet.hpp"

int main(int argc, char **argv) {

  // Create the interface over which we'll be sending packets. By default, this
  // is `tun0`.
  TCPInterface interface;
}
