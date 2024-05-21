#include <argparse/argparse.hpp>
#include <iostream>

#include "app.hpp"
#include "tcp-interface.hpp"
#include "topology.hpp"

Configuration Configuration::args(int argc, char **argv) {

  argparse::ArgumentParser parser{"close-stream"};
  parser.add_argument("-t", "--topology")
      .help("Specifies the topology for the attack")
      .metavar("TOPOLOGY")
      .required();
  parser.add_argument("port")
      .help("The port of an active connection for attempted hijacking")
      .metavar("PORT")
      .scan<'d', uint16_t>()
      .required();
  parser.add_argument("-d", "--timeout")
      .help("How long to wait between sending and receiving")
      .metavar("TIMEOUT")
      .scan<'d', size_t>()
      .default_value<size_t>(500);
  parser.add_argument("-e", "--delay")
      .help("How long to wait between sending consecutive packets")
      .metavar("DELAY")
      .scan<'d', size_t>()
      .default_value<size_t>(100);
  parser.add_argument("-r", "--redundancy")
      .help("How many duplicates of each packet to send")
      .metavar("REDUNDANCY")
      .scan<'d', size_t>()
      .default_value<size_t>(2);
  parser.add_argument("-w", "--router-timeout")
      .help("How long to wait before attempting to reset the connection at the router")
      .metavar("ROUTER_TIMEOUT")
      .scan<'d', size_t>()
      .default_value<size_t>(1000);

  try {
    parser.parse_args(argc, argv);
    return Configuration{
        .topology = Topology::parse(parser.get<std::string>("--topology")),
        .port = parser.get<uint16_t>("port"),
        .timeout = std::chrono::milliseconds{parser.get<size_t>("--timeout")},
        .packet_delay =
            std::chrono::milliseconds{parser.get<size_t>("--delay")},
        .packet_redundancy = parser.get<size_t>("--redundancy"),
        .router_timeout = std::chrono::milliseconds{parser.get<size_t>("--router-timeout")},
    };

  } catch (const Topology::ReadError &e) {
    // Something went wrong when reading the topology files
    std::cerr << e.what() << std::endl;
    std::exit(1);

  } catch (const TCPInterface::SetupError &e) {
    // Something went wrong when setting up the interface
    std::cerr << e.what() << std::endl;
    std::exit(1);

  } catch (const std::exception &e) {
    // Something went wrong when parsing arguments
    std::cerr << e.what() << std::endl;
    std::cerr << parser;
    std::exit(1);
  }
}
