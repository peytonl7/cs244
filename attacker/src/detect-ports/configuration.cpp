#include <argparse/argparse.hpp>
#include <iostream>

#include "app.hpp"
#include "tcp-interface.hpp"
#include "topology.hpp"

Configuration Configuration::args(int argc, char **argv) {

  // Topology to be populated when the argument is encountered
  Topology top;

  argparse::ArgumentParser parser{"detect-ports"};
  parser.add_argument("-t", "--topology")
    .help("Specifies the topology for the attack")
    .metavar("TOPOLOGY")
    .required()
    .action([&top](const std::string &filename) {
      top = Topology::parse(filename);
    });
  parser.add_argument("start")
    .help("The start of the range to probe (inclusive)")
    .metavar("START")
    .scan<'d', uint16_t>()
    .required();
  parser.add_argument("end")
    .help("The end of the range to probe (inclusive)")
    .metavar("END")
    .scan<'d', uint16_t>()
    .required();
  parser.add_argument("-i", "--interface")
    .help("The TUN device to work with")
    .metavar("TUN")
    .default_value(std::string("tun0"));
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
  parser.add_argument("--dumb-terminal")
    .help("Don't use control codes")
    .default_value(false)
    .implicit_value(true);

  try {
    parser.parse_args(argc, argv);
    return Configuration{
      .interface = TCPInterface{parser.get<std::string>("--interface")},
      .topology = top,
      .scan_port_range = {
        .start = parser.get<uint16_t>("start"),
        .end = parser.get<uint16_t>("end"),
      },
      .timeout = std::chrono::milliseconds{parser.get<size_t>("--timeout")},
      .packet_delay = std::chrono::milliseconds{parser.get<size_t>("--delay")},
      .packet_redundancy = parser.get<size_t>("--redundancy"),
      .dumb_terminal = parser.get<bool>("--dumb-terminal"),
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
