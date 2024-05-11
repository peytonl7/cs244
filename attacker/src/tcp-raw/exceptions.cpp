#include "tcp-raw.hpp"

TCPRawInterface::SetupError::SetupError(const std::string &interface)
    : std::runtime_error("Failed to open TUN device: " + interface) {}
