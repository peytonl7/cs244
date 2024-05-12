/**
  \file tcp-interface.hpp
  \brief Provides an interface for sending TCP packets over a TUN device
*/

#pragma once

#include <chrono>
#include <stdexcept>
#include <string>

#include "tcp-packet.hpp"

class TCPInterface {

public:
  /**
    \brief Constructs an interface over which TCP packets can be sent
    \param interface The name of the TUN device to use
    \throws SetupError If the TUN device cannot be opened
  */
  explicit TCPInterface(const std::string &interface = "tun0");
  /**
    \brief Closes the interface
  */
  ~TCPInterface() noexcept;

  // Rule of 5: We have a custom destructor, so we should have a custom copy
  // constructor and copy assignment operator. We don't want to allow any
  // copying.
  TCPInterface(const TCPInterface &) = delete;
  TCPInterface &operator=(const TCPInterface &) = delete;
  // Rule of 5: Additionally, we should have a custom move constructor and move
  // assignment operator. We don't want to allow any moving either, since that
  // requires keeping us in a valid state, which we can't do.
  TCPInterface(TCPInterface &&) = delete;
  TCPInterface &operator=(TCPInterface &&) = delete;

  /**
    \brief Send a TCP packet over this interface
    \return Whether the packet could be serialized and thus sent
    \throws SendError If the packet could not be sent
  */
  bool send(const TCPPacket &packet);

  /**
    \brief Try to receive a TCP packet from this interface
    \details The timeout must be specified - there's no way to delay forever
    \return The packet, or `std::nullopt` if the timeout elapsed
    \throws ReceiveError If the packet could not be received
  */
  std::optional<TCPPacket> receive(std::chrono::milliseconds timeout);

  /**
    \brief Exception thrown when the TUN device cannot be opened
  */
  class SetupError : public std::runtime_error {
  public:
    explicit SetupError(const std::string &interface) noexcept
        : std::runtime_error("Failed to open TUN device: " + interface){};
  };
  /**
    \brief Exception thrown on send failure
  */
  class SendError : public std::runtime_error {
  public:
    explicit SendError() noexcept
        : std::runtime_error("Failed to send on TUN device") {}
  };

  /**
    \brief Exception thrown on receive failure
  */
  class ReceiveError : public std::runtime_error {
  public:
    explicit ReceiveError() noexcept
        : std::runtime_error("Failed to receive on TUN device") {}
  };

private:
  /**
    \brief File descriptor for the TUN device
  */
  int fd_;
};
