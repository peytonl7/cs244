/**
  \file tcp-raw.hpp
  \brief Provides an interface for sending TCP packets over a TUN device
*/

#pragma once

#include <stdexcept>
#include <string>

class TCPRawInterface {

public:

  /**
    \brief Constructs an interface over which TCP packets can be sent
    \param interface The name of the TUN device to use
  */
  explicit TCPRawInterface(const std::string &interface = "tun0");
  /**
    \brief Closes the interface
  */
  ~TCPRawInterface();

  // Rule of 5: We have a custom destructor, so we should have a custom copy
  // constructor and copy assignment operator. We don't want to allow any
  // copying.
  TCPRawInterface(const TCPRawInterface &) = delete;
  TCPRawInterface &operator=(const TCPRawInterface &) = delete;
  // Rule of 5: Additionally, we should have a custom move constructor and move
  // assignment operator. We don't want to allow any moving either, since that
  // requires keeping us in a valid state, which we can't do.
  TCPRawInterface(TCPRawInterface &&) = delete;
  TCPRawInterface &operator=(TCPRawInterface &&) = delete;

  /**
    \brief Exception thrown when the TUN device cannot be opened
  */
  class SetupError : public std::runtime_error {
  public:
    explicit SetupError(const std::string &interface);
  };

private:
  /**
    \brief File descriptor for the TUN device
  */
  int fd_;
};
