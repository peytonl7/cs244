#include "tcp-interface.hpp"

#include <cstring>

#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <unistd.h>

#include <asm/types.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

TCPInterface::TCPInterface(const std::string &interface) : fd_(-1) {
  // Initially, the file descriptor is set to an invalid value.

  // Setup and `ifreq` structure for this interface. It's used a lot later, so
  // it's worth merging the common parts.
  struct ifreq ifr_base {};
  std::strncpy(ifr_base.ifr_name, interface.c_str(), IFNAMSIZ);

  // Create a socket and buffer for `netlink` messages. We don't want to miss
  // anything, so we do this first.
  int nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (nl_fd < 0)
    goto cleanup;
  {
    struct sockaddr_nl nl_addr {
      .nl_family = AF_NETLINK, .nl_groups = RTMGRP_LINK,
    };
    if (bind(nl_fd, (struct sockaddr *)&nl_addr, sizeof(nl_addr)) != 0)
      goto cleanup;
  }

  // Open the TUN clone interface
  this->fd_ = open("/dev/net/tun", O_RDWR);
  if (this->fd_ < 0)
    goto cleanup;

  // Set the file we just opened to point to the interface specified
  {
    // See: https://www.kernel.org/doc/Documentation/networking/tuntap.txt
    struct ifreq ifr = ifr_base;
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(this->fd_, TUNSETIFF, (void *)&ifr) < 0)
      goto cleanup;
  }

  // Wait for the interface to actually come up
  {
    // Get the index
    int interface_index = if_nametoindex(interface.c_str());
    if (interface_index == 0)
      goto cleanup;
    // Wait in a loop. This is fine since the `read` is blocking.
    while (true) {
      // Read a packet from the `netlink` interface
      char buf[4096];
      int res = read(nl_fd, buf, sizeof(buf));
      if (res < 0)
        goto cleanup;
      // Reinterpret the buffer as a packet
      struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
      struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
      // Ignore things that aren't for the TUN device
      if (ifi->ifi_index != interface_index)
        continue;
      // Check if the interface is truly up. If it is, we can break out of the
      // loop. It won't go down since we have an open file descriptor to it.
      if (ifi->ifi_flags & IFF_LOWER_UP)
        break;
    }
  }

  return;

  // We `goto` here on failure. Close all the file descriptors we've opened to
  // not leak them.
cleanup:
  if (this->fd_ >= 0)
    close(this->fd_);
  if (nl_fd >= 0)
    close(nl_fd);
  throw TCPInterface::SetupError{interface};
}

TCPInterface::~TCPInterface() noexcept { close(this->fd_); }

bool TCPInterface::send(const TCPPacket &packet) {
  // Serialize the packet. This may fail, so return a boolean to indicate this
  // failure mode.
  std::optional<std::string> serialized = packet.serialize();
  if (!serialized.has_value())
    return false;
  // Send the packet. This should not fail, so throw an exception if it does.
  if (write(this->fd_, serialized->data(), serialized->size()) < 0)
    throw TCPInterface::SendError{};
  // Return successfully
  return true;
}

std::optional<TCPPacket>
TCPInterface::receive(std::function<bool(const TCPPacket &)> filter,
                      std::chrono::milliseconds timeout) {

  // If the timeout is negative, round it up to zero
  if (timeout < std::chrono::milliseconds{0})
    timeout = std::chrono::milliseconds{0};

  // Setup the file descriptor list for `poll`
  struct pollfd poll_fd {
    .fd = this->fd_, .events = POLLIN,
  };

  // Continuously read from the file until we either get a valid TCP packet or
  // the timeout elapses.
  while (true) {
    // If we managed to get here with a negative timeout, it's because we polled
    // once before and were asked to retry. If that happens, just return
    // nothing, as if we had timed out.
    if (timeout < std::chrono::milliseconds{0})
      return std::nullopt;

    // Wait for the file descriptor to be ready. Keep track of how much time
    // elapsed.
    int res;
    std::chrono::steady_clock::duration elapsed;
    {
      auto start = std::chrono::steady_clock::now();
      res = poll(&poll_fd, 1, timeout.count());
      auto end = std::chrono::steady_clock::now();
      elapsed = end - start;
    }
    // Update the timeout with the time elapsed for the next loop. Make sure we
    // always decrease so we don't loop forever.
    timeout -= std::chrono::ceil<std::chrono::milliseconds>(elapsed);
    if (elapsed == std::chrono::steady_clock::duration::zero())
      timeout -= std::chrono::milliseconds{1};

    // If the timeout elapsed, we're done
    if (res == 0)
      return std::nullopt;
    // If it failed, we might be able to try again. Check if it failed with
    // EINTR or EAGAIN.
    if (res < 0) {
      if (errno == EINTR || errno == EAGAIN)
        continue;
      throw TCPInterface::ReceiveError{};
    }

    // If an error happened on the socket, we can't do anything about it
    if (poll_fd.revents & (POLLERR | POLLHUP | POLLNVAL))
      throw TCPInterface::ReceiveError{};
    // If the socket isn't ready to read, keep polling
    if (!(poll_fd.revents & POLLIN))
      continue;

    // Read the packet. Overprovision the buffer to avoid truncation.
    char buf[4096];
    int len = read(this->fd_, buf, sizeof(buf));
    if (len < 0)
      throw TCPInterface::ReceiveError{};

    // Parse the packet. If we don't have anything valid, just retry.
    std::optional<TCPPacket> packet =
        TCPPacket::deserialize(std::string_view{buf, static_cast<size_t>(len)});
    if (!packet.has_value())
      continue;

    // Return the packet if it meets our criteria
    if (filter(packet.value()))
      return packet;
    // Otherwise, keep trying
    continue;
  }
}

struct pollfd TCPInterface::get_fd() {
  struct pollfd poll_fd {
    .fd = this->fd_, .events = POLLIN,
  };
  return poll_fd;
}
