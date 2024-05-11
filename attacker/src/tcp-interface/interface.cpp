#include "tcp-interface.hpp"

#include <cstring>

#include <fcntl.h>
#include <net/if.h>
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
  struct ifreq ifr_base;
  std::memset(&ifr_base, 0, sizeof(ifr_base));
  std::strncpy(ifr_base.ifr_name, interface.c_str(), IFNAMSIZ);

  // Create a socket and buffer for `netlink` messages. We don't want to miss
  // anything, so we do this first. Create the auxiliary structrures before the
  // socket because we can't have declarations between `goto`s.
  char nl_buf[4096];
  struct sockaddr_nl nl_addr = {
    .nl_family = AF_NETLINK,
    .nl_groups = RTMGRP_LINK,
  };
  int nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (nl_fd < 0)
    goto cleanup;
  // Try to bind the socket
  if (bind(nl_fd, (struct sockaddr *)&nl_addr, sizeof(nl_addr)) != 0)
    goto cleanup;

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
      int res = read(nl_fd, nl_buf, sizeof(nl_buf));
      if (res < 0)
        goto cleanup;
      // Reinterpret the buffer as a packet
      struct nlmsghdr *nlh = (struct nlmsghdr *)nl_buf;
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
  throw TCPInterface::SetupError {interface};
}

TCPInterface::~TCPInterface() {
  close(this->fd_);
}
