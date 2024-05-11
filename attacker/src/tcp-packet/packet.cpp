#include "tcp-packet.hpp"

// Compute the checksum of some data, as is required by IP and TCP
uint16_t cksum(const std::string &data) {
  // Sum over all the pairs of bytes in the data. If the last byte is not part
  // of a pair, pad with zero.
  uint32_t sum = 0;
  for (size_t i = 0; i < data.size(); i += 2) {
    // Avoid sign extension
    uint8_t msb = data[i];
    uint8_t lsb = i + 1 < data.size() ? data[i + 1] : 0;
    sum += msb << 8 | lsb;
  }
  // Fold the sum into a 16-bit number
  while ((sum >> 16) != 0)
    sum = (sum & 0xffff) + (sum >> 16);
  // Done
  return ~sum;
}

// Write an unsigned integer to a string's iterator, in big-endian order. This
// very specific function is used to write integers into IP and TCP headers.
template <class V> static void wr_u(std::string::iterator it, V val) {
  for (size_t i = 0; i < sizeof(V); i++)
    *it++ = (val >> (8 * (sizeof(V) - 1 - i))) & 0xff;
}

std::optional<std::string> TCPPacket::serialize() const noexcept {

  // Figure out if we should include the data. We don't if we're sending a RST
  const std::string &data = rst ? std::string{} : this->data;
  // Check if the data we're about to send is too long
  if (data.size() > MAX_DATA_LENGTH)
    return std::nullopt;

  // Get all the headers
  std::string ip_header = this->serialize_ip_header(data.size());
  std::string tcp_header = this->serialize_tcp_header(data.size());
  std::string pseudo_header = this->serialize_pseudo_header(data.size());

  // Compute checksums
  uint16_t ip_cksum = cksum(ip_header);
  uint16_t tcp_cksum = cksum(pseudo_header + tcp_header + data);

  // Put the checksums in the headers
  wr_u<uint16_t>(ip_header.begin() + 10, ip_cksum);
  wr_u<uint16_t>(tcp_header.begin() + 16, tcp_cksum);

  return ip_header + tcp_header + data;
}

std::string TCPPacket::serialize_ip_header(size_t data_length) const noexcept {

  std::string ret(20, 0);

  // Version, IHL, DSCP, and ECN
  ret[0] = 0x45;
  ret[1] = 0x00;
  // Total length
  wr_u<uint16_t>(ret.begin() + 2, 20 + 20 + data_length);
  // Identification and fragmentation
  std::fill(ret.begin() + 4, ret.begin() + 6, 0x00);
  ret[6] = 0x40;
  ret[7] = 0x00;
  // TTL
  ret[8] = this->ttl;
  // Type
  ret[9] = 0x06;
  // Checksum
  std::fill(ret.begin() + 10, ret.begin() + 12, 0x00);
  // Source and destination addresses
  wr_u<uint32_t>(ret.begin() + 12, this->src.ip);
  wr_u<uint32_t>(ret.begin() + 16, this->dst.ip);

  return ret;
}

std::string TCPPacket::serialize_tcp_header(size_t data_length) const noexcept {

  std::string ret(20, 0);

  // Source and destination ports
  wr_u<uint16_t>(ret.begin() + 0, this->src.port);
  wr_u<uint16_t>(ret.begin() + 2, this->dst.port);
  // Sequence number
  wr_u<uint32_t>(ret.begin() + 4, this->seqno);
  // Acknowlegement number
  if (!this->rst and this->ackno.has_value())
    wr_u<uint32_t>(ret.begin() + 8, this->ackno.value());
  // Data offset
  ret[12] = 0x50;
  // Flags
  ret[13] = 0x00;
  if (this->ackno.has_value())
    ret[13] |= 0x10;
  if (this->rst) {
    ret[13] |= 0x04;
  } else {
    if (this->syn)
      ret[13] |= 0x02;
    if (this->fin)
      ret[13] |= 0x01;
  }
  // Window size
  wr_u<uint16_t>(ret.begin() + 14, this->window_size);
  // Checksum
  std::fill(ret.begin() + 16, ret.begin() + 18, 0x00);
  // Urgent pointer
  std::fill(ret.begin() + 18, ret.begin() + 20, 0x00);

  return ret;
}

std::string TCPPacket::serialize_pseudo_header(size_t data_length) const noexcept {

  std::string ret(12, 0);

  // Source and destination addresses
  wr_u<uint32_t>(ret.begin() + 0, this->src.ip);
  wr_u<uint32_t>(ret.begin() + 4, this->dst.ip);
  // Reserved
  ret[8] = 0x00;
  // Protocol
  ret[9] = 0x06;
  // Length
  wr_u<uint16_t>(ret.begin() + 10, 20 + data_length);

  return ret;
}
