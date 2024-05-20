#include "tcp-packet.hpp"

namespace {

// Perform the folding step required by checksum computation.
uint16_t fold(uint32_t sum) {
  while ((sum >> 16) != 0)
    sum = (sum & 0xffff) + (sum >> 16);
  return sum;
}

// Compute the checksum of some data, as is required by IP and TCP. This doesn't
// bitwise-NOT the result, so the caller should post-process.
uint16_t cksum_neg(std::string_view data) {
  // Sum over all the pairs of bytes in the data. If the last byte is not part
  // of a pair, pad with zero.
  uint32_t sum = 0;
  for (size_t i = 0; i < data.size(); i += 2) {
    // Avoid sign extension
    uint8_t msb = data[i];
    uint8_t lsb = i + 1 < data.size() ? data[i + 1] : 0;
    sum += msb << 8 | lsb;
  }
  // Fold and return. Don't bitwise-NOT
  return fold(sum);
}

// Compute the checksum of some data, as is required by IP and TCP. This one
// does the bitwise-NOT, so the caller doesn't have to.
uint16_t cksum(std::string_view data) { return ~cksum_neg(data); }

// Write an unsigned integer to an iterator, in big-endian order. This very
// specific function is used to write integers into IP and TCP headers.
template <class V, class It> void wr_u(It it, V val) {
  for (size_t i = 0; i < sizeof(V); i++)
    *it++ = (val >> (8 * (sizeof(V) - 1 - i))) & 0xff;
}

// Read an unsigned integer from an iterator, in big-endian order. This very
// specific function is used to read integers from IP and TCP headers.
template <class V, class It> V rd_u(It it) {
  V ret = 0;
  for (size_t i = 0; i < sizeof(V); i++) {
    // Make sure this doesn't sign extend
    uint8_t v_u8 = *it++;
    V v_v = static_cast<V>(v_u8);
    ret |= v_v << (8 * (sizeof(V) - 1 - i));
  }
  return ret;
}

}; // namespace

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
  uint16_t tcp_cksum;
  {
    uint32_t c0 = cksum_neg(pseudo_header);
    uint32_t c1 = cksum_neg(tcp_header);
    uint32_t c2 = cksum_neg(data);
    tcp_cksum = ~fold(c0 + c1 + c2);
  }

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

std::string
TCPPacket::serialize_pseudo_header(size_t data_length) const noexcept {

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

std::optional<TCPPacket>
TCPPacket::deserialize(std::string_view data) noexcept {

  // We should have at least enough data for at least the IP header
  if (data.size() < 20)
    return std::nullopt;
  // Run the checksum on the IP header
  if (cksum(data.substr(0, 20)) != 0)
    return std::nullopt;
  // Check that the length is correct - i.e. that we got everything
  if (rd_u<uint16_t>(data.begin() + 2) != data.size())
    return std::nullopt;
  // Check that the protocol is TCP. If not, drop it.
  if (data[9] != 0x06)
    return std::nullopt;

  // Get a pointer to the TCP data. The offset might not be 20 if the sender has
  // options. Also, check we have enough room in the remaining data for a TCP
  // header.
  size_t tcp_offset = ((data[0] >> 0) & 0x0f) * 4;
  std::string_view tcp_data = data.substr(tcp_offset);
  if (tcp_data.size() < 20)
    return std::nullopt;
  // Construct the pseudo-header from the IP header
  std::string pseudo_header = std::string(12, 0);
  std::copy(data.begin() + 12, data.begin() + 20, pseudo_header.begin());
  pseudo_header[8] = 0x00;
  pseudo_header[9] = 0x06;
  wr_u<uint16_t>(pseudo_header.begin() + 10, data.size() - 20);

  // Compute the checksum for TCP and check it matches
  {
    uint32_t c0 = cksum_neg(pseudo_header);
    uint32_t c1 = cksum_neg(tcp_data);
    if (~fold(c0 + c1) & 0xffff)
      return std::nullopt;
  }
  // Get the offset to the actual data from the start of the TCP data. Again,
  // the sender might have put options, so the offset might not be 20.
  size_t payload_offset = ((tcp_data[12] >> 4) & 0x0f) * 4;
  std::string_view payload_data = tcp_data.substr(payload_offset);
  // Make sure that the payload offset doesn't point outside of the TCP data. If
  // it does, the packet is invalid.
  if (payload_offset > tcp_data.size())
    return std::nullopt;

  return TCPPacket{.src = Address{.ip = rd_u<uint32_t>(data.begin() + 12),
                                  .port = rd_u<uint16_t>(tcp_data.begin() + 0)},
                   .dst = Address{.ip = rd_u<uint32_t>(data.begin() + 16),
                                  .port = rd_u<uint16_t>(tcp_data.begin() + 2)},
                   .ttl = static_cast<uint8_t>(data[8]),
                   .window_size = rd_u<uint16_t>(tcp_data.begin() + 14),
                   .seqno = rd_u<uint32_t>(tcp_data.begin() + 4),
                   .ackno = (tcp_data[13] & 0x10)
                                ? std::optional<uint32_t>{rd_u<uint32_t>(
                                      tcp_data.begin() + 8)}
                                : std::nullopt,
                   .syn = (tcp_data[13] & 0x02) != 0,
                   .fin = (tcp_data[13] & 0x01) != 0,
                   .rst = (tcp_data[13] & 0x04) != 0,
                   .data = std::string{payload_data}};
}

bool TCPPacket::operator==(const TCPPacket &that) const noexcept {
  return this->src == that.src and this->dst == that.dst and
         this->window_size == that.window_size and
         this->seqno == that.seqno and this->ackno == that.ackno and
         this->syn == that.syn and this->fin == that.fin and
         this->rst == that.rst and this->data == that.data;
}
