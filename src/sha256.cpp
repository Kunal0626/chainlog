#include "sha256.h"

#include <cassert>
#include <cstring>

namespace chainlog {
namespace {

// Round constants: the first 32 bits of the fractional parts of the cube roots
// of the first 64 primes (FIPS 180-4, section 4.2.2). They are "nothing up my
// sleeve" numbers -- derived from a public formula so that nobody can claim a
// backdoor was hidden in them.
const uint32_t kK[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

// Initial hash state: the first 32 bits of the fractional parts of the square
// roots of the first 8 primes (FIPS 180-4, section 5.3.3).
const uint32_t kH0[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                         0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

// Rotate right. Written as two shifts rather than using a rotate intrinsic so
// the code stays portable; clang recognises the pattern and emits `ror`.
// n is always in 1..31 here, so the `32 - n` shift is never undefined.
inline uint32_t rotr(uint32_t x, unsigned n) {
  return (x >> n) | (x << (32u - n));
}

// SHA-256 is defined on big-endian 32-bit words. The byte order below is fixed
// by the standard, so it must NOT follow the host's endianness -- doing these
// loads by memcpy-ing a uint32_t would give different digests on a big-endian
// machine. Shifting byte by byte is endian-independent by construction.
inline uint32_t load_be32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

inline void store_be32(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v >> 24);
  p[1] = static_cast<uint8_t>(v >> 16);
  p[2] = static_cast<uint8_t>(v >> 8);
  p[3] = static_cast<uint8_t>(v);
}

inline void store_be64(uint8_t* p, uint64_t v) {
  store_be32(p, static_cast<uint32_t>(v >> 32));
  store_be32(p + 4, static_cast<uint32_t>(v));
}

}  // namespace

Sha256::Sha256() { reset(); }

void Sha256::reset() {
  std::memcpy(h_, kH0, sizeof(h_));
  std::memset(buf_, 0, sizeof(buf_));
  buf_len_ = 0;
  total_len_ = 0;
  finished_ = false;
}

void Sha256::compress(const uint8_t block[kBlockSize]) {
  // Message schedule: the 16 input words, extended to 64. The extension is
  // what makes every output bit depend on every input bit of the block.
  uint32_t w[64];
  for (size_t i = 0; i < 16; ++i) {
    w[i] = load_be32(block + 4 * i);
  }
  for (size_t i = 16; i < 64; ++i) {
    const uint32_t s0 =
        rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const uint32_t s1 =
        rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    // Unsigned wraparound is intended and well-defined; this is modular
    // addition over 2^32, not an overflow bug.
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
  uint32_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];

  for (size_t i = 0; i < 64; ++i) {
    const uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const uint32_t ch = (e & f) ^ (~e & g);
    const uint32_t t1 = h + S1 + ch + kK[i] + w[i];
    const uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const uint32_t t2 = S0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  // Davies-Meyer feed-forward: adding the input state back in is what makes
  // the compression function one-way. Without it the 64 rounds are an
  // invertible permutation and the whole hash could be run backwards.
  h_[0] += a;
  h_[1] += b;
  h_[2] += c;
  h_[3] += d;
  h_[4] += e;
  h_[5] += f;
  h_[6] += g;
  h_[7] += h;
}

void Sha256::update(const void* data, size_t len) {
  assert(!finished_ && "Sha256::update() after finish(); call reset() first");
  if (len == 0) {
    return;  // Also keeps a null pointer out of memcpy, which would be UB.
  }

  const uint8_t* p = static_cast<const uint8_t*>(data);
  total_len_ += len;

  // Top up a partially filled block before touching the fast path, so that a
  // caller feeding odd-sized chunks gets the same digest as one big update().
  if (buf_len_ > 0) {
    size_t take = kBlockSize - buf_len_;
    if (take > len) {
      take = len;
    }
    std::memcpy(buf_ + buf_len_, p, take);
    buf_len_ += take;
    p += take;
    len -= take;
    if (buf_len_ == kBlockSize) {
      compress(buf_);
      buf_len_ = 0;
    }
  }

  // Compress whole blocks straight out of the caller's buffer: no copy.
  while (len >= kBlockSize) {
    compress(p);
    p += kBlockSize;
    len -= kBlockSize;
  }

  // Stash the remainder for next time.
  if (len > 0) {
    std::memcpy(buf_, p, len);
    buf_len_ = len;
  }
}

Digest Sha256::finish() {
  assert(!finished_ && "Sha256::finish() called twice; call reset() first");

  // Padding (FIPS 180-4, section 5.1.1): one 0x80 byte, then zeros, then the
  // message length in BITS as a 64-bit big-endian integer, arranged so the
  // total is a multiple of 64 bytes.
  //
  // Two things this buys us. The 0x80 makes the padding unambiguous -- without
  // a marker byte, "abc" and "abc\0" would pad to the same block. The trailing
  // length makes the padding injective over lengths too, which is what stops
  // length-extension-style ambiguity inside a single digest.
  //
  // Because the length needs the last 8 bytes and the marker needs 1, padding
  // needs 9 spare bytes. So a message with 55 bytes in the final block fits in
  // one block, and 56 does not -- it spills into a second, all-padding block.
  // That boundary is why the tests hammer lengths 55/56/57 and 119/120/121.
  const uint64_t bit_len = total_len_ * 8;

  uint8_t pad[2 * kBlockSize];
  std::memset(pad, 0, sizeof(pad));
  pad[0] = 0x80;
  const size_t zeros_and_marker =
      (buf_len_ < 56) ? (56 - buf_len_) : (56 + kBlockSize - buf_len_);
  store_be64(pad + zeros_and_marker, bit_len);

  // Feeding the padding through update() keeps the block-splitting logic in
  // one place. total_len_ becomes meaningless afterwards, which is fine: the
  // object is spent until reset().
  update(pad, zeros_and_marker + 8);
  assert(buf_len_ == 0 && "padding must land exactly on a block boundary");

  Digest out;
  for (size_t i = 0; i < 8; ++i) {
    store_be32(out.data() + 4 * i, h_[i]);
  }
  finished_ = true;
  return out;
}

Digest Sha256::hash(const void* data, size_t len) {
  Sha256 s;
  s.update(data, len);
  return s.finish();
}

Digest Sha256::hash(const std::string& str) {
  return hash(str.data(), str.size());
}

}  // namespace chainlog
