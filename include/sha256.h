// SHA-256, implemented by hand against FIPS 180-4.
//
// This is the one piece of cryptography in ChainLog that must not come from a
// library: the whole project is an exercise in knowing exactly what bytes get
// hashed and why. OpenSSL and shasum(1) appear only in tests, as oracles.
#ifndef CHAINLOG_SHA256_H
#define CHAINLOG_SHA256_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace chainlog {

// A 32-byte SHA-256 digest. A fixed-size array (not a vector) so that record
// and Merkle code can hold digests by value with no allocation.
using Digest = std::array<uint8_t, 32>;

// Streaming SHA-256.
//
// Usage: construct, call update() any number of times, call finish() once.
// Call reset() before reusing the object. The streaming form matters here
// because records carry arbitrary-length data and the Merkle code hashes
// short fixed prefixes followed by digests; neither should have to build a
// contiguous buffer just to hash it.
class Sha256 {
 public:
  // constexpr (not const) so these are implicitly inline in C++17 and need
  // no separate out-of-class definition when taken by reference.
  static constexpr size_t kBlockSize = 64;   // 512-bit compression block
  static constexpr size_t kDigestSize = 32;  // 256-bit output

  Sha256();

  // Returns the object to its initial state so it can hash a new message.
  void reset();

  // Feeds len bytes. Safe to call with len == 0.
  void update(const void* data, size_t len);

  // Appends the padding, runs the final block(s) and returns the digest.
  // Must be called at most once per message; reset() first to reuse.
  Digest finish();

  // One-shot convenience wrappers.
  static Digest hash(const void* data, size_t len);
  static Digest hash(const std::string& s);

 private:
  // Runs the 64-round compression function over one 64-byte block, folding
  // the result into h_.
  void compress(const uint8_t block[kBlockSize]);

  uint32_t h_[8];       // running hash state, 8 big-endian words
  uint8_t buf_[kBlockSize];  // partial block not yet compressed
  size_t buf_len_;      // bytes currently held in buf_ (always < kBlockSize)
  uint64_t total_len_;  // total message bytes seen, for the length padding
  bool finished_;       // guards against update()/finish() after finish()
};

}  // namespace chainlog

#endif  // CHAINLOG_SHA256_H
