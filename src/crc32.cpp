#include "crc32.h"

namespace chainlog {
namespace {

// Reflected form of the CRC-32 polynomial x^32 + x^26 + ... + x + 1
// (0x04C11DB7 written most-significant-bit-first).
const uint32_t kPoly = 0xEDB88320u;

// Byte-at-a-time lookup table. Wrapped in a type with a constructor so the
// function-local static below is initialised exactly once, thread-safely,
// under C++11's magic-static rule -- a bare `static bool init` flag would be
// a data race the first time two threads hashed concurrently.
struct Table {
  uint32_t v[256];

  Table() {
    for (uint32_t i = 0; i < 256; ++i) {
      uint32_t c = i;
      for (int bit = 0; bit < 8; ++bit) {
        // Reflected algorithm: shift right and conditionally xor the
        // polynomial, which is the mirror image of the textbook
        // shift-left-and-xor form.
        c = (c & 1u) ? (kPoly ^ (c >> 1)) : (c >> 1);
      }
      v[i] = c;
    }
  }
};

const Table& table() {
  static const Table instance;
  return instance;
}

}  // namespace

uint32_t crc32(const void* data, size_t len) {
  const uint8_t* p = static_cast<const uint8_t*>(data);
  const Table& t = table();

  // The all-ones initial value is what makes leading zero bytes change the
  // result; with a zero register, "\0\0abc" and "abc" would collide.
  uint32_t c = 0xFFFFFFFFu;
  for (size_t i = 0; i < len; ++i) {
    c = t.v[(c ^ p[i]) & 0xFFu] ^ (c >> 8);
  }
  return c ^ 0xFFFFFFFFu;
}

}  // namespace chainlog
