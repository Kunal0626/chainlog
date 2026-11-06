// cl-crc32 -- CRC-32 of stdin, printed as 8 lowercase hex digits.
// Exists so tests/oracle_crc32.sh can cross-check against python's
// zlib.crc32 on arbitrary input.

#include <cstdio>
#include <vector>

#include "crc32.h"

int main() {
  // CRC-32 is a rolling register, but chainlog::crc32 is one-shot by design
  // (frames are always contiguous in memory when they are checked), so the
  // tool buffers stdin rather than pretending to stream.
  std::vector<unsigned char> all;
  unsigned char buf[65536];
  while (true) {
    const size_t n = std::fread(buf, 1, sizeof(buf), stdin);
    if (n > 0) {
      all.insert(all.end(), buf, buf + n);
    }
    if (n < sizeof(buf)) {
      if (std::ferror(stdin)) {
        std::fprintf(stderr, "cl-crc32: read error on stdin\n");
        return 2;
      }
      break;
    }
  }
  std::printf("%08x\n", chainlog::crc32(all.data(), all.size()));
  return 0;
}
