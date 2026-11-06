// cl-sha256 -- hash stdin with ChainLog's hand-written SHA-256 and print the
// digest as hex.
//
// This exists so a shell script can compare our implementation against
// shasum(1) and openssl(1) on arbitrary input. --chunk lets the script drive
// the streaming path with a chosen buffer size, so the block-buffering logic
// is exercised against a real oracle and not just against itself.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "hex.h"
#include "sha256.h"

namespace {

void usage() {
  std::fprintf(stderr,
               "usage: cl-sha256 [--chunk N] < input\n"
               "  --chunk N   read stdin N bytes at a time (default 65536)\n");
}

}  // namespace

int main(int argc, char** argv) {
  size_t chunk = 65536;

  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--chunk") == 0 && i + 1 < argc) {
      const long n = std::strtol(argv[++i], nullptr, 10);
      if (n <= 0) {
        std::fprintf(stderr, "cl-sha256: --chunk must be positive\n");
        return 2;
      }
      chunk = static_cast<size_t>(n);
    } else {
      usage();
      return 2;
    }
  }

  chainlog::Sha256 h;
  std::vector<char> buf(chunk);
  while (true) {
    const size_t n = std::fread(buf.data(), 1, buf.size(), stdin);
    if (n > 0) {
      h.update(buf.data(), n);
    }
    if (n < buf.size()) {
      // Short read: either EOF or an error. Distinguish them, because
      // silently hashing a truncated stream and printing a confident digest
      // is exactly the kind of lie this project exists to prevent.
      if (std::ferror(stdin)) {
        std::fprintf(stderr, "cl-sha256: read error on stdin\n");
        return 2;
      }
      break;
    }
  }

  std::printf("%s\n", chainlog::to_hex(h.finish()).c_str());
  return 0;
}
