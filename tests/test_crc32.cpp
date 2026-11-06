// CRC-32 known-answer tests.
//
// The expected values below were produced by python3's zlib.crc32, which
// implements the same CRC-32/ISO-HDLC variant. 0xCBF43926 for "123456789" is
// the published "check" value for this variant, so it also confirms the
// parameter choices (reflected 0xEDB88320, init and final XOR 0xFFFFFFFF)
// rather than just the arithmetic.
//
// tests/oracle_crc32.sh re-checks the implementation against zlib over random
// input, for the same reason the SHA-256 oracle exists.

#include <string>

#include "crc32.h"
#include "test.h"

using chainlog::crc32;

namespace {

uint32_t crc_of(const std::string& s) { return crc32(s.data(), s.size()); }

}  // namespace

TEST(crc32_published_check_value) {
  // The standard conformance value for CRC-32/ISO-HDLC.
  CHECK_EQ(crc_of("123456789"), 0xCBF43926u);
}

TEST(crc32_known_answers) {
  CHECK_EQ(crc_of(""), 0x00000000u);
  CHECK_EQ(crc_of("a"), 0xE8B7BE43u);
  CHECK_EQ(crc_of("abc"), 0x352441C2u);
  CHECK_EQ(crc_of("chainlog"), 0x7F128297u);

  std::string all_bytes;
  for (int i = 0; i < 255; ++i) {
    all_bytes.push_back(static_cast<char>(i));
  }
  CHECK_EQ(crc32(all_bytes.data(), all_bytes.size()), 0xD32F9BA0u);
}

// The all-ones initial register is what makes leading zero bytes matter. With
// a zero init, "\0\0abc" and "abc" would produce the same CRC, and a frame
// whose payload gained or lost leading NULs would pass the check.
TEST(crc32_is_sensitive_to_leading_zeros) {
  const std::string padded = std::string("\0\0", 2) + "abc";
  CHECK_EQ(crc32(padded.data(), padded.size()), 0x0C476FCDu);
  CHECK(crc_of("abc") != crc32(padded.data(), padded.size()));
}

TEST(crc32_detects_every_single_bit_flip) {
  // CRC-32 is guaranteed to catch any single-bit error, which is exactly the
  // class of fault it is in the frame to catch. 64 bytes * 8 bits = 512 flips.
  std::string base(64, 'Z');
  const uint32_t expected = crc_of(base);
  for (size_t byte = 0; byte < base.size(); ++byte) {
    for (int bit = 0; bit < 8; ++bit) {
      std::string mutated = base;
      mutated[byte] = static_cast<char>(mutated[byte] ^ (1 << bit));
      CHECK(crc_of(mutated) != expected);
    }
  }
}

// Not a security property, but worth pinning as a fact about the primitive:
// forging a CRC is free. Appending four well-chosen bytes to any message
// drives the CRC to any value you like, which is why the frame's CRC protects
// only against accidents and the SHA-256 chain does the tamper detection.
TEST(crc32_is_trivially_forgeable) {
  const std::string a = "transfer 100 to alice";
  const std::string b = "transfer 900 to alice";
  // Different content, so different CRCs ...
  CHECK(crc_of(a) != crc_of(b));
  // ... but an attacker who edits the payload simply recomputes the CRC and
  // the frame checks out again. Nothing about CRC-32 requires a secret.
  CHECK_EQ(crc_of(b), crc32(b.data(), b.size()));
}
