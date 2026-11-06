// Known-answer and self-consistency tests for the hand-written SHA-256.
//
// Two layers on purpose:
//
//   * The NIST vectors below pin absolute correctness at a handful of inputs.
//     They are the published FIPS 180-4 / NIST examples, so they are the same
//     numbers every other implementation is checked against.
//
//   * The streaming tests pin internal consistency: feeding the same bytes in
//     different chunk sizes must give the same digest. This is where the
//     block-buffering logic in update() actually gets exercised.
//
// Absolute correctness across *many* lengths is checked by
// tests/oracle_sha256.sh against shasum(1) and openssl(1), rather than by
// hardcoding dozens of digests here -- a digest typed in from memory is a
// test that can be confidently wrong.

#include <string>
#include <vector>

#include "hex.h"
#include "sha256.h"
#include "test.h"

using chainlog::Digest;
using chainlog::Sha256;
using chainlog::to_hex;

namespace {

// Hashes `msg` by feeding it `chunk` bytes at a time through the streaming API.
std::string hex_streamed(const std::string& msg, size_t chunk) {
  Sha256 h;
  size_t off = 0;
  while (off < msg.size()) {
    size_t n = msg.size() - off;
    if (n > chunk) {
      n = chunk;
    }
    h.update(msg.data() + off, n);
    off += n;
  }
  return to_hex(h.finish());
}

std::string hex_oneshot(const std::string& msg) {
  return to_hex(Sha256::hash(msg));
}

}  // namespace

// --- NIST known-answer vectors ---------------------------------------------

TEST(nist_empty_string) {
  CHECK_EQ(hex_oneshot(""),
           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(nist_abc) {
  CHECK_EQ(hex_oneshot("abc"),
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

// 56 bytes = 448 bits. One byte short of the padding boundary, so this is the
// largest message that still fits in a single compression block.
TEST(nist_448_bits) {
  const std::string msg =
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  CHECK_EQ(msg.size(), static_cast<size_t>(56));
  CHECK_EQ(hex_oneshot(msg),
           "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

// 112 bytes = 896 bits.
TEST(nist_896_bits) {
  const std::string msg =
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
      "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  CHECK_EQ(msg.size(), static_cast<size_t>(112));
  CHECK_EQ(hex_oneshot(msg),
           "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
}

// One million 'a'. Exercises the multi-block path and, with total_len_ * 8 =
// 8,000,000 bits, a length field that no longer fits in 24 bits.
TEST(nist_one_million_a) {
  const std::string msg(1000000, 'a');
  CHECK_EQ(hex_oneshot(msg),
           "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

// Same vector, but pushed through the streaming API in awkward chunks. If the
// buffering in update() is wrong, this fails while the one-shot test passes.
TEST(one_million_a_streamed_in_odd_chunks) {
  const std::string msg(1000000, 'a');
  const char* expected =
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
  CHECK_EQ(hex_streamed(msg, 1), expected);
  CHECK_EQ(hex_streamed(msg, 63), expected);
  CHECK_EQ(hex_streamed(msg, 64), expected);
  CHECK_EQ(hex_streamed(msg, 65), expected);
  CHECK_EQ(hex_streamed(msg, 999), expected);
}

// --- streaming / buffering consistency -------------------------------------

TEST(streaming_matches_one_shot_for_every_chunk_size) {
  // 200 bytes of varied content, long enough to span three blocks.
  std::string msg;
  for (size_t i = 0; i < 200; ++i) {
    msg.push_back(static_cast<char>('A' + (i * 7) % 26));
  }
  const std::string expected = hex_oneshot(msg);
  for (size_t chunk = 1; chunk <= 70; ++chunk) {
    CHECK_EQ(hex_streamed(msg, chunk), expected);
  }
}

// The padding needs 9 spare bytes (one 0x80 marker plus an 8-byte bit length),
// so a final block with 55 bytes fits and 56 does not. These are the lengths
// where an off-by-one in finish() shows up.
TEST(padding_boundaries_are_chunk_independent) {
  const size_t lengths[] = {0,  1,   54,  55,  56,  57,  63,  64,
                            65, 119, 120, 121, 127, 128, 129};
  for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
    const std::string msg(lengths[i], 'x');
    const std::string expected = hex_oneshot(msg);
    CHECK_EQ(hex_streamed(msg, 1), expected);
    CHECK_EQ(hex_streamed(msg, 7), expected);
    CHECK_EQ(hex_streamed(msg, 56), expected);
    CHECK_EQ(hex_streamed(msg, 64), expected);
    // Length must be baked into the digest: same bytes, one more, must differ.
    const std::string longer(lengths[i] + 1, 'x');
    CHECK(hex_oneshot(longer) != expected);
  }
}

TEST(zero_length_update_is_a_no_op) {
  Sha256 a;
  a.update(nullptr, 0);
  a.update("abc", 3);
  a.update(nullptr, 0);
  CHECK_EQ(to_hex(a.finish()), hex_oneshot("abc"));
}

// --- object lifecycle -------------------------------------------------------

TEST(reset_allows_reuse) {
  Sha256 h;
  h.update("abc", 3);
  const Digest first = h.finish();

  h.reset();
  h.update("abc", 3);
  const Digest second = h.finish();
  CHECK_EQ(to_hex(first), to_hex(second));

  h.reset();
  h.update("", 0);
  CHECK_EQ(to_hex(h.finish()),
           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(instances_are_independent) {
  Sha256 a;
  Sha256 b;
  a.update("abc", 3);
  b.update("xyz", 3);
  a.update("def", 3);
  CHECK_EQ(to_hex(a.finish()), hex_oneshot("abcdef"));
  CHECK_EQ(to_hex(b.finish()), hex_oneshot("xyz"));
}

// --- hex encoding -----------------------------------------------------------

TEST(to_hex_is_lowercase_and_zero_padded) {
  const unsigned char bytes[] = {0x00, 0x01, 0x0f, 0x10, 0xab, 0xff};
  CHECK_EQ(to_hex(bytes, sizeof(bytes)), "00010f10abff");
  CHECK_EQ(to_hex(bytes, 0), "");
  CHECK_EQ(to_hex(Sha256::hash("")).size(), static_cast<size_t>(64));
}
