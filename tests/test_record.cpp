// Record format tests: the hashed preimage, the on-disk frame, the header.

#include <cstring>
#include <string>

#include "crc32.h"
#include "hex.h"
#include "record.h"
#include "sha256.h"
#include "test.h"

using chainlog::Digest;
using chainlog::Header;
using chainlog::Problem;
using chainlog::Record;
using chainlog::Sha256;
using chainlog::to_hex;

namespace {

// Compare problems by their stable kebab-case name, so a failure prints
// "bad-crc" instead of an opaque integer.
std::string pname(Problem p) { return chainlog::problem_name(p); }

Digest digest_of_byte(uint8_t b) {
  Digest d{};
  d.fill(b);
  return d;
}

Record sample(const std::string& data) {
  Record r;
  r.index = 7;
  r.timestamp_ns = 0x0123456789ABCDEFull;
  r.data = data;
  r.prev_hash = digest_of_byte(0xAB);
  r.hash = chainlog::compute_record_hash(r);
  return r;
}

}  // namespace

// --- the hashed preimage ---------------------------------------------------

TEST(preimage_layout_is_exactly_as_documented) {
  Record r = sample("hi");
  std::string pre;
  chainlog::append_preimage(r, &pre);

  // index(8) + timestamp(8) + data_len(8) + data + prev_hash(32)
  CHECK_EQ(pre.size(), chainlog::kPreimageFixedBytes + r.data.size());

  const uint8_t* p = reinterpret_cast<const uint8_t*>(pre.data());
  CHECK_EQ(chainlog::get_u64_le(p), 7ull);
  CHECK_EQ(chainlog::get_u64_le(p + 8), 0x0123456789ABCDEFull);
  CHECK_EQ(chainlog::get_u64_le(p + 16), 2ull);
  CHECK_EQ(std::string(pre, 24, 2), "hi");
  CHECK_EQ(to_hex(p + 26, 32), to_hex(digest_of_byte(0xAB)));
}

TEST(integers_are_little_endian_regardless_of_host) {
  // Pinned explicitly: if someone "optimised" these into a memcpy of a
  // uint64_t, this test would still pass on arm64 and silently change every
  // hash on a big-endian machine. The point is that the expected bytes are
  // written out by hand here, not derived from the same helper under test.
  uint8_t b[8];
  chainlog::put_u64_le(b, 0x0102030405060708ull);
  CHECK_EQ(to_hex(b, 8), "0807060504030201");

  uint8_t c[4];
  chainlog::put_u32_le(c, 0x11223344u);
  CHECK_EQ(to_hex(c, 4), "44332211");

  CHECK_EQ(chainlog::get_u64_le(b), 0x0102030405060708ull);
  CHECK_EQ(chainlog::get_u32_le(c), 0x11223344u);
}

TEST(record_hash_is_sha256_of_the_preimage) {
  Record r = sample("payload bytes");
  std::string pre;
  chainlog::append_preimage(r, &pre);
  // compute_record_hash() streams the fields instead of building the
  // preimage; this pins the two to the same answer.
  CHECK_EQ(to_hex(chainlog::compute_record_hash(r)),
           to_hex(Sha256::hash(pre)));
}

TEST(every_field_is_covered_by_the_hash) {
  const Record base = sample("abc");
  const std::string h = to_hex(base.hash);

  Record a = base;
  a.index = 8;
  CHECK(to_hex(chainlog::compute_record_hash(a)) != h);

  Record b = base;
  b.timestamp_ns += 1;
  CHECK(to_hex(chainlog::compute_record_hash(b)) != h);

  Record c = base;
  c.data = "abd";
  CHECK(to_hex(chainlog::compute_record_hash(c)) != h);

  Record d = base;
  d.data = "ab";
  CHECK(to_hex(chainlog::compute_record_hash(d)) != h);

  Record e = base;
  e.prev_hash = digest_of_byte(0xAC);
  CHECK(to_hex(chainlog::compute_record_hash(e)) != h);
}

// Why the data length is written out before the data.
//
// Being honest about the scope of this: in ChainLog's current layout, `data`
// is the ONLY variable-length field and it sits between two fixed-width runs,
// so the data length is already recoverable from the total preimage length --
// and SHA-256's own padding commits to that total length. So for this exact
// layout the prefix is belt-and-braces.
//
// It earns its place anyway, for two reasons this test demonstrates. First,
// injectivity becomes a property of the encoding that you can check by
// looking at it, instead of a property that depends on an argument about the
// rest of the layout plus the hash function's padding. Second, the moment a
// second variable-length field is added, the no-prefix encoding collides --
// and nothing about the field layout warns you.
TEST(length_prefix_is_what_keeps_the_encoding_injective) {
  // Imagine a format with two variable-length fields, "actor" and "data".
  const std::string actor_a = "ab";
  const std::string data_a = "c";
  const std::string actor_b = "a";
  const std::string data_b = "bc";

  // Concatenated with no lengths, two different records encode identically.
  const std::string naive_a = actor_a + data_a;
  const std::string naive_b = actor_b + data_b;
  CHECK_EQ(naive_a, naive_b);
  CHECK_EQ(to_hex(Sha256::hash(naive_a)), to_hex(Sha256::hash(naive_b)));

  // With a fixed-width length in front of each field, they cannot.
  auto prefixed = [](const std::string& actor, const std::string& data) {
    std::string out;
    uint8_t len[8];
    chainlog::put_u64_le(len, actor.size());
    out.append(reinterpret_cast<const char*>(len), 8);
    out.append(actor);
    chainlog::put_u64_le(len, data.size());
    out.append(reinterpret_cast<const char*>(len), 8);
    out.append(data);
    return out;
  };
  CHECK(prefixed(actor_a, data_a) != prefixed(actor_b, data_b));
  CHECK(to_hex(Sha256::hash(prefixed(actor_a, data_a))) !=
        to_hex(Sha256::hash(prefixed(actor_b, data_b))));
}

TEST(genesis_prev_hash_is_thirty_two_zero_bytes) {
  CHECK_EQ(to_hex(chainlog::genesis_prev_hash()),
           "0000000000000000000000000000000000000000000000000000000000000000");
  CHECK_EQ(chainlog::genesis_prev_hash().size(), static_cast<size_t>(32));
}

// --- the on-disk frame -----------------------------------------------------

TEST(frame_starts_with_readable_magic) {
  std::string frame;
  chainlog::append_frame(sample("x"), &frame);
  CHECK_EQ(std::string(frame, 0, 4), "CHLG");
}

TEST(frame_length_is_overhead_plus_payload) {
  for (size_t n : {size_t(0), size_t(1), size_t(63), size_t(1000)}) {
    std::string frame;
    chainlog::append_frame(sample(std::string(n, 'd')), &frame);
    CHECK_EQ(frame.size(),
             chainlog::kFrameOverheadBytes + chainlog::kPayloadFixedBytes + n);
  }
}

TEST(frame_round_trips) {
  const std::string payloads[] = {
      "",                            // empty data is legal
      "x",                           // one byte
      std::string("a\0b\0\0c", 6),   // NULs: data is bytes, not a C string
      std::string(1000, 'Z'),        // spans several read chunks
      std::string("\xff\xfe\x00\x01", 4),
  };
  for (const std::string& data : payloads) {
    const Record in = sample(data);
    std::string frame;
    chainlog::append_frame(in, &frame);

    Record out;
    size_t consumed = 0;
    std::string detail;
    CHECK_EQ(pname(chainlog::decode_frame(frame.data(), frame.size(), &out,
                                          &consumed, &detail)),
             "ok");
    CHECK_EQ(consumed, frame.size());
    CHECK_EQ(out.index, in.index);
    CHECK_EQ(out.timestamp_ns, in.timestamp_ns);
    CHECK_EQ(out.data.size(), in.data.size());
    CHECK(out.data == in.data);
    CHECK_EQ(to_hex(out.prev_hash), to_hex(in.prev_hash));
    CHECK_EQ(to_hex(out.hash), to_hex(in.hash));
  }
}

TEST(decode_rejects_a_bad_magic) {
  std::string frame;
  chainlog::append_frame(sample("x"), &frame);
  frame[0] = 'X';
  Record out;
  std::string detail;
  CHECK_EQ(pname(chainlog::decode_frame(frame.data(), frame.size(), &out,
                                        nullptr, &detail)),
           "bad-magic");
}

TEST(decode_rejects_a_bad_crc) {
  std::string frame;
  chainlog::append_frame(sample("hello"), &frame);
  // Flip a bit inside the payload and leave the stored CRC alone.
  frame[20] = static_cast<char>(frame[20] ^ 0x01);
  Record out;
  std::string detail;
  CHECK_EQ(pname(chainlog::decode_frame(frame.data(), frame.size(), &out,
                                        nullptr, &detail)),
           "bad-crc");
  // The message must say both values, or the error is useless in a log file.
  CHECK(detail.find("crc32 stored") != std::string::npos);
}

TEST(decode_reports_a_short_buffer_as_a_torn_tail) {
  std::string frame;
  chainlog::append_frame(sample("hello"), &frame);
  Record out;
  std::string detail;
  // Every truncation point, from "not even a prologue" to "one byte short".
  for (size_t keep = 0; keep < frame.size(); ++keep) {
    CHECK_EQ(pname(chainlog::decode_frame(frame.data(), keep, &out, nullptr,
                                          &detail)),
             "torn-tail");
  }
}

TEST(decode_rejects_inconsistent_lengths) {
  const Record in = sample("hello");
  std::string frame;
  chainlog::append_frame(in, &frame);

  // Rewrite the preimage's data_len to a different value and fix the CRC, so
  // the only thing left wrong is that the two length encodings disagree. This
  // is the redundancy between payload_len and data_len doing its job.
  uint8_t* bytes = reinterpret_cast<uint8_t*>(&frame[0]);
  const uint32_t payload_len = chainlog::get_u32_le(bytes + 4);
  chainlog::put_u64_le(bytes + 8 + 16, 4);  // data_len: 5 -> 4
  chainlog::put_u32_le(bytes + 8 + payload_len,
                       chainlog::crc32(bytes + 8, payload_len));

  Record out;
  std::string detail;
  CHECK_EQ(pname(chainlog::decode_frame(frame.data(), frame.size(), &out,
                                        nullptr, &detail)),
           "bad-frame-length");
}

TEST(decode_rejects_an_implausible_payload_length) {
  std::string frame;
  chainlog::append_frame(sample("hello"), &frame);
  uint8_t* bytes = reinterpret_cast<uint8_t*>(&frame[0]);

  Record out;
  std::string detail;

  // Below the fixed minimum: there is not room for the fields a record must
  // have, so this is rejected before anything is read.
  chainlog::put_u32_le(bytes + 4, 10);
  CHECK_EQ(pname(chainlog::decode_frame(frame.data(), frame.size(), &out,
                                        nullptr, &detail)),
           "bad-frame-length");

  // Above the data cap. This is the case that matters for robustness: a
  // flipped bit in the length field must not turn into a huge allocation.
  chainlog::put_u32_le(bytes + 4, 0xFFFFFFFFu);
  CHECK_EQ(pname(chainlog::decode_frame(frame.data(), frame.size(), &out,
                                        nullptr, &detail)),
           "bad-frame-length");
  CHECK(detail.find("limit") != std::string::npos);
}

// --- the file header -------------------------------------------------------

TEST(header_round_trips) {
  Header in;
  in.block_size = 4096;
  std::string buf;
  chainlog::encode_header(in, &buf);
  CHECK_EQ(buf.size(), chainlog::kHeaderBytes);
  CHECK_EQ(std::string(buf, 0, 8), "CHAINLOG");

  Header out;
  std::string detail;
  CHECK_EQ(pname(chainlog::decode_header(buf.data(), buf.size(), &out, &detail)),
           "ok");
  CHECK_EQ(out.format_version, chainlog::kFormatVersion);
  CHECK_EQ(out.flags, 0u);
  CHECK_EQ(out.block_size, 4096ull);
}

TEST(header_rejects_damage_and_unknown_versions) {
  Header in;
  std::string good;
  chainlog::encode_header(in, &good);

  Header out;
  std::string detail;

  // Short file.
  CHECK_EQ(pname(chainlog::decode_header(good.data(), 8, &out, &detail)),
           "bad-header");

  // Wrong magic.
  std::string bad_magic = good;
  bad_magic[0] = 'X';
  CHECK_EQ(pname(chainlog::decode_header(bad_magic.data(), bad_magic.size(),
                                         &out, &detail)),
           "bad-header");

  // A flipped bit anywhere in the covered bytes must be caught by the CRC.
  for (size_t i = 8; i < 28; ++i) {
    std::string flipped = good;
    flipped[i] = static_cast<char>(flipped[i] ^ 0x01);
    CHECK_EQ(pname(chainlog::decode_header(flipped.data(), flipped.size(), &out,
                                           &detail)),
             "bad-header");
  }

  // A future format version, with a correct CRC, reads as "I do not
  // understand this file" rather than being misparsed as version 1.
  std::string future = good;
  uint8_t* fb = reinterpret_cast<uint8_t*>(&future[0]);
  chainlog::put_u32_le(fb + 8, chainlog::kFormatVersion + 1);
  chainlog::put_u32_le(fb + 28, chainlog::crc32(fb, 28));
  CHECK_EQ(pname(chainlog::decode_header(future.data(), future.size(), &out,
                                         &detail)),
           "bad-header");
  CHECK(detail.find("format version") != std::string::npos);

  // block_size 0 would make every checkpoint calculation a division by zero.
  std::string zero_block = good;
  uint8_t* zb = reinterpret_cast<uint8_t*>(&zero_block[0]);
  chainlog::put_u64_le(zb + 16, 0);
  chainlog::put_u32_le(zb + 28, chainlog::crc32(zb, 28));
  CHECK_EQ(pname(chainlog::decode_header(zero_block.data(), zero_block.size(),
                                         &out, &detail)),
           "bad-header");
}
