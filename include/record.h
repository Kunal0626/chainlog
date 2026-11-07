// The record format: what gets hashed, and what gets written to disk.
//
// These are two different byte strings on purpose, and keeping them separate
// is the single most important decision in the format:
//
//   preimage -- the canonical bytes that SHA-256 sees. Fixed-width
//               little-endian integers, with the data length written out
//               before the data, so that distinct records can never produce
//               the same preimage.
//
//   frame    -- what lands in the file: a magic number, a payload length, the
//               payload (preimage + the record's own hash), and a CRC-32.
//               Pure transport. It is deliberately NOT part of the hash, so
//               the framing can change in a future format version without
//               invalidating a single historical hash.
#ifndef CHAINLOG_RECORD_H
#define CHAINLOG_RECORD_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "sha256.h"

namespace chainlog {

// --- limits ----------------------------------------------------------------

// A length read off disk must never be trusted enough to drive an allocation.
// Without a cap, a single flipped bit in a frame's length field turns into a
// multi-gigabyte malloc; with one, it turns into a clean "bad frame length".
// 16 MiB is far more than an audit record needs.
constexpr uint64_t kMaxDataLen = 16ull * 1024ull * 1024ull;

// index(8) + timestamp(8) + data_len(8) + prev_hash(32)
constexpr size_t kPreimageFixedBytes = 8 + 8 + 8 + 32;
// preimage + the record's own hash(32)
constexpr size_t kPayloadFixedBytes = kPreimageFixedBytes + 32;
// magic(4) + payload_len(4) + crc32(4)
constexpr size_t kFrameOverheadBytes = 12;

// Stored little-endian, so the first four bytes of every frame read as
// "CHLG" in a hex dump. Costs nothing and makes the file navigable by eye.
constexpr uint32_t kFrameMagic = 0x474C4843u;

// --- the log file header ---------------------------------------------------
//
// 32 bytes at the front of the log file:
//   0..7   magic "CHAINLOG"
//   8..11  format_version u32 LE
//   12..15 flags u32 LE (reserved, must be 0)
//   16..23 block_size u64 LE -- records per sealed Merkle block
//   24..27 reserved u32 LE (must be 0)
//   28..31 crc32 u32 LE over bytes 0..27
//
// block_size lives in the file rather than in a constant because the
// checkpoints are only meaningful relative to it: if a future release changed
// the default, every existing log's checkpoints would silently stop matching.
constexpr size_t kHeaderBytes = 32;
constexpr uint32_t kFormatVersion = 1;
constexpr uint64_t kDefaultBlockSize = 1024;

struct Header {
  uint32_t format_version = kFormatVersion;
  uint32_t flags = 0;
  uint64_t block_size = kDefaultBlockSize;
};

// --- the record ------------------------------------------------------------

struct Record {
  uint64_t index = 0;
  uint64_t timestamp_ns = 0;  // unix nanoseconds, informational only
  std::string data;           // arbitrary bytes; may contain NULs
  Digest prev_hash{};         // genesis uses all zeros
  Digest hash{};              // SHA-256 of this record's preimage
};

// 32 zero bytes. Documented rather than accidental: the genesis record has no
// predecessor, and "no predecessor" still has to be *some* fixed value that
// goes through the hash like every other field.
const Digest& genesis_prev_hash();

// Unix nanoseconds from the realtime clock.
uint64_t now_unix_nanos();

// Appends r's canonical hash preimage to *out:
//   index || timestamp || data_len || data || prev_hash
// all integers 8-byte little-endian. r.hash is not part of its own preimage.
void append_preimage(const Record& r, std::string* out);

// SHA-256 of append_preimage(r).
Digest compute_record_hash(const Record& r);

// --- problems --------------------------------------------------------------
//
// One enum for every way a log can fail to check out, so the CLI, the tests
// and the error messages all speak the same vocabulary. The split between the
// framing group and the chain group is the split between "a write went wrong"
// and "someone changed history".
enum class Problem {
  kOk = 0,

  // Framing: accidental damage, or a write that never finished.
  kBadHeader,        // file header magic/version/flags/crc is wrong
  kTornTail,         // the file ends part-way through a frame
  kBadMagic,         // a frame mid-file does not start with "CHLG"
  kBadFrameLength,   // payload length implausible, or inconsistent with data_len
  kBadCrc,           // frame CRC-32 mismatch

  // Chain: the records are individually well-formed but history is wrong.
  kBadIndex,         // index is not previous + 1
  kBrokenLink,       // prev_hash does not match the previous record's hash
  kBadHash,          // the stored hash is not the hash of the record's bytes

  // Checkpoints. A checkpoint holds no information that is not already in the
  // records, so a MISSING one is never evidence of tampering -- but a
  // checkpoint that DISAGREES with the records is, and so is a gap in an
  // append-only file.
  kTornCheckpointTail,  // the checkpoints file ends part-way through a frame
  kBadCheckpoint,       // a checkpoint disagrees with the records, or the set
                        // of checkpoints is not the expected contiguous run

  // Anchoring (used from phase 5): the log disagrees with a published head.
  kAnchorMismatch,
  kAnchorMissing,    // the log is shorter than the anchored index
};

// Stable kebab-case name, e.g. "broken-link". Used in CLI output and tests,
// so it is part of the interface, not a debug string.
const char* problem_name(Problem p);

// The result of checking a log. `index`/`offset` point at the FIRST thing
// that is wrong -- a verifier that reports the last failure, or all of them,
// makes it much harder to work out what actually happened.
struct Verdict {
  Problem problem = Problem::kOk;
  uint64_t index = 0;
  uint64_t offset = 0;
  uint64_t records_verified = 0;
  std::string detail;

  bool ok() const { return problem == Problem::kOk; }

  // One line, suitable for stderr.
  std::string message() const;
};

// --- framing ---------------------------------------------------------------

// Appends the on-disk frame for r to *out.
void append_frame(const Record& r, std::string* out);

// Encodes/decodes the 32-byte file header.
void encode_header(const Header& h, std::string* out);
Problem decode_header(const void* buf, size_t len, Header* out,
                      std::string* detail);

// Parses the 8-byte frame prologue (magic + payload length), validating the
// length against the format's limits.
Problem parse_frame_header(const void* buf, uint32_t* payload_len,
                           std::string* detail);

// Verifies the CRC and parses a payload into *out. `payload_len` must be the
// value parse_frame_header returned; `stored_crc` the u32 that followed the
// payload on disk.
Problem parse_frame_body(const void* payload, uint32_t payload_len,
                         uint32_t stored_crc, Record* out,
                         std::string* detail);

// Decodes one whole frame sitting at the front of buf. Convenience for tests
// and for anything holding a complete frame in memory; the log reader uses
// the two functions above so it never has to buffer more than it needs.
// Returns kTornTail if buf is shorter than the frame it describes.
Problem decode_frame(const void* buf, size_t len, Record* out,
                     size_t* consumed, std::string* detail);

// --- little-endian helpers -------------------------------------------------
// Exposed because the tests do byte surgery on frames and need to speak the
// same encoding. Fixed-width and explicitly little-endian: the serialisation
// must not depend on the host's byte order, or two machines would compute
// different hashes for the same record.
void put_u32_le(uint8_t* p, uint32_t v);
void put_u64_le(uint8_t* p, uint64_t v);
uint32_t get_u32_le(const uint8_t* p);
uint64_t get_u64_le(const uint8_t* p);

}  // namespace chainlog

#endif  // CHAINLOG_RECORD_H
