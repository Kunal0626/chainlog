// Checkpoints: the sealed Merkle root of a block of records.
//
// Every `block_size` records, the Merkle root over that block's record hashes
// is written to the `checkpoints` file as {first_index, last_index, root}.
//
// Checkpoints do two jobs. The obvious one is that they are what an inclusion
// proof is proof *against* -- a proof is only meaningful relative to a root
// somebody already trusts. The less obvious one is that they are a second,
// independent record of history: an attacker who rewrites the log and
// re-links every hash still leaves the old roots sitting in this file. So
// sealing a block turns the "re-link the whole tail" attack from undetectable
// into detectable-unless-they-rewrite-this-file-too.
#ifndef CHAINLOG_CHECKPOINT_H
#define CHAINLOG_CHECKPOINT_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "record.h"
#include "sha256.h"

namespace chainlog {

// 32-byte header, same shape as the log's so there is one layout to learn:
//   0..7   magic "CHLGCKPT"
//   8..11  format_version u32 LE
//   12..15 flags u32 LE (reserved, must be 0)
//   16..23 block_size u64 LE -- must agree with the log's header
//   24..27 reserved u32 LE (must be 0)
//   28..31 crc32 u32 LE over bytes 0..27
//
// block_size is repeated here deliberately. It is derived data, so the
// duplication is a consistency check: if the two files disagree, one of them
// has been swapped in from a different log.
constexpr size_t kCheckpointHeaderBytes = 32;
constexpr uint32_t kCheckpointFormatVersion = 1;

// Stored little-endian, so a frame begins with the ASCII "CKPT".
constexpr uint32_t kCheckpointMagic = 0x54504B43u;

// flags(4) + first_index(8) + last_index(8) + root(32)
constexpr size_t kCheckpointPayloadBytes = 52;
// magic(4) + payload_len(4) + crc32(4)
constexpr size_t kCheckpointOverheadBytes = 12;

struct CheckpointHeader {
  uint32_t format_version = kCheckpointFormatVersion;
  uint32_t flags = 0;
  uint64_t block_size = kDefaultBlockSize;
};

struct Checkpoint {
  // Reserved for the signed-checkpoint mode in phase 5: bit 0 will mean "an
  // HMAC-SHA256 follows the root". Unknown bits are rejected, so an old build
  // refuses a signed file loudly instead of reading it as unsigned.
  uint32_t flags = 0;
  uint64_t first_index = 0;
  uint64_t last_index = 0;
  Digest root{};

  uint64_t leaf_count() const { return last_index - first_index + 1; }
};

void encode_checkpoint_header(const CheckpointHeader& h, std::string* out);
Problem decode_checkpoint_header(const void* buf, size_t len,
                                 CheckpointHeader* out, std::string* detail);

void append_checkpoint_frame(const Checkpoint& c, std::string* out);

// Decodes one checkpoint frame from the front of buf. Returns
// kTornCheckpointTail if fewer bytes are present than the frame needs, so a
// crash during the final write is distinguishable from a damaged file.
Problem decode_checkpoint_frame(const void* buf, size_t len, Checkpoint* out,
                                size_t* consumed, std::string* detail);

}  // namespace chainlog

#endif  // CHAINLOG_CHECKPOINT_H
