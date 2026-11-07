#include "record.h"

#include <cstdio>
#include <cstring>
#include <ctime>

#include "crc32.h"

namespace chainlog {
namespace {

const char kHeaderMagic[8] = {'C', 'H', 'A', 'I', 'N', 'L', 'O', 'G'};

// Appends a fixed-width little-endian integer to a byte string.
void append_u64_le(std::string* out, uint64_t v) {
  uint8_t b[8];
  put_u64_le(b, v);
  out->append(reinterpret_cast<const char*>(b), sizeof(b));
}

void append_u32_le(std::string* out, uint32_t v) {
  uint8_t b[4];
  put_u32_le(b, v);
  out->append(reinterpret_cast<const char*>(b), sizeof(b));
}

}  // namespace

void put_u32_le(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
  p[2] = static_cast<uint8_t>(v >> 16);
  p[3] = static_cast<uint8_t>(v >> 24);
}

void put_u64_le(uint8_t* p, uint64_t v) {
  put_u32_le(p, static_cast<uint32_t>(v));
  put_u32_le(p + 4, static_cast<uint32_t>(v >> 32));
}

uint32_t get_u32_le(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t get_u64_le(const uint8_t* p) {
  return static_cast<uint64_t>(get_u32_le(p)) |
         (static_cast<uint64_t>(get_u32_le(p + 4)) << 32);
}

const Digest& genesis_prev_hash() {
  // All zeros. std::array's default member initialiser in Record already does
  // this, but naming it makes the intent explicit at every use site.
  static const Digest kZero{};
  return kZero;
}

uint64_t now_unix_nanos() {
  struct timespec ts;
  // CLOCK_REALTIME, not CLOCK_MONOTONIC: the timestamp is meant to be a
  // wall-clock time a human can read, which also means it can jump backwards
  // when NTP steps the clock. verify() therefore does NOT require timestamps
  // to increase -- see docs/FORMAT.md.
  if (::clock_gettime(CLOCK_REALTIME, &ts) != 0) {
    return 0;
  }
  return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull +
         static_cast<uint64_t>(ts.tv_nsec);
}

void append_preimage(const Record& r, std::string* out) {
  append_u64_le(out, r.index);
  append_u64_le(out, r.timestamp_ns);
  // The length goes in BEFORE the data. Without it, (data="ab", prev_hash=X)
  // and (data="a", prev_hash=Y) could concatenate to identical bytes for some
  // X and Y -- two different records, one hash, and a forgery the chain would
  // happily accept. A length prefix makes the encoding injective.
  append_u64_le(out, static_cast<uint64_t>(r.data.size()));
  out->append(r.data);
  out->append(reinterpret_cast<const char*>(r.prev_hash.data()),
              r.prev_hash.size());
}

Digest compute_record_hash(const Record& r) {
  // Streamed rather than concatenated: data can be up to 16 MiB and there is
  // no reason to build a second copy of it just to hash it.
  uint8_t fixed[24];
  put_u64_le(fixed, r.index);
  put_u64_le(fixed + 8, r.timestamp_ns);
  put_u64_le(fixed + 16, static_cast<uint64_t>(r.data.size()));

  Sha256 h;
  h.update(fixed, sizeof(fixed));
  h.update(r.data.data(), r.data.size());
  h.update(r.prev_hash.data(), r.prev_hash.size());
  return h.finish();
}

const char* problem_name(Problem p) {
  switch (p) {
    case Problem::kOk:
      return "ok";
    case Problem::kBadHeader:
      return "bad-header";
    case Problem::kTornTail:
      return "torn-tail";
    case Problem::kBadMagic:
      return "bad-magic";
    case Problem::kBadFrameLength:
      return "bad-frame-length";
    case Problem::kBadCrc:
      return "bad-crc";
    case Problem::kBadIndex:
      return "bad-index";
    case Problem::kBrokenLink:
      return "broken-link";
    case Problem::kBadHash:
      return "bad-hash";
    case Problem::kTornCheckpointTail:
      return "torn-checkpoint-tail";
    case Problem::kBadCheckpoint:
      return "bad-checkpoint";
    case Problem::kAnchorMismatch:
      return "anchor-mismatch";
    case Problem::kAnchorMissing:
      return "anchor-missing";
  }
  return "unknown";
}

std::string Verdict::message() const {
  if (ok()) {
    return "ok: " + std::to_string(records_verified) + " record(s) verified";
  }
  std::string s = std::string(problem_name(problem)) +
                  " at index " + std::to_string(index) + " (byte offset " +
                  std::to_string(offset) + ")";
  if (!detail.empty()) {
    s += ": " + detail;
  }
  return s;
}

void encode_header(const Header& h, std::string* out) {
  uint8_t buf[kHeaderBytes];
  std::memset(buf, 0, sizeof(buf));
  std::memcpy(buf, kHeaderMagic, sizeof(kHeaderMagic));
  put_u32_le(buf + 8, h.format_version);
  put_u32_le(buf + 12, h.flags);
  put_u64_le(buf + 16, h.block_size);
  put_u32_le(buf + 24, 0);  // reserved
  put_u32_le(buf + 28, crc32(buf, 28));
  out->append(reinterpret_cast<const char*>(buf), sizeof(buf));
}

Problem decode_header(const void* buf, size_t len, Header* out,
                      std::string* detail) {
  if (len < kHeaderBytes) {
    if (detail != nullptr) {
      *detail = "file is shorter than the " + std::to_string(kHeaderBytes) +
                "-byte header";
    }
    return Problem::kBadHeader;
  }
  const uint8_t* p = static_cast<const uint8_t*>(buf);

  if (std::memcmp(p, kHeaderMagic, sizeof(kHeaderMagic)) != 0) {
    if (detail != nullptr) {
      *detail = "magic is not \"CHAINLOG\"";
    }
    return Problem::kBadHeader;
  }
  // Check the CRC before trusting any field, including the version: a
  // corrupted version number should read as "damaged header", not as "log
  // from the future".
  if (get_u32_le(p + 28) != crc32(p, 28)) {
    if (detail != nullptr) {
      *detail = "header crc32 mismatch";
    }
    return Problem::kBadHeader;
  }

  Header h;
  h.format_version = get_u32_le(p + 8);
  h.flags = get_u32_le(p + 12);
  h.block_size = get_u64_le(p + 16);

  if (h.format_version != kFormatVersion) {
    if (detail != nullptr) {
      *detail = "format version " + std::to_string(h.format_version) +
                ", this build understands " + std::to_string(kFormatVersion);
    }
    return Problem::kBadHeader;
  }
  if (h.flags != 0) {
    if (detail != nullptr) {
      *detail = "unknown flags set: " + std::to_string(h.flags);
    }
    return Problem::kBadHeader;
  }
  if (h.block_size == 0) {
    if (detail != nullptr) {
      *detail = "block_size is 0";
    }
    return Problem::kBadHeader;
  }

  *out = h;
  return Problem::kOk;
}

void append_frame(const Record& r, std::string* out) {
  std::string payload;
  payload.reserve(kPayloadFixedBytes + r.data.size());
  append_preimage(r, &payload);
  payload.append(reinterpret_cast<const char*>(r.hash.data()), r.hash.size());

  append_u32_le(out, kFrameMagic);
  append_u32_le(out, static_cast<uint32_t>(payload.size()));
  out->append(payload);
  append_u32_le(out, crc32(payload.data(), payload.size()));
}

Problem parse_frame_header(const void* buf, uint32_t* payload_len,
                           std::string* detail) {
  const uint8_t* p = static_cast<const uint8_t*>(buf);

  if (get_u32_le(p) != kFrameMagic) {
    if (detail != nullptr) {
      *detail = "frame does not start with \"CHLG\"";
    }
    return Problem::kBadMagic;
  }

  const uint32_t len = get_u32_le(p + 4);
  if (len < kPayloadFixedBytes) {
    if (detail != nullptr) {
      *detail = "payload length " + std::to_string(len) + " is below the " +
                std::to_string(kPayloadFixedBytes) + "-byte minimum";
    }
    return Problem::kBadFrameLength;
  }
  if (len - kPayloadFixedBytes > kMaxDataLen) {
    if (detail != nullptr) {
      *detail = "payload length " + std::to_string(len) + " implies data of " +
                std::to_string(len - kPayloadFixedBytes) +
                " bytes, over the " + std::to_string(kMaxDataLen) +
                "-byte limit";
    }
    return Problem::kBadFrameLength;
  }

  *payload_len = len;
  return Problem::kOk;
}

Problem parse_frame_body(const void* payload, uint32_t payload_len,
                         uint32_t stored_crc, Record* out,
                         std::string* detail) {
  const uint8_t* p = static_cast<const uint8_t*>(payload);

  // CRC first: everything below reads fields out of these bytes, and there is
  // no point interpreting bytes that are known to be damaged.
  const uint32_t actual = crc32(p, payload_len);
  if (actual != stored_crc) {
    if (detail != nullptr) {
      char buf[96];
      std::snprintf(buf, sizeof(buf), "crc32 stored %08x, computed %08x",
                    stored_crc, actual);
      *detail = buf;
    }
    return Problem::kBadCrc;
  }

  Record r;
  r.index = get_u64_le(p);
  r.timestamp_ns = get_u64_le(p + 8);
  const uint64_t data_len = get_u64_le(p + 16);

  // The frame's payload length and the preimage's data length are two
  // independent encodings of the same number. Requiring them to agree turns
  // that redundancy into a consistency check rather than wasted bytes.
  if (data_len > kMaxDataLen ||
      data_len + kPayloadFixedBytes != payload_len) {
    if (detail != nullptr) {
      *detail = "data_len " + std::to_string(data_len) +
                " disagrees with payload length " +
                std::to_string(payload_len);
    }
    return Problem::kBadFrameLength;
  }

  r.data.assign(reinterpret_cast<const char*>(p + 24),
                static_cast<size_t>(data_len));
  std::memcpy(r.prev_hash.data(), p + 24 + data_len, 32);
  std::memcpy(r.hash.data(), p + 24 + data_len + 32, 32);

  *out = r;
  return Problem::kOk;
}

Problem decode_frame(const void* buf, size_t len, Record* out,
                     size_t* consumed, std::string* detail) {
  if (len < 8) {
    if (detail != nullptr) {
      *detail = "fewer than 8 bytes available for the frame prologue";
    }
    return Problem::kTornTail;
  }

  uint32_t payload_len = 0;
  const Problem p =
      parse_frame_header(buf, &payload_len, detail);
  if (p != Problem::kOk) {
    return p;
  }

  const size_t frame_len = kFrameOverheadBytes + payload_len;
  if (len < frame_len) {
    if (detail != nullptr) {
      *detail = "frame claims " + std::to_string(frame_len) +
                " bytes, only " + std::to_string(len) + " available";
    }
    return Problem::kTornTail;
  }

  const uint8_t* bytes = static_cast<const uint8_t*>(buf);
  const uint32_t stored_crc = get_u32_le(bytes + 8 + payload_len);
  const Problem q =
      parse_frame_body(bytes + 8, payload_len, stored_crc, out, detail);
  if (q != Problem::kOk) {
    return q;
  }

  if (consumed != nullptr) {
    *consumed = frame_len;
  }
  return Problem::kOk;
}

}  // namespace chainlog
