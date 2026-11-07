#include "wal.h"

#include <cstring>

#include "crc32.h"

namespace chainlog {
namespace {

const char kMagic[8] = {'C', 'H', 'L', 'G', 'W', 'A', 'L', '1'};

}  // namespace

void encode_wal_header(const WalHeader& h, std::string* out) {
  uint8_t buf[kWalHeaderBytes];
  std::memset(buf, 0, sizeof(buf));
  std::memcpy(buf, kMagic, sizeof(kMagic));
  put_u32_le(buf + 8, h.format_version);
  put_u32_le(buf + 12, h.flags);
  put_u32_le(buf + 28, crc32(buf, 28));
  out->append(reinterpret_cast<const char*>(buf), sizeof(buf));
}

Problem decode_wal_header(const void* buf, size_t len, WalHeader* out,
                          std::string* detail) {
  if (len < kWalHeaderBytes) {
    if (detail != nullptr) {
      *detail = "WAL is shorter than its 32-byte header";
    }
    return Problem::kBadWal;
  }
  const uint8_t* p = static_cast<const uint8_t*>(buf);

  if (std::memcmp(p, kMagic, sizeof(kMagic)) != 0) {
    if (detail != nullptr) {
      *detail = "WAL magic is not \"CHLGWAL1\"";
    }
    return Problem::kBadWal;
  }
  if (get_u32_le(p + 28) != crc32(p, 28)) {
    if (detail != nullptr) {
      *detail = "WAL header crc32 mismatch";
    }
    return Problem::kBadWal;
  }

  WalHeader h;
  h.format_version = get_u32_le(p + 8);
  h.flags = get_u32_le(p + 12);

  if (h.format_version != kWalFormatVersion) {
    if (detail != nullptr) {
      *detail = "WAL format version " + std::to_string(h.format_version) +
                ", this build understands " +
                std::to_string(kWalFormatVersion);
    }
    return Problem::kBadWal;
  }
  if (h.flags != 0 || get_u64_le(p + 16) != 0 || get_u32_le(p + 24) != 0) {
    if (detail != nullptr) {
      *detail = "reserved bits are set in the WAL header";
    }
    return Problem::kBadWal;
  }

  *out = h;
  return Problem::kOk;
}

}  // namespace chainlog
