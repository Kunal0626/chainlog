// The write-ahead log.
//
// `log.wal` holds at most one record: the one currently being appended. The
// protocol in Log::append is
//
//   1. write the framed record to log.wal, fsync
//   2. append the same frame to log, fsync
//   3. truncate log.wal, fsync
//
// What this buys over the hash chain is a different kind of safety, and the
// distinction is the point of the whole file. The hash chain makes a damaged
// log DETECTABLE. The WAL makes an interrupted append RECOVERABLE. A crash
// inside step 2 leaves a torn frame at the end of `log` -- the chain notices,
// but it cannot know whether that record was ever meant to exist, so it cannot
// safely finish or discard it. The WAL holds the answer: if a complete,
// valid frame is sitting in log.wal, the record was durable before the main
// write began, so the append can be completed. If the WAL frame is itself
// torn, step 1 never finished, the caller was never told the append
// succeeded, and the record can be dropped.
//
// Note that the record frame written to the WAL is byte-identical to the one
// written to the log -- same magic, same CRC. There is no separate WAL record
// format to get wrong, and recovery can compare the two with memcmp.
#ifndef CHAINLOG_WAL_H
#define CHAINLOG_WAL_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "record.h"

namespace chainlog {

// 32-byte header, same shape as the log's and the checkpoints':
//   0..7   magic "CHLGWAL1"
//   8..11  format_version u32 LE
//   12..15 flags u32 LE (reserved, must be 0)
//   16..23 reserved u64 LE (must be 0)
//   24..27 reserved u32 LE (must be 0)
//   28..31 crc32 u32 LE over bytes 0..27
//
// "Empty WAL" means a file of exactly kWalHeaderBytes: step 3 truncates to
// the header rather than to zero, so an empty WAL is still identifiably a
// WAL and not a stray zero-length file.
constexpr size_t kWalHeaderBytes = 32;
constexpr uint32_t kWalFormatVersion = 1;

struct WalHeader {
  uint32_t format_version = kWalFormatVersion;
  uint32_t flags = 0;
};

void encode_wal_header(const WalHeader& h, std::string* out);
Problem decode_wal_header(const void* buf, size_t len, WalHeader* out,
                          std::string* detail);

}  // namespace chainlog

#endif  // CHAINLOG_WAL_H
