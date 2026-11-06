// The append-only log file and the chain check over it.
//
// Phase 2 scope: this append() writes the frame and fsyncs it. That is
// durable but not yet crash-atomic -- a crash in the middle of the write can
// leave a torn frame at the tail, which verify() reports as kTornTail.
// Phase 4 wraps the same write in a write-ahead log so the torn tail becomes
// recoverable rather than merely detectable.
#ifndef CHAINLOG_LOG_H
#define CHAINLOG_LOG_H

#include <cstdint>
#include <string>

#include "fileio.h"
#include "record.h"

namespace chainlog {

class Log {
 public:
  struct Options {
    // Records per sealed Merkle block. Only used when creating a new log;
    // for an existing one the value in the file header wins, because the
    // stored checkpoints are only meaningful relative to it.
    uint64_t block_size = kDefaultBlockSize;
  };

  struct Stats {
    uint64_t record_count = 0;
    uint64_t log_bytes = 0;    // including the 32-byte header
    uint64_t data_bytes = 0;   // sum of record payload sizes
    uint64_t block_size = 0;
    uint64_t sealed_blocks = 0;
  };

  Log() = default;
  Log(const Log&) = delete;
  Log& operator=(const Log&) = delete;

  // Opens `dir`, creating the directory and the log file if they are absent.
  //
  // Opening scans the whole file to find the tail. That is O(n) in the number
  // of records, and it is a deliberate choice: the alternative is caching the
  // head in a second file, which creates a second source of truth that can
  // disagree with the log -- exactly the class of bug this project exists to
  // detect. The scan checks framing only (magic, lengths, CRC); it does not
  // recompute SHA-256, so it is far cheaper than verify().
  bool open(const std::string& dir, const Options& opt, std::string* err);

  bool is_open() const { return log_fd_.valid(); }

  // Appends a record carrying `data` and fsyncs. Fills *out on success.
  // Refuses if the open-time scan found the file structurally damaged.
  bool append(const std::string& data, Record* out, std::string* err);

  // Recomputes every record hash and every chain link from the genesis
  // record, and reports the FIRST inconsistency. *err is set only for I/O
  // failures; a tampered log is a Verdict, not an error -- a verifier that
  // returned "error" for a detected forgery would be conflating "I could not
  // check" with "I checked, and it is bad".
  bool verify(Verdict* out, std::string* err) const;

  // Copies the last record into *out. Returns false if the log is empty.
  // O(1): the tail record is cached by open() and append().
  bool head(Record* out) const;

  // O(1): every field is accumulated during the open-time scan and by
  // append(), so this never touches the disk.
  Stats stats() const;

  uint64_t block_size() const { return header_.block_size; }
  uint64_t record_count() const { return next_index_; }

  // What the open-time scan concluded. ok() unless the file is damaged.
  const Verdict& scan_verdict() const { return scan_verdict_; }

  // Standard file names inside the log directory.
  static std::string log_path(const std::string& dir);
  static std::string wal_path(const std::string& dir);
  static std::string checkpoints_path(const std::string& dir);
  static std::string lock_path(const std::string& dir);

  // Default directory: $CHAINLOG_DIR, else "./chainlog.d".
  static std::string default_dir();

 private:
  // Walks frames from the header to end of file, filling in next_index_,
  // last_hash_ and log_end_, and recording any structural problem found.
  bool scan_tail(std::string* err);

  std::string dir_;
  Fd log_fd_;
  Header header_;

  // Cached tail state, so append() does not rescan the file every time.
  // next_index_ comes from the last frame's stored index + 1, not from the
  // record count: on a tampered log those differ, and appending should keep
  // the chain locally consistent while verify() reports the tampering.
  uint64_t next_index_ = 0;
  Digest last_hash_ = Digest{};
  uint64_t log_end_ = 0;  // byte offset just past the last intact frame
  uint64_t record_count_ = 0;
  uint64_t data_bytes_ = 0;
  Record last_record_;
  bool has_last_ = false;

  Verdict scan_verdict_;
};

}  // namespace chainlog

#endif  // CHAINLOG_LOG_H
