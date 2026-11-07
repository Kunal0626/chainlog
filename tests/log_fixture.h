// Test-only helpers for building log files and performing byte surgery on
// them. The tamper tests need to behave like an attacker with write access,
// which means editing frames directly rather than going through the API.
#ifndef CHAINLOG_TESTS_LOG_FIXTURE_H
#define CHAINLOG_TESTS_LOG_FIXTURE_H

#include <cstdint>
#include <string>
#include <vector>

#include "record.h"

namespace chainlog_test {

// A directory from mkdtemp(3), removed on destruction. Tests must never write
// into the source tree or into a fixed path, or two concurrent runs collide.
class TempDir {
 public:
  TempDir();
  ~TempDir();
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;

  const std::string& path() const { return path_; }

 private:
  std::string path_;
};

std::string read_file(const std::string& path);
void write_file(const std::string& path, const std::string& bytes);

struct FrameSpan {
  uint64_t offset;
  uint64_t length;
};

// Offsets and lengths of every intact frame in a log file's bytes.
std::vector<FrameSpan> frame_spans(const std::string& bytes);

std::vector<chainlog::Record> read_frames(const std::string& bytes);

// Re-encodes `r` over the frame at `offset`, recomputing the CRC. The record's
// data length must be unchanged so the frame length is unchanged; this aborts
// if it is not, rather than silently corrupting the following frames.
void rewrite_frame(std::string* bytes, uint64_t offset,
                   const chainlog::Record& r);

// Re-links and re-hashes every record from `from_index` to the end, the way a
// determined attacker with write access to the whole file would. Used to show
// what the chain alone cannot detect.
void relink_from(std::string* bytes, uint64_t from_index);

// --- building logs ---------------------------------------------------------

// Fixed-width record data, "rec-000007". Fixed width so that every frame is
// the same length and the tamper tests can swap or rewrite frames without
// shifting any offsets.
std::string record_label(uint64_t i);

// Builds a log in `dir` holding n records labelled by record_label().
void build_log(const std::string& dir, uint64_t n,
               uint64_t block_size = chainlog::kDefaultBlockSize);

// Opens `dir` and returns what verify() says about it. Aborts on I/O failure,
// since that means the test itself is broken.
chainlog::Verdict verify_dir(const std::string& dir);

// Rewrites the checkpoints file from scratch so that every root matches the
// records currently on disk -- what a thorough attacker would do after
// re-linking the log. Used to show the last rung of the ladder.
void reseal_all_checkpoints(const std::string& dir);

}  // namespace chainlog_test

#endif  // CHAINLOG_TESTS_LOG_FIXTURE_H
