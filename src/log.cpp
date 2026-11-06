#include "log.h"

#include <cstdlib>
#include <cstring>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

namespace chainlog {
namespace {

// Read size for the sequential scan. Big enough that walking a million frames
// costs a few thousand syscalls rather than a million.
constexpr size_t kReadChunk = 256 * 1024;

// A sequential, buffered reader over a byte range of a file.
//
// Written by hand instead of using stdio because the frame walker needs to
// peek at a frame prologue, learn how long the frame is, and then get a
// contiguous pointer to the whole frame -- including frames larger than the
// buffer. FILE* gives you neither contiguity nor a growable window.
class BufReader {
 public:
  BufReader(int fd, uint64_t start, uint64_t end)
      : fd_(fd), file_off_(start), end_(end) {
    buf_.resize(kReadChunk);
  }

  // Makes at least n bytes available at ptr() if the file still holds them.
  // Returns how many are actually available; a value below n means end of
  // file was reached, which is not in itself an error.
  size_t ensure(size_t n, std::string* err) {
    if (failed_) {
      return 0;
    }
    while (tail_ - head_ < n) {
      // Slide the unread bytes to the front so the window can grow forwards.
      if (head_ > 0) {
        const size_t avail = tail_ - head_;
        std::memmove(buf_.data(), buf_.data() + head_, avail);
        head_ = 0;
        tail_ = avail;
      }
      if (buf_.size() < n) {
        buf_.resize(n);  // A single frame may exceed kReadChunk.
      }
      const uint64_t read_off = file_off_ + (tail_ - head_);
      if (read_off >= end_) {
        break;
      }
      size_t want = buf_.size() - tail_;
      const uint64_t remaining = end_ - read_off;
      if (want > remaining) {
        want = static_cast<size_t>(remaining);
      }
      if (want == 0) {
        break;
      }
      size_t got = 0;
      if (!pread_full(fd_, buf_.data() + tail_, want, read_off, &got, err)) {
        failed_ = true;
        return 0;
      }
      if (got == 0) {
        break;
      }
      tail_ += got;
    }
    return tail_ - head_;
  }

  const uint8_t* ptr() const { return buf_.data() + head_; }

  void consume(size_t n) {
    head_ += n;
    file_off_ += n;  // Keeps file_off_ equal to the absolute offset of ptr().
  }

  uint64_t offset() const { return file_off_; }
  bool failed() const { return failed_; }

 private:
  int fd_;
  uint64_t file_off_;  // absolute file offset of ptr()
  uint64_t end_;       // absolute offset to stop reading at
  std::vector<uint8_t> buf_;
  size_t head_ = 0;    // read cursor within buf_
  size_t tail_ = 0;    // bytes filled in buf_
  bool failed_ = false;
};

enum class Step {
  kFrame,     // a well-formed frame was read
  kEndOfLog,  // clean end of file, exactly on a frame boundary
  kProblem,   // the file is damaged; *problem says how
  kIoError,   // read() failed; *err says why
};

// Walks the frames of a log file. Structural checks only -- it does not
// recompute hashes, so it can be used both by the cheap open-time tail scan
// and by the full verify().
class FrameCursor {
 public:
  FrameCursor(int fd, uint64_t start, uint64_t end) : r_(fd, start, end) {}

  Step next(Record* out, uint64_t* frame_offset, Problem* problem,
            std::string* detail, std::string* err) {
    *frame_offset = r_.offset();

    size_t avail = r_.ensure(8, err);
    if (r_.failed()) {
      return Step::kIoError;
    }
    if (avail == 0) {
      return Step::kEndOfLog;
    }
    // Between 1 and 7 bytes left: a write stopped part-way through the
    // prologue. Always at end of file, so this is a crash artifact.
    if (avail < 8) {
      *problem = Problem::kTornTail;
      *detail = "only " + std::to_string(avail) +
                " byte(s) left at end of file, too few for a frame prologue";
      return Step::kProblem;
    }

    uint32_t payload_len = 0;
    Problem p = parse_frame_header(r_.ptr(), &payload_len, detail);
    if (p != Problem::kOk) {
      *problem = p;
      return Step::kProblem;
    }

    const size_t frame_len = kFrameOverheadBytes + payload_len;
    avail = r_.ensure(frame_len, err);
    if (r_.failed()) {
      return Step::kIoError;
    }
    if (avail < frame_len) {
      *problem = Problem::kTornTail;
      *detail = "frame claims " + std::to_string(frame_len) +
                " bytes, only " + std::to_string(avail) +
                " left at end of file";
      return Step::kProblem;
    }

    // ensure() may have slid the window, so re-read the pointer.
    const uint8_t* bytes = r_.ptr();
    const uint32_t stored_crc = get_u32_le(bytes + 8 + payload_len);
    p = parse_frame_body(bytes + 8, payload_len, stored_crc, out, detail);
    if (p != Problem::kOk) {
      *problem = p;
      return Step::kProblem;
    }

    r_.consume(frame_len);
    return Step::kFrame;
  }

  uint64_t offset() const { return r_.offset(); }

 private:
  BufReader r_;
};

}  // namespace

std::string Log::log_path(const std::string& dir) { return dir + "/log"; }
std::string Log::wal_path(const std::string& dir) { return dir + "/log.wal"; }
std::string Log::checkpoints_path(const std::string& dir) {
  return dir + "/checkpoints";
}
std::string Log::lock_path(const std::string& dir) { return dir + "/lock"; }

std::string Log::default_dir() {
  const char* env = std::getenv("CHAINLOG_DIR");
  if (env != nullptr && env[0] != '\0') {
    return env;
  }
  return "chainlog.d";
}

bool Log::open(const std::string& dir, const Options& opt, std::string* err) {
  dir_ = dir;
  if (!make_dir_if_missing(dir, err)) {
    return false;
  }

  const std::string path = log_path(dir);
  const int fd = ::open(path.c_str(), O_RDWR | O_CREAT, 0644);
  if (fd < 0) {
    *err = errno_text("open(" + path + ")");
    return false;
  }
  log_fd_.reset(fd);

  uint64_t len = 0;
  if (!file_length(log_fd_.get(), &len, err)) {
    return false;
  }

  if (len == 0) {
    Header h;
    h.block_size = (opt.block_size == 0) ? kDefaultBlockSize : opt.block_size;
    std::string buf;
    encode_header(h, &buf);
    if (!pwrite_all(log_fd_.get(), buf.data(), buf.size(), 0, err)) {
      return false;
    }
    // Both barriers matter: full_fsync makes the 32 bytes durable, and
    // fsync_dir makes the file's NAME durable. Without the second, a crash
    // here can leave an inode with a valid header that no directory entry
    // points to -- the log would appear to have never been created.
    if (!full_fsync(log_fd_.get(), err)) {
      return false;
    }
    if (!fsync_dir(dir, err)) {
      return false;
    }
    header_ = h;
    last_hash_ = genesis_prev_hash();
    log_end_ = kHeaderBytes;
    return true;
  }

  uint8_t hbuf[kHeaderBytes];
  size_t got = 0;
  if (!pread_full(log_fd_.get(), hbuf, sizeof(hbuf), 0, &got, err)) {
    return false;
  }
  std::string detail;
  const Problem p = decode_header(hbuf, got, &header_, &detail);
  if (p != Problem::kOk) {
    // Not an I/O error: the file exists and reads fine, it simply is not a
    // valid log. Recording it as a verdict (rather than failing open()) means
    // `chainlog verify` can still run and report it properly, which is the
    // whole point of having a verifier.
    scan_verdict_ = Verdict{};
    scan_verdict_.problem = Problem::kBadHeader;
    scan_verdict_.detail = detail;
    log_end_ = len;
    last_hash_ = genesis_prev_hash();
    return true;
  }

  return scan_tail(err);
}

bool Log::scan_tail(std::string* err) {
  uint64_t len = 0;
  if (!file_length(log_fd_.get(), &len, err)) {
    return false;
  }

  FrameCursor cur(log_fd_.get(), kHeaderBytes, len);
  Record r;
  uint64_t off = 0;
  Problem p = Problem::kOk;
  std::string detail;

  uint64_t count = 0;
  uint64_t data_bytes = 0;
  uint64_t next_index = 0;
  Digest last = genesis_prev_hash();
  Record last_record;
  bool has_last = false;
  uint64_t end = kHeaderBytes;

  while (true) {
    const Step s = cur.next(&r, &off, &p, &detail, err);
    if (s == Step::kIoError) {
      return false;
    }
    if (s == Step::kEndOfLog) {
      break;
    }
    if (s == Step::kProblem) {
      scan_verdict_.problem = p;
      scan_verdict_.index = count;
      scan_verdict_.offset = off;
      scan_verdict_.records_verified = count;
      scan_verdict_.detail = detail;
      break;
    }

    // Framing only -- no SHA-256 here. That makes open() cheap, at the cost
    // of taking the stored hash at face value. If a stored hash was tampered
    // with, a later append chains onto the bad value; verify() still reports
    // it. The guarantee is detection, not prevention.
    last = r.hash;
    next_index = r.index + 1;
    last_record = r;
    has_last = true;
    data_bytes += r.data.size();
    end = cur.offset();
    ++count;
  }

  record_count_ = count;
  data_bytes_ = data_bytes;
  next_index_ = next_index;
  last_hash_ = last;
  last_record_ = last_record;
  has_last_ = has_last;
  log_end_ = end;
  return true;
}

bool Log::append(const std::string& data, Record* out, std::string* err) {
  if (!scan_verdict_.ok()) {
    *err = "refusing to append to a damaged log: " + scan_verdict_.message() +
           "; run `chainlog verify`";
    return false;
  }
  if (data.size() > kMaxDataLen) {
    *err = "record data is " + std::to_string(data.size()) +
           " bytes, the limit is " + std::to_string(kMaxDataLen);
    return false;
  }

  Record r;
  r.index = next_index_;
  r.timestamp_ns = now_unix_nanos();
  r.data = data;
  r.prev_hash = last_hash_;
  r.hash = compute_record_hash(r);

  std::string frame;
  append_frame(r, &frame);

  // Phase 2: one write, one barrier. Durable once full_fsync returns, but a
  // crash *inside* the write leaves a torn frame at the tail. Phase 4 puts
  // this behind a write-ahead log so that case becomes recoverable instead of
  // merely detectable.
  if (!pwrite_all(log_fd_.get(), frame.data(), frame.size(), log_end_, err)) {
    return false;
  }
  if (!full_fsync(log_fd_.get(), err)) {
    return false;
  }

  log_end_ += frame.size();
  next_index_ = r.index + 1;
  last_hash_ = r.hash;
  last_record_ = r;
  has_last_ = true;
  ++record_count_;
  data_bytes_ += data.size();

  *out = r;
  return true;
}

bool Log::verify(Verdict* out, std::string* err) const {
  Verdict v;

  uint64_t len = 0;
  if (!file_length(log_fd_.get(), &len, err)) {
    return false;
  }

  // Re-read the header from disk rather than trusting what open() cached.
  // verify() has to be a statement about the bytes that are there now.
  uint8_t hbuf[kHeaderBytes];
  size_t got = 0;
  if (!pread_full(log_fd_.get(), hbuf, sizeof(hbuf), 0, &got, err)) {
    return false;
  }
  Header h;
  std::string detail;
  Problem p = decode_header(hbuf, got, &h, &detail);
  if (p != Problem::kOk) {
    v.problem = p;
    v.detail = detail;
    *out = v;
    return true;
  }

  FrameCursor cur(log_fd_.get(), kHeaderBytes, len);
  Record r;
  uint64_t off = 0;
  uint64_t expected_index = 0;
  Digest prev = genesis_prev_hash();

  while (true) {
    const Step s = cur.next(&r, &off, &p, &detail, err);
    if (s == Step::kIoError) {
      return false;
    }
    if (s == Step::kEndOfLog) {
      break;
    }
    if (s == Step::kProblem) {
      v.problem = p;
      v.index = expected_index;
      v.offset = off;
      v.detail = detail;
      break;
    }

    if (r.index != expected_index) {
      v.problem = Problem::kBadIndex;
      v.index = expected_index;
      v.offset = off;
      v.detail = "expected index " + std::to_string(expected_index) +
                 ", frame says " + std::to_string(r.index);
      break;
    }

    if (r.prev_hash != prev) {
      v.problem = Problem::kBrokenLink;
      v.index = expected_index;
      v.offset = off;
      v.detail = "prev_hash does not match the previous record's hash";
      break;
    }

    const Digest computed = compute_record_hash(r);
    if (computed != r.hash) {
      v.problem = Problem::kBadHash;
      v.index = expected_index;
      v.offset = off;
      v.detail = "stored hash is not the hash of this record's bytes";
      break;
    }

    // Chain on the COMPUTED hash, never the stored one.
    //
    // This is the difference between a useful error and a misleading one. If
    // someone edits the stored hash field of record i, chaining on the
    // computed value reports kBadHash at exactly i. Chaining on the stored
    // value would instead report a broken link at i+1 -- pointing the
    // investigator at the one record that was not touched.
    prev = computed;
    ++expected_index;
    ++v.records_verified;
  }

  *out = v;
  return true;
}

bool Log::head(Record* out) const {
  if (!has_last_) {
    return false;
  }
  *out = last_record_;
  return true;
}

Log::Stats Log::stats() const {
  Stats s;
  s.record_count = record_count_;
  s.log_bytes = log_end_;
  s.data_bytes = data_bytes_;
  s.block_size = header_.block_size;
  s.sealed_blocks =
      (header_.block_size == 0) ? 0 : record_count_ / header_.block_size;
  return s;
}

}  // namespace chainlog
