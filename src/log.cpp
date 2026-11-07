#include "log.h"

#include "hex.h"

#include <cerrno>
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

// Every checkpoint frame is the same size in format version 1, so the offset
// of the n-th one is exact arithmetic rather than a walk.
constexpr uint64_t kCheckpointFrameBytes =
    kCheckpointOverheadBytes + kCheckpointPayloadBytes;

// Cuts a file back to `len` and makes the new length durable.
bool truncate_to(int fd, uint64_t len, std::string* err) {
  if (::ftruncate(fd, static_cast<off_t>(len)) != 0) {
    if (err != nullptr) {
      *err = errno_text("ftruncate");
    }
    return false;
  }
  return full_fsync(fd, err);
}

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

  // Both files are opened before either is interpreted, so that even a log
  // with an unreadable header still has a usable checkpoints descriptor for
  // reporting.
  const std::string path = log_path(dir);
  const int fd = ::open(path.c_str(), O_RDWR | O_CREAT, 0644);
  if (fd < 0) {
    *err = errno_text("open(" + path + ")");
    return false;
  }
  log_fd_.reset(fd);

  const std::string cpath = checkpoints_path(dir);
  const int cfd = ::open(cpath.c_str(), O_RDWR | O_CREAT, 0644);
  if (cfd < 0) {
    *err = errno_text("open(" + cpath + ")");
    return false;
  }
  ckpt_fd_.reset(cfd);

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
    // points to -- the log would appear never to have been created.
    if (!full_fsync(log_fd_.get(), err)) {
      return false;
    }
    if (!fsync_dir(dir, err)) {
      return false;
    }
    header_ = h;
    last_hash_ = genesis_prev_hash();
    log_end_ = kHeaderBytes;
  } else {
    uint8_t hbuf[kHeaderBytes];
    size_t got = 0;
    if (!pread_full(log_fd_.get(), hbuf, sizeof(hbuf), 0, &got, err)) {
      return false;
    }
    std::string detail;
    const Problem p = decode_header(hbuf, got, &header_, &detail);
    if (p != Problem::kOk) {
      // Not an I/O error: the file exists and reads fine, it simply is not a
      // valid log. Recording it as a verdict (rather than failing open())
      // means `chainlog verify` can still run and report it properly, which
      // is the whole point of having a verifier.
      scan_verdict_ = Verdict{};
      scan_verdict_.problem = Problem::kBadHeader;
      scan_verdict_.detail = detail;
      log_end_ = len;
      last_hash_ = genesis_prev_hash();
      return true;
    }
    if (!scan_tail(err)) {
      return false;
    }
  }

  // The checkpoints file, now that block_size is known.
  uint64_t clen = 0;
  if (!file_length(ckpt_fd_.get(), &clen, err)) {
    return false;
  }
  if (clen == 0) {
    CheckpointHeader ch;
    ch.block_size = header_.block_size;
    std::string buf;
    encode_checkpoint_header(ch, &buf);
    if (!pwrite_all(ckpt_fd_.get(), buf.data(), buf.size(), 0, err)) {
      return false;
    }
    if (!full_fsync(ckpt_fd_.get(), err)) {
      return false;
    }
    if (!fsync_dir(dir, err)) {
      return false;
    }
    ckpt_end_ = kCheckpointHeaderBytes;
    checkpoint_count_ = 0;
  }

  return reconcile_checkpoints(err);
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

  const uint64_t bs = header_.block_size;
  uint64_t count = 0;
  uint64_t data_bytes = 0;
  uint64_t next_index = 0;
  Digest last = genesis_prev_hash();
  Record last_record;
  bool has_last = false;
  uint64_t end = kHeaderBytes;
  std::vector<Digest> pending;
  uint64_t pending_first = 0;

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
    //
    // The pending block is cleared when a new block STARTS, not when one
    // completes, so that after a scan of a log ending exactly on a boundary
    // `pending` still holds that last block's hashes -- which is what makes
    // the crash repair in reconcile_checkpoints() possible.
    if (count % bs == 0) {
      pending.clear();
      pending_first = r.index;
    }
    pending.push_back(r.hash);

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
  pending_hashes_ = pending;
  pending_first_index_ = pending_first;
  return true;
}

bool Log::read_checkpoints(std::vector<Checkpoint>* out, Verdict* v,
                           std::string* err) const {
  out->clear();
  *v = Verdict{};

  uint64_t len = 0;
  if (!file_length(ckpt_fd_.get(), &len, err)) {
    return false;
  }

  // The whole file at once. One checkpoint per block_size records at 64 bytes
  // each, so a million-record log is about 60 KB. A log large enough for this
  // to matter would need streaming, which is noted as a limitation rather
  // than pretended away.
  std::string bytes;
  if (len > 0) {
    bytes.resize(static_cast<size_t>(len));
    size_t got = 0;
    if (!pread_full(ckpt_fd_.get(), &bytes[0], bytes.size(), 0, &got, err)) {
      return false;
    }
    bytes.resize(got);
  }

  CheckpointHeader ch;
  std::string detail;
  Problem p =
      decode_checkpoint_header(bytes.data(), bytes.size(), &ch, &detail);
  if (p != Problem::kOk) {
    v->problem = p;
    v->detail = detail;
    return true;
  }
  if (ch.block_size != header_.block_size) {
    // The duplicated block_size earning its keep: this is a checkpoints file
    // from a different log, or a log whose header was swapped.
    v->problem = Problem::kBadCheckpoint;
    v->detail = "checkpoints block_size " + std::to_string(ch.block_size) +
                " disagrees with the log's " +
                std::to_string(header_.block_size);
    return true;
  }

  size_t off = kCheckpointHeaderBytes;
  while (off < bytes.size()) {
    Checkpoint c;
    size_t consumed = 0;
    p = decode_checkpoint_frame(bytes.data() + off, bytes.size() - off, &c,
                                &consumed, &detail);
    if (p != Problem::kOk) {
      v->problem = p;
      v->index = out->size();
      v->offset = off;
      v->detail = detail;
      return true;
    }
    out->push_back(c);
    off += consumed;
  }
  return true;
}

bool Log::reconcile_checkpoints(std::string* err) {
  if (!scan_verdict_.ok()) {
    return true;  // Nothing to reconcile against a damaged log.
  }

  std::vector<Checkpoint> cps;
  Verdict cv;
  if (!read_checkpoints(&cps, &cv, err)) {
    return false;
  }
  checkpoint_count_ = cps.size();
  ckpt_end_ = kCheckpointHeaderBytes + cps.size() * kCheckpointFrameBytes;

  if (cv.problem == Problem::kTornCheckpointTail) {
    // A torn trailing frame is a crash artifact in DERIVED data: a checkpoint
    // holds no information that is not already in the records, so cutting the
    // partial frame off loses nothing and the root can be recomputed below.
    if (!truncate_to(ckpt_fd_.get(), ckpt_end_, err)) {
      return false;
    }
  } else if (!cv.ok()) {
    scan_verdict_ = cv;
    return true;
  }

  const uint64_t bs = header_.block_size;
  const uint64_t complete = record_count_ / bs;
  if (checkpoint_count_ == complete) {
    return true;
  }

  // One missing block, with the log ending exactly on a boundary, is the one
  // shortfall a crash can produce: append() writes the record, fsyncs, and
  // only then seals, so a crash in between leaves exactly one complete block
  // unsealed -- and pending_hashes_ holds precisely those hashes. Re-seal it.
  if (checkpoint_count_ + 1 == complete && record_count_ % bs == 0 &&
      pending_hashes_.size() == bs &&
      pending_first_index_ == checkpoint_count_ * bs) {
    return seal_pending_block(err);
  }

  // Anything else did not come from a crash. Sealing is synchronous inside
  // append(), so two or more missing blocks means the checkpoints file was
  // truncated or edited. Re-deriving those roots from the records would
  // destroy the very evidence that makes checkpoints worth keeping -- an
  // attacker who rewrites the log is caught precisely because the old roots
  // are still here. So this is reported, never repaired.
  scan_verdict_.problem = Problem::kBadCheckpoint;
  scan_verdict_.index = checkpoint_count_ * bs;
  scan_verdict_.records_verified = record_count_;
  scan_verdict_.detail =
      std::to_string(record_count_) + " record(s) form " +
      std::to_string(complete) + " complete block(s) but the checkpoints " +
      "file holds " + std::to_string(checkpoint_count_) +
      "; a crash can leave at most one block unsealed";
  return true;
}

bool Log::seal_pending_block(std::string* err) {
  Checkpoint c;
  c.flags = 0;
  c.first_index = pending_first_index_;
  c.last_index = pending_first_index_ + pending_hashes_.size() - 1;
  c.root = merkle_root(pending_hashes_);

  std::string frame;
  append_checkpoint_frame(c, &frame);
  if (!pwrite_all(ckpt_fd_.get(), frame.data(), frame.size(), ckpt_end_, err)) {
    return false;
  }
  if (!full_fsync(ckpt_fd_.get(), err)) {
    return false;
  }
  ckpt_end_ += frame.size();
  ++checkpoint_count_;
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

  // Phase 3: one write, one barrier, then maybe a checkpoint. Durable once
  // full_fsync returns, but a crash *inside* the write leaves a torn frame at
  // the tail. Phase 4 puts this behind a write-ahead log so that case becomes
  // recoverable instead of merely detectable.
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
  data_bytes_ += data.size();

  const uint64_t bs = header_.block_size;
  if (record_count_ % bs == 0) {
    pending_hashes_.clear();
    pending_first_index_ = r.index;
  }
  pending_hashes_.push_back(r.hash);
  ++record_count_;

  // The record is durable before the checkpoint is written, which is the
  // right order: a checkpoint is derived from records, so a checkpoint
  // without its records would be a claim about history that cannot be
  // checked. The reverse gap -- records without their checkpoint -- is
  // repaired at the next open().
  if (record_count_ % bs == 0) {
    if (!seal_pending_block(err)) {
      return false;
    }
  }

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
  if (h.block_size != header_.block_size) {
    v.problem = Problem::kBadHeader;
    v.detail = "block_size changed from " +
               std::to_string(header_.block_size) + " to " +
               std::to_string(h.block_size) + " since the log was opened";
    *out = v;
    return true;
  }

  std::vector<Checkpoint> cps;
  Verdict cv;
  if (!read_checkpoints(&cps, &cv, err)) {
    return false;
  }
  if (!cv.ok()) {
    *out = cv;
    return true;
  }

  const uint64_t bs = h.block_size;
  FrameCursor cur(log_fd_.get(), kHeaderBytes, len);
  Record r;
  uint64_t off = 0;
  uint64_t expected_index = 0;
  Digest prev = genesis_prev_hash();

  // Leaves of the block currently being rebuilt. Bounded by block_size, so
  // verify() is O(block) in memory no matter how long the log is.
  std::vector<Digest> block;
  block.reserve(static_cast<size_t>(bs));
  uint64_t block_no = 0;

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
    // computed value reports bad-hash at exactly i. Chaining on the stored
    // value would instead report a broken link at i+1 -- pointing the
    // investigator at the one record that was not touched.
    prev = computed;
    block.push_back(computed);
    ++expected_index;
    ++v.records_verified;

    if (block.size() != bs) {
      continue;
    }

    // A block just completed: rebuild its root and hold the checkpoint to it.
    if (block_no >= cps.size()) {
      v.problem = Problem::kBadCheckpoint;
      v.index = block_no * bs;
      v.offset = off;
      v.detail = "records " + std::to_string(block_no * bs) + ".." +
                 std::to_string(block_no * bs + bs - 1) +
                 " form a complete block but the checkpoints file holds only " +
                 std::to_string(cps.size()) + " checkpoint(s)";
      break;
    }
    const Checkpoint& cp = cps[static_cast<size_t>(block_no)];
    const uint64_t want_first = block_no * bs;
    const uint64_t want_last = want_first + bs - 1;
    if (cp.first_index != want_first || cp.last_index != want_last) {
      v.problem = Problem::kBadCheckpoint;
      v.index = want_first;
      v.detail = "checkpoint " + std::to_string(block_no) + " covers " +
                 std::to_string(cp.first_index) + ".." +
                 std::to_string(cp.last_index) + ", expected " +
                 std::to_string(want_first) + ".." + std::to_string(want_last);
      break;
    }
    const Digest root = merkle_root(block);
    if (root != cp.root) {
      // The records are internally consistent and still disagree with the
      // sealed root. Either the records were rewritten and re-linked, or the
      // checkpoint was edited. Either way it is evidence.
      v.problem = Problem::kBadCheckpoint;
      v.index = want_first;
      v.detail = "block " + std::to_string(block_no) + " (records " +
                 std::to_string(want_first) + ".." +
                 std::to_string(want_last) + ") has root " + to_hex(root) +
                 " but the checkpoint says " + to_hex(cp.root);
      break;
    }
    ++block_no;
    block.clear();
  }

  if (v.ok() && cps.size() != block_no) {
    v.problem = Problem::kBadCheckpoint;
    v.index = block_no * bs;
    v.detail = "the checkpoints file holds " + std::to_string(cps.size()) +
               " checkpoint(s) but the log has only " +
               std::to_string(block_no) + " complete block(s)";
  }

  *out = v;
  return true;
}

bool Log::prove(uint64_t index, ProveResult* out, std::string* err) const {
  *out = ProveResult{};

  if (!scan_verdict_.ok()) {
    out->outcome = ProveOutcome::kProblem;
    out->why = scan_verdict_;
    return true;
  }

  std::vector<Checkpoint> cps;
  Verdict cv;
  if (!read_checkpoints(&cps, &cv, err)) {
    return false;
  }
  if (!cv.ok()) {
    out->outcome = ProveOutcome::kProblem;
    out->why = cv;
    return true;
  }

  if (index >= record_count_) {
    out->outcome = ProveOutcome::kOutOfRange;
    out->detail = "index " + std::to_string(index) + " is past the end: the " +
                  "log holds " + std::to_string(record_count_) + " record(s)";
    return true;
  }

  const uint64_t bs = header_.block_size;
  const uint64_t block = index / bs;
  if (block >= cps.size()) {
    // A proof is only meaningful against a root somebody already trusts, and
    // the records in the block being filled have no root yet. Inventing an
    // ephemeral one would produce a proof against a value that is published
    // nowhere, which proves nothing.
    out->outcome = ProveOutcome::kNotSealed;
    if (cps.empty()) {
      out->detail = "no block has been sealed yet; the first checkpoint lands "
                    "at record " + std::to_string(bs - 1);
    } else {
      out->detail = "index " + std::to_string(index) +
                    " is in the block being filled; the last sealed index is " +
                    std::to_string(cps.back().last_index);
    }
    return true;
  }

  const Checkpoint cp = cps[static_cast<size_t>(block)];
  if (cp.first_index != block * bs || cp.leaf_count() != bs) {
    out->outcome = ProveOutcome::kProblem;
    out->why.problem = Problem::kBadCheckpoint;
    out->why.index = block * bs;
    out->why.detail = "checkpoint " + std::to_string(block) + " covers " +
                      std::to_string(cp.first_index) + ".." +
                      std::to_string(cp.last_index) +
                      ", which is not block " + std::to_string(block);
    return true;
  }

  // Walk to the block and recompute its record hashes. O(n) in the records
  // before the block, because frames are variable-length and there is no
  // offset index -- see docs/FORMAT.md on why a separate index file was not
  // added. The walk stops as soon as the block ends.
  uint64_t len = 0;
  if (!file_length(log_fd_.get(), &len, err)) {
    return false;
  }
  FrameCursor cur(log_fd_.get(), kHeaderBytes, len);
  Record r;
  uint64_t off = 0;
  Problem p = Problem::kOk;
  std::string detail;

  std::vector<Digest> leaves;
  leaves.reserve(static_cast<size_t>(bs));
  uint64_t pos = 0;
  bool found = false;

  while (pos <= cp.last_index) {
    const Step s = cur.next(&r, &off, &p, &detail, err);
    if (s == Step::kIoError) {
      return false;
    }
    if (s == Step::kEndOfLog) {
      break;
    }
    if (s == Step::kProblem) {
      out->outcome = ProveOutcome::kProblem;
      out->why.problem = p;
      out->why.index = pos;
      out->why.offset = off;
      out->why.detail = detail;
      return true;
    }
    if (pos >= cp.first_index) {
      leaves.push_back(compute_record_hash(r));
      if (pos == index) {
        out->record = r;
        found = true;
      }
    }
    ++pos;
  }

  if (!found || leaves.size() != bs) {
    out->outcome = ProveOutcome::kProblem;
    out->why.problem = Problem::kBadCheckpoint;
    out->why.index = cp.first_index;
    out->why.detail = "block " + std::to_string(block) + " should hold " +
                      std::to_string(bs) + " records but only " +
                      std::to_string(leaves.size()) + " were readable";
    return true;
  }

  const MerkleTree tree = MerkleTree::build(leaves);
  if (tree.root() != cp.root) {
    // Refuse to hand out a proof that is already known not to verify. A tool
    // that emitted it anyway would be shifting the discovery of tampering
    // onto whoever checks the proof later.
    out->outcome = ProveOutcome::kProblem;
    out->why.problem = Problem::kBadCheckpoint;
    out->why.index = cp.first_index;
    out->why.detail = "block " + std::to_string(block) +
                      " hashes to " + to_hex(tree.root()) +
                      " but its checkpoint says " + to_hex(cp.root);
    return true;
  }

  if (!merkle_prove(tree, index - cp.first_index, &out->proof)) {
    out->outcome = ProveOutcome::kProblem;
    out->why.problem = Problem::kBadCheckpoint;
    out->why.index = index;
    out->why.detail = "leaf " + std::to_string(index - cp.first_index) +
                      " is outside the rebuilt tree";
    return true;
  }

  out->checkpoint = cp;
  out->outcome = ProveOutcome::kOk;
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
  s.checkpoint_count = checkpoint_count_;
  s.pending_records =
      (header_.block_size == 0) ? 0 : record_count_ % header_.block_size;
  return s;
}

}  // namespace chainlog
