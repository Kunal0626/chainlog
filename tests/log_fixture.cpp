#include "log_fixture.h"

#include "checkpoint.h"
#include "log.h"
#include "merkle.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <dirent.h>
#include <unistd.h>

namespace chainlog_test {
namespace {

void die(const std::string& msg) {
  std::fprintf(stderr, "test fixture: %s\n", msg.c_str());
  std::abort();
}

}  // namespace

TempDir::TempDir() {
  const char* base = std::getenv("TMPDIR");
  std::string tmpl =
      (base != nullptr && base[0] != '\0') ? std::string(base) : "/tmp";
  if (tmpl.back() != '/') {
    tmpl.push_back('/');
  }
  tmpl += "chainlog-test-XXXXXX";

  std::vector<char> buf(tmpl.begin(), tmpl.end());
  buf.push_back('\0');
  const char* made = ::mkdtemp(buf.data());
  if (made == nullptr) {
    die("mkdtemp failed");
  }
  path_ = made;
}

TempDir::~TempDir() {
  // Shallow removal is enough: a log directory never contains subdirectories.
  DIR* d = ::opendir(path_.c_str());
  if (d != nullptr) {
    for (struct dirent* e = ::readdir(d); e != nullptr; e = ::readdir(d)) {
      const std::string name = e->d_name;
      if (name == "." || name == "..") {
        continue;
      }
      ::unlink((path_ + "/" + name).c_str());
    }
    ::closedir(d);
  }
  ::rmdir(path_.c_str());
}

std::string read_file(const std::string& path) {
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (f == nullptr) {
    die("cannot open " + path);
  }
  std::string out;
  char buf[65536];
  while (true) {
    const size_t n = std::fread(buf, 1, sizeof(buf), f);
    out.append(buf, n);
    if (n < sizeof(buf)) {
      break;
    }
  }
  std::fclose(f);
  return out;
}

void write_file(const std::string& path, const std::string& bytes) {
  std::FILE* f = std::fopen(path.c_str(), "wb");
  if (f == nullptr) {
    die("cannot write " + path);
  }
  if (!bytes.empty() &&
      std::fwrite(bytes.data(), 1, bytes.size(), f) != bytes.size()) {
    die("short write to " + path);
  }
  std::fclose(f);
}

std::vector<FrameSpan> frame_spans(const std::string& bytes) {
  std::vector<FrameSpan> out;
  uint64_t off = chainlog::kHeaderBytes;
  while (off + 8 <= bytes.size()) {
    const uint8_t* p =
        reinterpret_cast<const uint8_t*>(bytes.data()) + off;
    uint32_t payload_len = 0;
    std::string detail;
    if (chainlog::parse_frame_header(p, &payload_len, &detail) !=
        chainlog::Problem::kOk) {
      break;
    }
    const uint64_t frame_len = chainlog::kFrameOverheadBytes + payload_len;
    if (off + frame_len > bytes.size()) {
      break;
    }
    out.push_back({off, frame_len});
    off += frame_len;
  }
  return out;
}

std::vector<chainlog::Record> read_frames(const std::string& bytes) {
  std::vector<chainlog::Record> out;
  const std::vector<FrameSpan> spans = frame_spans(bytes);
  for (size_t i = 0; i < spans.size(); ++i) {
    chainlog::Record r;
    std::string detail;
    if (chainlog::decode_frame(bytes.data() + spans[i].offset,
                               static_cast<size_t>(spans[i].length), &r,
                               nullptr, &detail) != chainlog::Problem::kOk) {
      die("frame " + std::to_string(i) + " will not decode: " + detail);
    }
    out.push_back(r);
  }
  return out;
}

void rewrite_frame(std::string* bytes, uint64_t offset,
                   const chainlog::Record& r) {
  std::string frame;
  chainlog::append_frame(r, &frame);

  const uint8_t* p = reinterpret_cast<const uint8_t*>(bytes->data()) + offset;
  uint32_t old_payload_len = 0;
  std::string detail;
  if (chainlog::parse_frame_header(p, &old_payload_len, &detail) !=
      chainlog::Problem::kOk) {
    die("no frame at offset " + std::to_string(offset));
  }
  const uint64_t old_len = chainlog::kFrameOverheadBytes + old_payload_len;
  if (old_len != frame.size()) {
    die("rewrite_frame would change the frame length (" +
        std::to_string(old_len) + " -> " + std::to_string(frame.size()) + ")");
  }
  bytes->replace(static_cast<size_t>(offset), frame.size(), frame);
}

void relink_from(std::string* bytes, uint64_t from_index) {
  const std::vector<FrameSpan> spans = frame_spans(*bytes);
  std::vector<chainlog::Record> records = read_frames(*bytes);
  if (from_index >= records.size()) {
    die("relink_from past the end of the log");
  }

  // The hash the first rewritten record must link to: whatever its
  // predecessor's hash currently is (recomputed, not taken from the field).
  chainlog::Digest prev = chainlog::genesis_prev_hash();
  if (from_index > 0) {
    prev = chainlog::compute_record_hash(records[from_index - 1]);
  }

  for (size_t i = static_cast<size_t>(from_index); i < records.size(); ++i) {
    records[i].prev_hash = prev;
    records[i].hash = chainlog::compute_record_hash(records[i]);
    rewrite_frame(bytes, spans[i].offset, records[i]);
    prev = records[i].hash;
  }
}

std::string record_label(uint64_t i) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "rec-%06llu",
                static_cast<unsigned long long>(i));
  return buf;
}

void build_log(const std::string& dir, uint64_t n, uint64_t block_size) {
  chainlog::Log log;
  chainlog::Log::Options opt;
  opt.block_size = block_size;
  std::string err;
  if (!log.open(dir, opt, &err)) {
    die("build_log: open failed: " + err);
  }
  for (uint64_t i = 0; i < n; ++i) {
    chainlog::Record r;
    if (!log.append(record_label(i), &r, &err)) {
      die("build_log: append failed: " + err);
    }
  }
}

chainlog::Verdict verify_dir(const std::string& dir) {
  chainlog::Log log;
  chainlog::Log::Options opt;
  std::string err;
  if (!log.open(dir, opt, &err)) {
    die("verify_dir: open failed: " + err);
  }
  chainlog::Verdict v;
  if (!log.verify(&v, &err)) {
    die("verify_dir: verify failed: " + err);
  }
  return v;
}

void reseal_all_checkpoints(const std::string& dir) {
  const std::string log_bytes = read_file(chainlog::Log::log_path(dir));

  chainlog::Header h;
  std::string detail;
  if (chainlog::decode_header(log_bytes.data(), log_bytes.size(), &h,
                              &detail) != chainlog::Problem::kOk) {
    die("reseal_all_checkpoints: bad log header: " + detail);
  }
  const uint64_t bs = h.block_size;

  const std::vector<chainlog::Record> records = read_frames(log_bytes);

  chainlog::CheckpointHeader ch;
  ch.block_size = bs;
  std::string out;
  chainlog::encode_checkpoint_header(ch, &out);

  std::vector<chainlog::Digest> block;
  for (size_t i = 0; i < records.size(); ++i) {
    block.push_back(chainlog::compute_record_hash(records[i]));
    if (block.size() == bs) {
      chainlog::Checkpoint c;
      c.first_index = records[i].index + 1 - bs;
      c.last_index = records[i].index;
      c.root = chainlog::merkle_root(block);
      chainlog::append_checkpoint_frame(c, &out);
      block.clear();
    }
  }
  write_file(chainlog::Log::checkpoints_path(dir), out);
}

}  // namespace chainlog_test
