// chainlog -- command line interface.
//
// Phase 2 subset: append, verify, head, stats. Merkle proofs, checkpoints and
// --anchor arrive in later phases; this is deliberately the smallest CLI that
// makes the hash chain usable and testable by hand.
//
// Exit codes are part of the interface, because the demo and the crash tests
// branch on them:
//   0  the operation succeeded / the log verified
//   1  the log did NOT verify (tampering or damage was detected)
//   2  usage error, or an I/O failure that prevented checking at all
//
// Keeping 1 and 2 apart matters: "I checked and it is bad" and "I could not
// check" are different answers, and a script that treats them alike will
// eventually report a permissions problem as a security incident.

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "hex.h"
#include "log.h"

namespace {

constexpr int kExitOk = 0;
constexpr int kExitTamper = 1;
constexpr int kExitUsage = 2;

void usage() {
  std::fprintf(stderr,
               "usage: chainlog [--dir DIR] <command>\n"
               "\n"
               "commands:\n"
               "  append <data>   append a record containing <data>\n"
               "  append -        append a record containing all of stdin\n"
               "  verify          recompute the whole chain\n"
               "  head            index and hash of the last record\n"
               "  stats           record count and sizes\n"
               "\n"
               "options:\n"
               "  --dir DIR       log directory (default: $CHAINLOG_DIR, "
               "else ./chainlog.d)\n"
               "  --block-size N  records per sealed block, new logs only "
               "(default: %llu)\n"
               "\n"
               "exit codes: 0 ok, 1 verification failed, 2 usage/IO error\n",
               static_cast<unsigned long long>(chainlog::kDefaultBlockSize));
}

// Reads all of stdin into a string. Records are arbitrary bytes, so this must
// not stop at a NUL or translate newlines.
bool read_stdin(std::string* out, std::string* err) {
  char buf[65536];
  while (true) {
    const size_t n = std::fread(buf, 1, sizeof(buf), stdin);
    if (n > 0) {
      out->append(buf, n);
    }
    if (n < sizeof(buf)) {
      if (std::ferror(stdin) != 0) {
        *err = "read error on stdin";
        return false;
      }
      return true;
    }
  }
}

// Printed for any command run against a log whose open-time scan found
// damage. Exit code 1 ("this log does not check out") rather than 2 ("I could
// not check"), because the damage *was* detected -- a script that sees 2 here
// would read a real finding as an infrastructure problem.
int report_damaged(const chainlog::Log& log) {
  std::fprintf(stderr, "chainlog: log does not check out: %s\n",
               log.scan_verdict().message().c_str());
  return kExitTamper;
}

int cmd_append(chainlog::Log* log, const std::string& arg) {
  std::string data;
  std::string err;
  if (arg == "-") {
    if (!read_stdin(&data, &err)) {
      std::fprintf(stderr, "chainlog: %s\n", err.c_str());
      return kExitUsage;
    }
  } else {
    data = arg;
  }

  chainlog::Record r;
  if (!log->append(data, &r, &err)) {
    std::fprintf(stderr, "chainlog: %s\n", err.c_str());
    // Refusing to extend a damaged chain is a detection, not an I/O failure.
    return log->scan_verdict().ok() ? kExitUsage : kExitTamper;
  }
  std::printf("index=%llu hash=%s\n", static_cast<unsigned long long>(r.index),
              chainlog::to_hex(r.hash).c_str());
  return kExitOk;
}

int cmd_verify(const chainlog::Log& log) {
  chainlog::Verdict v;
  std::string err;
  if (!log.verify(&v, &err)) {
    std::fprintf(stderr, "chainlog: %s\n", err.c_str());
    return kExitUsage;
  }
  if (v.ok()) {
    std::printf("%s\n", v.message().c_str());
    return kExitOk;
  }
  std::fprintf(stderr, "chainlog: verification FAILED: %s\n",
               v.message().c_str());
  std::fprintf(stderr, "chainlog: %llu record(s) verified before the failure\n",
               static_cast<unsigned long long>(v.records_verified));
  return kExitTamper;
}

int cmd_head(const chainlog::Log& log) {
  chainlog::Record r;
  if (!log.head(&r)) {
    std::printf("empty\n");
    return kExitOk;
  }
  std::printf("index=%llu hash=%s\n", static_cast<unsigned long long>(r.index),
              chainlog::to_hex(r.hash).c_str());
  return kExitOk;
}

int cmd_stats(const chainlog::Log& log) {
  const chainlog::Log::Stats s = log.stats();
  std::printf("records=%llu\n", static_cast<unsigned long long>(s.record_count));
  std::printf("log_bytes=%llu\n", static_cast<unsigned long long>(s.log_bytes));
  std::printf("data_bytes=%llu\n",
              static_cast<unsigned long long>(s.data_bytes));
  std::printf("block_size=%llu\n",
              static_cast<unsigned long long>(s.block_size));
  std::printf("sealed_blocks=%llu\n",
              static_cast<unsigned long long>(s.sealed_blocks));
  return kExitOk;
}

}  // namespace

int main(int argc, char** argv) {
  std::string dir = chainlog::Log::default_dir();
  chainlog::Log::Options opt;

  int i = 1;
  for (; i < argc; ++i) {
    if (std::strcmp(argv[i], "--dir") == 0 && i + 1 < argc) {
      dir = argv[++i];
    } else if (std::strcmp(argv[i], "--block-size") == 0 && i + 1 < argc) {
      const long long n = std::atoll(argv[++i]);
      if (n <= 0) {
        std::fprintf(stderr, "chainlog: --block-size must be positive\n");
        return kExitUsage;
      }
      opt.block_size = static_cast<uint64_t>(n);
    } else if (std::strcmp(argv[i], "--help") == 0 ||
               std::strcmp(argv[i], "-h") == 0) {
      usage();
      return kExitOk;
    } else {
      break;  // First non-option argument is the command.
    }
  }

  if (i >= argc) {
    usage();
    return kExitUsage;
  }
  const std::string cmd = argv[i++];

  chainlog::Log log;
  std::string err;
  if (!log.open(dir, opt, &err)) {
    std::fprintf(stderr, "chainlog: %s\n", err.c_str());
    return kExitUsage;
  }

  if (cmd == "append") {
    if (i >= argc) {
      std::fprintf(stderr, "chainlog: append needs <data> or -\n");
      return kExitUsage;
    }
    return cmd_append(&log, argv[i]);
  }
  if (cmd == "verify") {
    return cmd_verify(log);
  }
  if (cmd == "head" || cmd == "stats") {
    // Still print what can be read, so the operator has something to work
    // with, but exit non-zero so a script cannot mistake a damaged log for a
    // healthy one just because `head` happened to succeed.
    const int rc = (cmd == "head") ? cmd_head(log) : cmd_stats(log);
    if (rc == kExitOk && !log.scan_verdict().ok()) {
      return report_damaged(log);
    }
    return rc;
  }

  std::fprintf(stderr, "chainlog: unknown command \"%s\"\n", cmd.c_str());
  usage();
  return kExitUsage;
}
