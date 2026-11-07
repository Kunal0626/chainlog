#include "faultinject.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <unistd.h>

namespace chainlog {
namespace {

CrashPoint parse_crash_point() {
  const char* env = std::getenv("CHAINLOG_CRASH_AT");
  if (env == nullptr || env[0] == '\0') {
    return CrashPoint::kNone;
  }
  if (std::strcmp(env, "after_wal_write") == 0) {
    return CrashPoint::kAfterWalWrite;
  }
  if (std::strcmp(env, "after_main_write") == 0) {
    return CrashPoint::kAfterMainWrite;
  }
  if (std::strcmp(env, "before_wal_truncate") == 0) {
    return CrashPoint::kBeforeWalTruncate;
  }
  // Loud, not silent. A mistyped crash point in a test script would
  // otherwise make the test pass while injecting no fault at all.
  std::fprintf(stderr,
               "chainlog: CHAINLOG_CRASH_AT=\"%s\" is not a crash point.\n"
               "Valid values: after_wal_write, after_main_write, "
               "before_wal_truncate\n",
               env);
  std::exit(2);
}

}  // namespace

CrashPoint configured_crash_point() {
  // Read once: the tests set this before exec, and re-reading per append
  // would let a long-running process change behaviour mid-flight.
  static const CrashPoint point = parse_crash_point();
  return point;
}

void crash_if_configured(CrashPoint at) {
  if (at == CrashPoint::kNone || configured_crash_point() != at) {
    return;
  }
  // No message: a power cut does not announce itself, and anything written
  // here would have to be flushed, which is exactly what we are avoiding.
  ::_exit(kCrashExitStatus);
}

}  // namespace chainlog
