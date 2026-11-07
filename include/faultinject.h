// Deliberate crash points, for the crash-recovery tests.
//
// Gated on $CHAINLOG_CRASH_AT and compiled into the release binary on
// purpose. The crash tests have to exercise the binary that ships: a
// -DFAULT_INJECTION build would test code paths that nobody actually runs,
// which is the opposite of what a crash test is for.
//
// The exposure this adds is real but narrow: someone who can set environment
// variables in your process can make appends die. Someone who can set your
// environment variables can also replace the binary, so this is not the weak
// link. $CHAINLOG_CRASH_AT is never set in normal operation, and an
// unrecognised value is a hard error rather than a silent no-op -- a typo in
// a test script must not quietly test nothing.
#ifndef CHAINLOG_FAULTINJECT_H
#define CHAINLOG_FAULTINJECT_H

namespace chainlog {

enum class CrashPoint {
  kNone,
  kAfterWalWrite,       // the record is durable in the WAL, not in the log
  kAfterMainWrite,      // durable in the log, checkpoint not sealed, WAL full
  kBeforeWalTruncate,   // durable in the log, checkpoint sealed, WAL full
};

// Exit status used by the injected crash. Distinct from the CLI's 0/1/2 so a
// test can tell "died where I asked" from any real outcome.
constexpr int kCrashExitStatus = 99;

// Parses $CHAINLOG_CRASH_AT once, on first call. An unrecognised value writes
// a message to stderr and exits 2.
CrashPoint configured_crash_point();

// Terminates the process immediately if `at` is the configured crash point.
//
// Uses _exit(2), not exit(3), and the difference matters. exit() runs atexit
// handlers and flushes stdio, so a buffered "index=7 hash=..." line would
// still reach the caller -- the process would report a successful append and
// then vanish, which is not a crash, it is a lie. _exit() is the closest
// thing available to pulling the power: no handlers, no destructors, no
// flushes, nothing closed.
void crash_if_configured(CrashPoint at);

}  // namespace chainlog

#endif  // CHAINLOG_FAULTINJECT_H
