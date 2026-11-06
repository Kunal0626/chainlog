#!/usr/bin/env bash
#
# End-to-end checks on the chainlog CLI: output shapes and exit codes.
#
# The unit tests drive the library directly. This script drives the binary,
# because the exit codes and the printed lines are an interface too -- the
# tamper demo and the crash tests branch on them, and a change that breaks
# `cut -d= -f2` breaks the demo without breaking a single unit test.
#
# Usage: tests/cli.sh [path-to-chainlog]

set -uo pipefail

CLI="${1:-build/release/chainlog}"

if [ ! -x "$CLI" ]; then
  echo "cli: $CLI not found or not executable (run 'make' first)" >&2
  exit 2
fi
# Resolve to an absolute path: the tests cd into a temp directory.
case "$CLI" in
  /*) ;;
  *) CLI="$PWD/$CLI" ;;
esac

TMP="$(mktemp -d "${TMPDIR:-/tmp}/chainlog-cli.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

checks=0
fails=0

fail() {
  echo "FAIL $1" >&2
  fails=$((fails + 1))
}

# Runs the CLI and checks its exit code.
# expect_exit <code> <label> <args...>
expect_exit() {
  local want="$1"
  local label="$2"
  shift 2
  checks=$((checks + 1))
  local out
  out="$("$CLI" "$@" 2>&1)"
  local got=$?
  if [ "$got" -ne "$want" ]; then
    fail "$label: exit $got, wanted $want"
    echo "       output: $out" >&2
  fi
}

# expect_stdout_match <regex> <label> <args...>
expect_stdout_match() {
  local pattern="$1"
  local label="$2"
  shift 2
  checks=$((checks + 1))
  local out
  out="$("$CLI" "$@" 2>/dev/null)"
  if ! printf '%s' "$out" | grep -Eq "$pattern"; then
    fail "$label: stdout did not match /$pattern/"
    echo "       output: $out" >&2
  fi
}

# expect_stderr_match <regex> <label> <args...>
expect_stderr_match() {
  local pattern="$1"
  local label="$2"
  shift 2
  checks=$((checks + 1))
  local errout
  errout="$("$CLI" "$@" 2>&1 >/dev/null)"
  if ! printf '%s' "$errout" | grep -Eq "$pattern"; then
    fail "$label: stderr did not match /$pattern/"
    echo "       stderr: $errout" >&2
  fi
}

echo "cli: testing $CLI"

HEX64='[0-9a-f]{64}'

# --- usage and help --------------------------------------------------------

expect_exit 0 "--help exits 0" --help
expect_exit 2 "no command is a usage error" --dir "$TMP/unused"
expect_exit 2 "unknown command is a usage error" --dir "$TMP/unused" frobnicate
expect_exit 2 "append with no argument is a usage error" --dir "$TMP/unused" append
expect_exit 2 "--block-size 0 is rejected" --dir "$TMP/unused" --block-size 0 stats

# --- an empty log ----------------------------------------------------------

D="$TMP/empty"
expect_stdout_match "^records=0$" "fresh log has no records" --dir "$D" stats
expect_stdout_match "^empty$" "fresh log has no head" --dir "$D" head
expect_exit 0 "fresh log verifies" --dir "$D" verify
expect_stdout_match "^ok: 0 record" "fresh log reports zero verified" --dir "$D" verify

checks=$((checks + 1))
for f in log; do
  if [ ! -f "$D/$f" ]; then
    fail "opening a log did not create $f"
  fi
done

# --- appending -------------------------------------------------------------

D="$TMP/basic"
expect_stdout_match "^index=0 hash=$HEX64$" "first append is index 0" \
  --dir "$D" append "hello"
expect_stdout_match "^index=1 hash=$HEX64$" "second append is index 1" \
  --dir "$D" append "world"

# Appending from stdin, including bytes that are not text.
checks=$((checks + 1))
if ! printf 'line one\nline two\n\000binary\377' | "$CLI" --dir "$D" append - \
     | grep -Eq "^index=2 hash=$HEX64$"; then
  fail "append - did not read stdin"
fi

expect_stdout_match "^index=2 hash=$HEX64$" "head follows the last append" \
  --dir "$D" head
expect_stdout_match "^records=3$" "stats counts three records" --dir "$D" stats
expect_exit 0 "a clean log verifies" --dir "$D" verify

# head and the last append must agree on the hash.
checks=$((checks + 1))
LAST_APPEND="$("$CLI" --dir "$D" append "fourth" | sed 's/.*hash=//')"
HEAD_HASH="$("$CLI" --dir "$D" head | sed 's/.*hash=//')"
if [ "$LAST_APPEND" != "$HEAD_HASH" ]; then
  fail "head hash ($HEAD_HASH) differs from the appended hash ($LAST_APPEND)"
fi

# --- $CHAINLOG_DIR ---------------------------------------------------------

checks=$((checks + 1))
if ! CHAINLOG_DIR="$TMP/viaenv" "$CLI" append "env" \
     | grep -Eq "^index=0 hash=$HEX64$"; then
  fail "CHAINLOG_DIR was not honoured"
fi
checks=$((checks + 1))
if [ ! -f "$TMP/viaenv/log" ]; then
  fail "CHAINLOG_DIR did not create the log in the right place"
fi

# An explicit --dir must win over the environment.
checks=$((checks + 1))
if ! CHAINLOG_DIR="$TMP/viaenv" "$CLI" --dir "$TMP/viaflag" append "flag" \
     | grep -Eq "^index=0 "; then
  fail "--dir did not override CHAINLOG_DIR"
fi

# --- block size persists ---------------------------------------------------

D="$TMP/blocks"
expect_exit 0 "create with --block-size 4" --dir "$D" --block-size 4 append "a"
for i in 2 3 4 5; do
  "$CLI" --dir "$D" append "rec-$i" >/dev/null
done
expect_stdout_match "^block_size=4$" "block_size came from the file header" \
  --dir "$D" stats
expect_stdout_match "^sealed_blocks=1$" "5 records at block size 4 seals one" \
  --dir "$D" stats

# --- tampering -------------------------------------------------------------

D="$TMP/tampered"
for i in 0 1 2 3 4 5 6 7 8 9; do
  "$CLI" --dir "$D" append "rec-$i" >/dev/null
done
expect_exit 0 "ten records verify before tampering" --dir "$D" verify

# Flip one byte well past the header, inside a record.
checks=$((checks + 1))
if ! printf '\xff' | dd of="$D/log" bs=1 seek=200 count=1 conv=notrunc \
     status=none 2>/dev/null; then
  fail "could not flip a byte in the log"
fi

expect_exit 1 "a tampered log exits 1, not 2" --dir "$D" verify
expect_stderr_match "verification FAILED" "verify says so on stderr" \
  --dir "$D" verify
expect_stderr_match "at index [0-9]+" "verify names the first bad index" \
  --dir "$D" verify

# Appending to a damaged log must be refused, and must not grow the file.
BEFORE="$(wc -c <"$D/log")"
expect_exit 1 "append to a damaged log exits 1" --dir "$D" append "more"
checks=$((checks + 1))
AFTER="$(wc -c <"$D/log")"
if [ "$BEFORE" != "$AFTER" ]; then
  fail "a refused append still changed the file ($BEFORE -> $AFTER bytes)"
fi

# head and stats still print, but must not claim the log is fine.
expect_exit 1 "head on a damaged log exits 1" --dir "$D" head
expect_exit 1 "stats on a damaged log exits 1" --dir "$D" stats

# --- a torn tail -----------------------------------------------------------

D="$TMP/torn"
for i in 0 1 2 3 4; do
  "$CLI" --dir "$D" append "rec-$i" >/dev/null
done
checks=$((checks + 1))
SIZE="$(wc -c <"$D/log" | tr -d ' ')"
if ! dd if="$D/log" of="$D/log.trunc" bs=1 count=$((SIZE - 9)) status=none \
     2>/dev/null; then
  fail "could not truncate the log"
fi
mv "$D/log.trunc" "$D/log"
expect_exit 1 "a torn tail exits 1" --dir "$D" verify
expect_stderr_match "torn-tail" "a torn tail is named as such" --dir "$D" verify

# --- a corrupt header ------------------------------------------------------

D="$TMP/badheader"
"$CLI" --dir "$D" append "x" >/dev/null
checks=$((checks + 1))
if ! printf 'X' | dd of="$D/log" bs=1 seek=2 count=1 conv=notrunc \
     status=none 2>/dev/null; then
  fail "could not corrupt the header"
fi
expect_exit 1 "a corrupt header exits 1" --dir "$D" verify
expect_stderr_match "bad-header" "a corrupt header is named as such" \
  --dir "$D" verify

# --- unreadable directory is an I/O error, not a tamper report -------------
# The distinction the exit codes exist for: "I could not check" must never be
# reported as "I checked and it is bad".

D="$TMP/noperm"
mkdir -p "$D"
"$CLI" --dir "$D" append "x" >/dev/null
chmod 000 "$D/log"
expect_exit 2 "an unreadable log is exit 2, not 1" --dir "$D" verify
chmod 644 "$D/log"

echo "cli: $checks check(s), $fails failure(s)"
if [ "$fails" -ne 0 ]; then
  exit 1
fi
echo "cli: OK"
