#!/usr/bin/env bash
#
# Crash-recovery tests.
#
# Kills the real binary at each of the three points in the append protocol,
# restarts it, and asserts that the log is consistent and that the record is
# present exactly once -- never lost, never duplicated.
#
# The crash points are compiled into the shipping binary and selected with
# $CHAINLOG_CRASH_AT. The injected exit uses _exit(99): no atexit handlers, no
# stdio flush, nothing closed. If it used exit(3) the buffered "index=..."
# line would still reach the caller, and the process would report a successful
# append and then vanish -- which is not a crash, it is a lie.
#
# What is being tested is the difference between DETECTABLE and RECOVERABLE. A
# crash inside the main write leaves a torn frame that the hash chain notices,
# but the chain cannot know whether that record was ever meant to exist. The
# WAL holds that answer.
#
# Usage: tests/crash.sh [path-to-chainlog]

set -uo pipefail

CLI="${1:-build/release/chainlog}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PARSER="$HERE/oracle_format.py"

if [ ! -x "$CLI" ]; then
  echo "crash: $CLI not found or not executable (run 'make' first)" >&2
  exit 2
fi
case "$CLI" in
  /*) ;;
  *) CLI="$PWD/$CLI" ;;
esac

TMP="$(mktemp -d "${TMPDIR:-/tmp}/chainlog-crash.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

checks=0
fails=0

fail() {
  echo "FAIL $1" >&2
  fails=$((fails + 1))
}

note() {
  printf '  %s\n' "$1"
}

# count_bytes <file> <needle> -- exact occurrence count, binary safe.
count_bytes() {
  python3 -I -c '
import sys
print(open(sys.argv[1], "rb").read().count(sys.argv[2].encode()))
' "$1" "$2"
}

records_in() {
  "$CLI" --dir "$1" stats 2>/dev/null | sed -n 's/^records=//p'
}

checkpoints_in() {
  "$CLI" --dir "$1" stats 2>/dev/null | sed -n 's/^checkpoints=//p'
}

wal_size() {
  wc -c <"$1/log.wal" | tr -d ' '
}

# fresh_log <dir> <n> [extra CLI args...]
fresh_log() {
  local dir="$1"
  local n="$2"
  shift 2
  local i=0
  while [ "$i" -lt "$n" ]; do
    "$CLI" --dir "$dir" "$@" append "rec-$i" >/dev/null || return 1
    i=$((i + 1))
  done
}

# expect_eq <got> <want> <label>
expect_eq() {
  checks=$((checks + 1))
  if [ "$1" != "$2" ]; then
    fail "$3: got \"$1\", wanted \"$2\""
  fi
}

WAL_EMPTY=32  # the WAL header alone

echo "crash: testing $CLI"

# --- the three crash points ------------------------------------------------
#
# All three must end with the record present exactly once. That is a choice,
# not an accident: a complete frame in the WAL means step 1's fsync returned,
# so the record was durable before the main log was touched, and redo is the
# correct resolution.

for POINT in after_wal_write after_main_write before_wal_truncate; do
  D="$TMP/point-$POINT"
  fresh_log "$D" 5 || fail "could not build the log for $POINT"

  expect_eq "$(records_in "$D")" "5" "$POINT: five records before the crash"
  expect_eq "$(wal_size "$D")" "$WAL_EMPTY" "$POINT: WAL empty before the crash"

  # The crash itself.
  checks=$((checks + 1))
  CHAINLOG_CRASH_AT="$POINT" "$CLI" --dir "$D" append "crash-me" \
    >/dev/null 2>&1
  RC=$?
  if [ "$RC" -ne 99 ]; then
    fail "$POINT: expected exit 99 from the injected crash, got $RC"
  fi

  # The WAL must still hold the staged frame: step 3 never ran.
  checks=$((checks + 1))
  if [ "$(wal_size "$D")" = "$WAL_EMPTY" ]; then
    fail "$POINT: the WAL was cleared, so no crash was injected"
  fi

  # The intermediate state differs per point, and that is the whole reason
  # for having three of them.
  RAW_LOG_HITS="$(count_bytes "$D/log" "crash-me")"
  case "$POINT" in
    after_wal_write)
      expect_eq "$RAW_LOG_HITS" "0" \
        "$POINT: the record must not be in the log yet"
      ;;
    after_main_write|before_wal_truncate)
      expect_eq "$RAW_LOG_HITS" "1" \
        "$POINT: the record must already be in the log"
      ;;
  esac

  # Restart: opening the log recovers it.
  checks=$((checks + 1))
  if ! "$CLI" --dir "$D" verify >/dev/null 2>&1; then
    fail "$POINT: the log does not verify after recovery"
    "$CLI" --dir "$D" verify 2>&1 | sed 's/^/       /' >&2
  fi

  expect_eq "$(records_in "$D")" "6" "$POINT: six records after recovery"
  expect_eq "$(count_bytes "$D/log" "crash-me")" "1" \
    "$POINT: the record is present exactly once"
  expect_eq "$(wal_size "$D")" "$WAL_EMPTY" \
    "$POINT: the WAL is cleared by recovery"

  # An independent implementation must agree.
  checks=$((checks + 1))
  if ! python3 -I "$PARSER" "$D" >/dev/null 2>&1; then
    fail "$POINT: the python oracle rejects the recovered log"
  fi

  # Recovery must be idempotent: opening again changes nothing.
  BEFORE="$(wc -c <"$D/log" | tr -d ' ')"
  "$CLI" --dir "$D" verify >/dev/null 2>&1
  expect_eq "$(wc -c <"$D/log" | tr -d ' ')" "$BEFORE" \
    "$POINT: a second open changed the log"

  # And appending afterwards continues the chain.
  checks=$((checks + 1))
  if ! "$CLI" --dir "$D" append "after-recovery" >/dev/null 2>&1; then
    fail "$POINT: cannot append after recovery"
  fi
  expect_eq "$(records_in "$D")" "7" "$POINT: seven records after appending"
  note "$POINT: ok"
done

# --- crashing on the record that completes a block -------------------------
#
# The checkpoint interacts with the WAL here. Sealing happens after the
# record's fsync and before the WAL is cleared, so after_main_write leaves the
# block unsealed while before_wal_truncate leaves it sealed -- two genuinely
# different states, both of which must recover to the same place.

for POINT in after_wal_write after_main_write before_wal_truncate; do
  D="$TMP/seal-$POINT"
  fresh_log "$D" 3 --block-size 4 || fail "could not build the log"
  expect_eq "$(checkpoints_in "$D")" "0" "$POINT: nothing sealed yet"

  checks=$((checks + 1))
  CHAINLOG_CRASH_AT="$POINT" "$CLI" --dir "$D" --block-size 4 \
    append "seals-the-block" >/dev/null 2>&1
  RC=$?
  if [ "$RC" -ne 99 ]; then
    fail "$POINT (boundary): expected exit 99, got $RC"
  fi

  # Whatever the intermediate state, recovery must land on four records and
  # exactly one sealed checkpoint.
  checks=$((checks + 1))
  if ! "$CLI" --dir "$D" verify >/dev/null 2>&1; then
    fail "$POINT (boundary): does not verify after recovery"
    "$CLI" --dir "$D" verify 2>&1 | sed 's/^/       /' >&2
  fi
  expect_eq "$(records_in "$D")" "4" "$POINT (boundary): four records"
  expect_eq "$(checkpoints_in "$D")" "1" \
    "$POINT (boundary): the block is sealed after recovery"
  expect_eq "$(count_bytes "$D/log" "seals-the-block")" "1" \
    "$POINT (boundary): the record is present exactly once"

  checks=$((checks + 1))
  if ! python3 -I "$PARSER" "$D" >/dev/null 2>&1; then
    fail "$POINT (boundary): the python oracle rejects the recovered log"
  fi
  note "$POINT at a block boundary: ok"
done

# --- a torn WAL frame is dropped, not replayed -----------------------------
#
# This is why the WAL frame carries its own CRC. A half-written staged record
# must be distinguishable from a complete one: step 1's fsync had not returned,
# so append() never reported success and nobody was told the record existed.
# Replaying it would invent a record the caller never got an acknowledgement
# for; dropping it is correct.

D="$TMP/torn-wal"
fresh_log "$D" 4 || fail "could not build the log"
CHAINLOG_CRASH_AT=after_wal_write "$CLI" --dir "$D" append "never-promised" \
  >/dev/null 2>&1
FULL_WAL="$(wal_size "$D")"
checks=$((checks + 1))
if [ "$FULL_WAL" = "$WAL_EMPTY" ]; then
  fail "torn WAL: setup failed, nothing was staged"
fi

# Cut the staged frame at every byte inside it. Each one must be dropped.
CUT=$((WAL_EMPTY + 1))
while [ "$CUT" -lt "$FULL_WAL" ]; do
  cp "$D/log.wal" "$TMP/wal.full"
  dd if="$TMP/wal.full" of="$D/log.wal" bs=1 count="$CUT" status=none
  checks=$((checks + 1))
  if ! "$CLI" --dir "$D" verify >/dev/null 2>&1; then
    fail "torn WAL cut at $CUT: the log does not verify"
  fi
  expect_eq "$(records_in "$D")" "4" "torn WAL cut at $CUT: no record added"
  expect_eq "$(wal_size "$D")" "$WAL_EMPTY" \
    "torn WAL cut at $CUT: the WAL was not cleared"
  cp "$TMP/wal.full" "$D/log.wal"
  CUT=$((CUT + 17))
done
note "a torn WAL frame is dropped at every cut point: ok"

# A WAL whose own header is damaged is reported rather than guessed at.
cp "$TMP/wal.full" "$D/log.wal"
printf 'X' | dd of="$D/log.wal" bs=1 seek=3 count=1 conv=notrunc status=none
checks=$((checks + 1))
if "$CLI" --dir "$D" verify >/dev/null 2>&1; then
  fail "a corrupt WAL header was accepted"
fi
# Note the capture-then-grep: `chainlog stats` exits 1 on a damaged log, and
# under `set -o pipefail` a pipeline inherits that, so `cli | grep` would look
# like a failed grep no matter what it matched.
STATS_OUT="$("$CLI" --dir "$D" stats 2>&1)"
checks=$((checks + 1))
if ! printf '%s' "$STATS_OUT" | grep -q "bad-wal"; then
  fail "a corrupt WAL header was not reported as bad-wal"
  printf '%s\n' "$STATS_OUT" | sed 's/^/       /' >&2
fi
note "a corrupt WAL header is reported: ok"

# --- a WAL that does not fit the log it sits beside ------------------------
#
# A crash cannot produce this: the WAL holds at most one record and is cleared
# before the next append begins. So an intact staged frame that does not link
# to the log's tail means one of the two files was edited.

DA="$TMP/donor"
DB="$TMP/recipient"
fresh_log "$DA" 10 || fail "could not build the donor log"
CHAINLOG_CRASH_AT=after_wal_write "$CLI" --dir "$DA" append "donor-record" \
  >/dev/null 2>&1
fresh_log "$DB" 3 || fail "could not build the recipient log"
cp "$DA/log.wal" "$DB/log.wal"

checks=$((checks + 1))
if "$CLI" --dir "$DB" verify >/dev/null 2>&1; then
  fail "a WAL from another log was accepted"
fi
STATS_OUT="$("$CLI" --dir "$DB" stats 2>&1)"
checks=$((checks + 1))
if ! printf '%s' "$STATS_OUT" | grep -q "bad-wal"; then
  fail "a mismatched WAL was not reported as bad-wal"
  printf '%s\n' "$STATS_OUT" | sed 's/^/       /' >&2
fi
# And it must refuse to append rather than build on a state it cannot explain.
checks=$((checks + 1))
if "$CLI" --dir "$DB" append "should-not-land" >/dev/null 2>&1; then
  fail "appended to a log with a mismatched WAL"
fi
expect_eq "$(count_bytes "$DB/log" "donor-record")" "0" \
  "the donor record must not have been replayed"
note "a mismatched WAL is reported as bad-wal: ok"

# --- crash, recover, crash, recover ... ------------------------------------
#
# One recovery working proves little if the recovered state cannot itself be
# crashed. Twelve rounds, rotating through the crash points.

D="$TMP/repeat"
fresh_log "$D" 1 || fail "could not build the log"
EXPECTED=1
ROUND=0
POINTS="after_wal_write after_main_write before_wal_truncate"
while [ "$ROUND" -lt 12 ]; do
  # shellcheck disable=SC2086
  set -- $POINTS
  IDX=$((ROUND % 3 + 1))
  eval "POINT=\${$IDX}"

  CHAINLOG_CRASH_AT="$POINT" "$CLI" --dir "$D" append "round-$ROUND" \
    >/dev/null 2>&1
  RC=$?
  checks=$((checks + 1))
  if [ "$RC" -ne 99 ]; then
    fail "repeat round $ROUND ($POINT): exit $RC, wanted 99"
  fi
  EXPECTED=$((EXPECTED + 1))

  checks=$((checks + 1))
  if ! "$CLI" --dir "$D" verify >/dev/null 2>&1; then
    fail "repeat round $ROUND ($POINT): does not verify"
    break
  fi
  expect_eq "$(records_in "$D")" "$EXPECTED" \
    "repeat round $ROUND ($POINT): record count"
  expect_eq "$(count_bytes "$D/log" "round-$ROUND")" "1" \
    "repeat round $ROUND ($POINT): exactly one copy"

  ROUND=$((ROUND + 1))
done
checks=$((checks + 1))
if ! python3 -I "$PARSER" "$D" >/dev/null 2>&1; then
  fail "the python oracle rejects the log after 12 crash rounds"
fi
note "12 crash-and-recover rounds: ok"

# --- flock ------------------------------------------------------------------
#
# Two writers must not interleave. The lock is taken with LOCK_NB, so the
# second process is told the log is busy rather than being queued behind an
# appender that might run for hours.

D="$TMP/locked"
fresh_log "$D" 2 || fail "could not build the log"

python3 -I -c '
import fcntl, sys, time
f = open(sys.argv[1], "a+")
fcntl.flock(f, fcntl.LOCK_EX)
sys.stderr.write("held\n")
sys.stderr.flush()
time.sleep(10)
' "$D/lock" 2>"$TMP/holder.err" &
HOLDER=$!

# Wait for the holder to actually have the lock.
WAITED=0
while [ "$WAITED" -lt 50 ] && ! grep -q held "$TMP/holder.err" 2>/dev/null; do
  sleep 0.1
  WAITED=$((WAITED + 1))
done

checks=$((checks + 1))
if ! grep -q held "$TMP/holder.err" 2>/dev/null; then
  fail "could not set up the lock holder"
else
  OUT="$("$CLI" --dir "$D" append "contended" 2>&1)"
  RC=$?
  checks=$((checks + 1))
  if [ "$RC" -ne 2 ]; then
    fail "a contended append exited $RC, wanted 2"
  fi
  checks=$((checks + 1))
  if ! printf '%s' "$OUT" | grep -q "another chainlog process"; then
    fail "the lock error does not name the problem: $OUT"
  fi
  expect_eq "$(count_bytes "$D/log" "contended")" "0" \
    "a refused append must not write anything"
fi

kill "$HOLDER" 2>/dev/null
wait "$HOLDER" 2>/dev/null

# With the lock released, the same append succeeds.
checks=$((checks + 1))
if ! "$CLI" --dir "$D" append "uncontended" >/dev/null 2>&1; then
  fail "the append still fails after the lock was released"
fi
note "an exclusive flock keeps a second writer out: ok"

# --- a read-only log is still verifiable ------------------------------------
#
# Refusing to look at a log you cannot write would make the verifier useless
# in exactly the situation where you most want it: inspecting an archive.

D="$TMP/readonly"
fresh_log "$D" 6 --block-size 4 || fail "could not build the log"
chmod a-w "$D/log" "$D/checkpoints" "$D/log.wal" "$D"
checks=$((checks + 1))
if ! "$CLI" --dir "$D" verify >/dev/null 2>&1; then
  fail "a read-only log does not verify"
fi
STATS_OUT="$("$CLI" --dir "$D" stats 2>/dev/null)"
checks=$((checks + 1))
if ! printf '%s' "$STATS_OUT" | grep -q "^read_only=1$"; then
  fail "stats does not report read_only=1"
fi
checks=$((checks + 1))
if "$CLI" --dir "$D" append "nope" >/dev/null 2>&1; then
  fail "appended to a read-only log"
fi
chmod u+w "$D" "$D/log" "$D/checkpoints" "$D/log.wal"
note "a read-only log verifies but refuses appends: ok"

# --- a mistyped crash point is loud ----------------------------------------
# A silent no-op here would make every test above pass while injecting
# nothing at all.

D="$TMP/badpoint"
checks=$((checks + 1))
OUT="$(CHAINLOG_CRASH_AT=after_the_pub "$CLI" --dir "$D" append "x" 2>&1)"
RC=$?
if [ "$RC" -ne 2 ]; then
  fail "a mistyped CHAINLOG_CRASH_AT exited $RC, wanted 2"
fi
checks=$((checks + 1))
if ! printf '%s' "$OUT" | grep -q "is not a crash point"; then
  fail "a mistyped CHAINLOG_CRASH_AT was not reported: $OUT"
fi
note "a mistyped crash point is a hard error: ok"

echo "crash: $checks check(s), $fails failure(s)"
if [ "$fails" -ne 0 ]; then
  exit 1
fi
echo "crash: OK"
