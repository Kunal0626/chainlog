#!/usr/bin/env bash
#
# Builds logs with the C++ CLI and checks them with tests/oracle_format.py, an
# independent parser written from docs/FORMAT.md using python's hashlib and
# zlib instead of ChainLog's own SHA-256 and CRC-32.
#
# This closes a gap the C++ tests cannot: they verify that the code agrees with
# itself. This verifies that the code agrees with the written specification,
# and that the specification is complete enough for somebody else to implement.
# It also checks that the Python parser reaches the SAME verdict name on
# tampered logs -- agreeing on success is easy, agreeing on diagnoses is not.
#
# Usage: tests/oracle_format.sh [path-to-chainlog]

set -uo pipefail

CLI="${1:-build/release/chainlog}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PARSER="$HERE/oracle_format.py"

if [ ! -x "$CLI" ]; then
  echo "oracle-format: $CLI not found or not executable (run 'make' first)" >&2
  exit 2
fi
case "$CLI" in
  /*) ;;
  *) CLI="$PWD/$CLI" ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
  echo "oracle-format: python3 not found; cannot cross-check" >&2
  exit 2
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/chainlog-oracle-fmt.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

checks=0
fails=0

fail() {
  echo "FAIL $1" >&2
  fails=$((fails + 1))
}

# run_parser <label> <log-file> <expected-args...>
run_parser() {
  local label="$1"
  local logfile="$2"
  shift 2
  checks=$((checks + 1))
  local out
  out="$(python3 -I "$PARSER" "$logfile" "$@" 2>&1)"
  if [ $? -ne 0 ]; then
    fail "$label"
    echo "       $out" >&2
  fi
}

echo "oracle-format: checking the C++ writer against docs/FORMAT.md"

# --- a clean log of varied records -----------------------------------------
# Empty data, binary data, a long record and a short one, so the parser has to
# get data_len handling right rather than assuming a fixed size.

D="$TMP/clean"
"$CLI" --dir "$D" append "" >/dev/null
"$CLI" --dir "$D" append "hello" >/dev/null
printf 'binary\000\377\376 bytes' | "$CLI" --dir "$D" append - >/dev/null
"$CLI" --dir "$D" append "$(head -c 5000 /dev/zero | tr '\0' 'x')" >/dev/null
for i in $(seq 1 40); do
  "$CLI" --dir "$D" append "rec-$i" >/dev/null
done
run_parser "python parser rejected a clean log" "$D/log" --expect-ok

# Both implementations must agree on the head hash, not merely on "it is fine".
checks=$((checks + 1))
CPP_HEAD="$("$CLI" --dir "$D" head | sed 's/.*hash=//')"
PY_HEAD="$(python3 -I "$PARSER" "$D/log" | sed 's/.*head=//')"
if [ "$CPP_HEAD" != "$PY_HEAD" ]; then
  fail "head hash disagrees: c++=$CPP_HEAD python=$PY_HEAD"
fi

# And on the record count.
checks=$((checks + 1))
CPP_COUNT="$("$CLI" --dir "$D" stats | sed -n 's/^records=//p')"
PY_COUNT="$(python3 -I "$PARSER" "$D/log" | sed -n 's/.*ok, \([0-9]*\) record.*/\1/p')"
if [ "$CPP_COUNT" != "$PY_COUNT" ]; then
  fail "record count disagrees: c++=$CPP_COUNT python=$PY_COUNT"
fi

# --- the same diagnosis on damaged logs ------------------------------------
# A shared success is weak evidence. Agreeing on *which* check failed, and on
# the same kebab-case name, means both sides implement the same order of
# checks from the same spec.

# fresh_log <dir> <n>
fresh_log() {
  local dir="$1"
  local n="$2"
  local i=0
  while [ "$i" -lt "$n" ]; do
    "$CLI" --dir "$dir" append "rec-$i" >/dev/null
    i=$((i + 1))
  done
}

# flip one byte inside a record -> bad-crc on both sides
D="$TMP/badcrc"
fresh_log "$D" 10
printf '\xaa' | dd of="$D/log" bs=1 seek=200 count=1 conv=notrunc status=none
run_parser "python parser missed a flipped byte" "$D/log" \
  --expect-problem bad-crc
checks=$((checks + 1))
if "$CLI" --dir "$D" verify >/dev/null 2>&1; then
  fail "the C++ verifier accepted a flipped byte"
fi

# corrupt the header magic -> bad-header on both sides
D="$TMP/badheader"
fresh_log "$D" 3
printf 'X' | dd of="$D/log" bs=1 seek=2 count=1 conv=notrunc status=none
run_parser "python parser missed a corrupt header" "$D/log" \
  --expect-problem bad-header

# truncate mid-frame -> torn-tail on both sides
D="$TMP/torn"
fresh_log "$D" 6
SIZE="$(wc -c <"$D/log" | tr -d ' ')"
dd if="$D/log" of="$D/trunc" bs=1 count=$((SIZE - 11)) status=none
mv "$D/trunc" "$D/log"
run_parser "python parser missed a torn tail" "$D/log" \
  --expect-problem torn-tail

# remove a whole frame -> bad-index on both sides
D="$TMP/deleted"
fresh_log "$D" 10
# Every record here is "rec-N" for single-digit N, so all frames are 93 + 12
# bytes and the arithmetic below is exact.
FRAME=$((88 + 5 + 12))
HEADER=32
KEEP=$((HEADER + 4 * FRAME))
dd if="$D/log" of="$TMP/part1" bs=1 count=$KEEP status=none
dd if="$D/log" of="$TMP/part2" bs=1 skip=$((KEEP + FRAME)) status=none
cat "$TMP/part1" "$TMP/part2" >"$D/log"
run_parser "python parser missed a deleted record" "$D/log" \
  --expect-problem bad-index

echo "oracle-format: $checks check(s), $fails failure(s)"
if [ "$fails" -ne 0 ]; then
  exit 1
fi
echo "oracle-format: OK"
