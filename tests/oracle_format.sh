#!/usr/bin/env bash
#
# Builds logs with the C++ CLI and checks them with tests/oracle_format.py, an
# independent implementation written from docs/FORMAT.md using python's hashlib
# and zlib instead of ChainLog's own SHA-256 and CRC-32, and RFC 6962's
# recursive MTH/PATH instead of the iterative level-by-level build.
#
# This closes a gap the C++ tests cannot: they verify that the code agrees with
# itself. This verifies that the code agrees with the written specification,
# and that the specification is complete enough for somebody else to
# implement. Three things are compared, in increasing strength:
#
#   1. both sides accept a clean log, and agree on the head hash and count
#   2. both sides reach the SAME kebab-case diagnosis on damaged logs
#   3. both sides emit BYTE-IDENTICAL inclusion proofs
#
# (3) is the strongest: agreeing on a proof's bytes means the iterative tree
# really is RFC 6962's tree, not merely some tree, and that the wire format is
# unambiguous down to the last flag byte.
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

py() {
  python3 -I "$PARSER" "$@"
}

# run_parser <label> <log-dir> <expected-args...>
run_parser() {
  local label="$1"
  local dir="$2"
  shift 2
  checks=$((checks + 1))
  local out
  if ! out="$(py "$dir" "$@" 2>&1)"; then
    fail "$label"
    echo "       $out" >&2
  fi
}

# fresh_log <dir> <n> [block-size-args...]
fresh_log() {
  local dir="$1"
  local n="$2"
  shift 2
  local i=0
  while [ "$i" -lt "$n" ]; do
    "$CLI" --dir "$dir" "$@" append "rec-$i" >/dev/null
    i=$((i + 1))
  done
}

echo "oracle-format: checking the C++ writer against docs/FORMAT.md"

# --- 1. a clean log of varied records --------------------------------------
# Empty data, binary data, a long record and short ones, so the parser has to
# get data_len handling right rather than assuming a fixed size.

D="$TMP/clean"
"$CLI" --dir "$D" append "" >/dev/null
"$CLI" --dir "$D" append "hello" >/dev/null
printf 'binary\000\377\376 bytes' | "$CLI" --dir "$D" append - >/dev/null
"$CLI" --dir "$D" append "$(head -c 5000 /dev/zero | tr '\0' 'x')" >/dev/null
fresh_log "$D" 40
run_parser "python rejected a clean log" "$D" --expect-ok

checks=$((checks + 1))
CPP_HEAD="$("$CLI" --dir "$D" head | sed 's/.*hash=//')"
PY_HEAD="$(py "$D" | sed 's/.*head=//')"
if [ "$CPP_HEAD" != "$PY_HEAD" ]; then
  fail "head hash disagrees: c++=$CPP_HEAD python=$PY_HEAD"
fi

checks=$((checks + 1))
CPP_COUNT="$("$CLI" --dir "$D" stats | sed -n 's/^records=//p')"
PY_COUNT="$(py "$D" | sed -n 's/.*ok, \([0-9]*\) record.*/\1/p')"
if [ "$CPP_COUNT" != "$PY_COUNT" ]; then
  fail "record count disagrees: c++=$CPP_COUNT python=$PY_COUNT"
fi

# --- 2. checkpoints and Merkle roots ---------------------------------------
# A small block size so plenty of blocks actually seal. The python side
# rebuilds each root with the recursive RFC 6962 MTH and compares.

D="$TMP/sealed"
fresh_log "$D" 70 --block-size 8
run_parser "python rejected the sealed roots" "$D" --expect-ok

checks=$((checks + 1))
CPP_CKPTS="$("$CLI" --dir "$D" stats | sed -n 's/^checkpoints=//p')"
PY_CKPTS="$(py "$D" | sed -n 's/.*ok, [0-9]* record(s), \([0-9]*\) checkpoint.*/\1/p')"
if [ "$CPP_CKPTS" != "$PY_CKPTS" ] || [ "$CPP_CKPTS" != "8" ]; then
  fail "checkpoint count disagrees: c++=$CPP_CKPTS python=$PY_CKPTS (want 8)"
fi

# Every sealed root, line by line.
checks=$((checks + 1))
if ! "$CLI" --dir "$D" checkpoints >"$TMP/cpp_roots.txt"; then
  fail "chainlog checkpoints failed"
fi
checks=$((checks + 1))
if [ "$(wc -l <"$TMP/cpp_roots.txt" | tr -d ' ')" != "8" ]; then
  fail "expected 8 checkpoint lines, got $(wc -l <"$TMP/cpp_roots.txt")"
fi

# --- 3. byte-identical inclusion proofs ------------------------------------
# The iterative level-by-level build versus RFC 6962's recursive PATH. If
# promotion were implemented as duplication, or the domain-separation
# prefixes were wrong, or the flag encoding differed by a byte, these would
# not match.

for idx in 0 1 7 8 15 31 32 63; do
  checks=$((checks + 1))
  CPP_PROOF="$("$CLI" --dir "$D" prove "$idx" | sed -n 's/^proof=//p')"
  PY_PROOF="$(py "$D" --prove "$idx" | sed -n 's/^proof=//p')"
  if [ -z "$CPP_PROOF" ]; then
    fail "chainlog prove $idx produced no proof"
  elif [ "$CPP_PROOF" != "$PY_PROOF" ]; then
    fail "proof for index $idx differs between implementations"
    echo "       c++:    $CPP_PROOF" >&2
    echo "       python: $PY_PROOF" >&2
  fi
done

# And the C++ standalone verifier must accept the proof python built.
for idx in 3 11 60; do
  checks=$((checks + 1))
  PROVE="$("$CLI" --dir "$D" prove "$idx")"
  PY_PROOF="$(py "$D" --prove "$idx" | sed -n 's/^proof=//p')"
  ROOT="$(printf '%s' "$PROVE" | sed -n 's/^root=//p')"
  DATA="$(printf '%s' "$PROVE" | sed -n 's/^data_hex=//p')"
  TS="$(printf '%s' "$PROVE" | sed -n 's/^timestamp_ns=//p')"
  PREV="$(printf '%s' "$PROVE" | sed -n 's/^prev_hash=//p')"
  if ! "$CLI" verify-proof "$idx" "hex:$DATA" "$ROOT" "$PY_PROOF" \
       --timestamp "$TS" --prev-hash "$PREV" >/dev/null 2>&1; then
    fail "the C++ verifier rejected python's proof for index $idx"
  fi
done

# --- 4. the same diagnosis on damaged logs ---------------------------------
# A shared success is weak evidence. Agreeing on *which* check failed, with
# the same kebab-case name, means both sides implement the same order of
# checks from the same spec.

# flip one byte inside a record -> bad-crc
D="$TMP/badcrc"
fresh_log "$D" 10
printf '\xaa' | dd of="$D/log" bs=1 seek=200 count=1 conv=notrunc status=none
run_parser "python missed a flipped byte" "$D" --expect-problem bad-crc
checks=$((checks + 1))
if "$CLI" --dir "$D" verify >/dev/null 2>&1; then
  fail "the C++ verifier accepted a flipped byte"
fi

# corrupt the header magic -> bad-header
D="$TMP/badheader"
fresh_log "$D" 3
printf 'X' | dd of="$D/log" bs=1 seek=2 count=1 conv=notrunc status=none
run_parser "python missed a corrupt header" "$D" --expect-problem bad-header

# truncate mid-frame -> torn-tail
D="$TMP/torn"
fresh_log "$D" 6
SIZE="$(wc -c <"$D/log" | tr -d ' ')"
dd if="$D/log" of="$D/trunc" bs=1 count=$((SIZE - 11)) status=none
mv "$D/trunc" "$D/log"
run_parser "python missed a torn tail" "$D" --expect-problem torn-tail

# remove a whole frame -> bad-index
D="$TMP/deleted"
fresh_log "$D" 10
# Every record here is "rec-N" for single-digit N, so all frames are 88+5+12.
FRAME=$((88 + 5 + 12))
KEEP=$((32 + 4 * FRAME))
dd if="$D/log" of="$TMP/part1" bs=1 count=$KEEP status=none
dd if="$D/log" of="$TMP/part2" bs=1 skip=$((KEEP + FRAME)) status=none
cat "$TMP/part1" "$TMP/part2" >"$D/log"
run_parser "python missed a deleted record" "$D" --expect-problem bad-index

# edit a checkpoint root -> bad-checkpoint
D="$TMP/badroot"
fresh_log "$D" 16 --block-size 8
# The root sits at offset 20 inside the second checkpoint's payload.
CKPT_FRAME=$((12 + 52))
printf '\x5a' | dd of="$D/checkpoints" bs=1 \
  seek=$((32 + CKPT_FRAME + 8 + 20)) count=1 conv=notrunc status=none
run_parser "python missed an edited root" "$D" --expect-problem bad-checkpoint
checks=$((checks + 1))
if "$CLI" --dir "$D" verify >/dev/null 2>&1; then
  fail "the C++ verifier accepted an edited checkpoint root"
fi

# re-link the log but leave the sealed roots stale -> bad-checkpoint.
# This is the attack the chain alone could not see in phase 2.
D="$TMP/relinked"
fresh_log "$D" 24 --block-size 8
checks=$((checks + 1))
if ! python3 -I - "$D" <<'PY'
import hashlib, struct, sys
path = sys.argv[1] + "/log"
blob = bytearray(open(path, "rb").read())

# Walk the frames, note their offsets.
spans, off = [], 32
while off < len(blob):
    plen = struct.unpack_from("<I", blob, off + 4)[0]
    spans.append((off, 12 + plen, plen))
    off += 12 + plen

import zlib
def reframe(at, plen, payload):
    blob[at + 8:at + 8 + plen] = payload
    struct.pack_into("<I", blob, at + 8 + plen, zlib.crc32(payload) & 0xffffffff)

# Edit record 9's data in place (same length), then re-link everything after.
prev = None
for i, (at, flen, plen) in enumerate(spans):
    payload = bytearray(blob[at + 8:at + 8 + plen])
    dlen = struct.unpack_from("<Q", payload, 16)[0]
    if i == 9:
        payload[24:24 + dlen] = b"HACKED".ljust(dlen, b"!")[:dlen]
    if i >= 9:
        if prev is not None:
            payload[24 + dlen:24 + dlen + 32] = prev
        h = hashlib.sha256(bytes(payload[:24 + dlen + 32])).digest()
        payload[24 + dlen + 32:24 + dlen + 64] = h
        reframe(at, plen, bytes(payload))
        prev = h
    else:
        prev = bytes(payload[24 + dlen + 32:24 + dlen + 64])
open(path, "wb").write(bytes(blob))
PY
then
  fail "could not re-link the log for the stale-root check"
fi
run_parser "python missed a re-linked log" "$D" --expect-problem bad-checkpoint
checks=$((checks + 1))
if "$CLI" --dir "$D" verify >/dev/null 2>&1; then
  fail "the C++ verifier accepted a re-linked log with stale roots"
fi

echo "oracle-format: $checks check(s), $fails failure(s)"
if [ "$fails" -ne 0 ]; then
  exit 1
fi
echo "oracle-format: OK"
