#!/usr/bin/env bash
#
# Cross-check ChainLog's hand-written CRC-32 against python3's zlib.crc32.
#
# Same reasoning as tests/oracle_sha256.sh: the implementation is ours, the
# reference is somebody else's. A table-driven CRC with the wrong polynomial
# or the wrong reflection is perfectly self-consistent and completely wrong.
#
# Usage: tests/oracle_crc32.sh [path-to-cl-crc32]

set -euo pipefail

CL="${1:-build/release/cl-crc32}"

if [ ! -x "$CL" ]; then
  echo "oracle-crc32: $CL not found or not executable (run 'make' first)" >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "oracle-crc32: python3 not found; cannot cross-check" >&2
  exit 2
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/chainlog-oracle-crc.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

checks=0
fails=0

compare_file() {
  local file="$1"
  local label="$2"

  local ours ref
  ours="$("$CL" <"$file")"
  ref="$(python3 -c '
import sys, zlib
sys.stdout.write("%08x" % (zlib.crc32(open(sys.argv[1], "rb").read()) & 0xffffffff))
' "$file")"

  checks=$((checks + 1))
  if [ "$ours" != "$ref" ]; then
    echo "FAIL $label: cl-crc32=$ours zlib=$ref" >&2
    fails=$((fails + 1))
  fi
}

make_random() {
  local len="$1"
  local out="$2"
  if [ "$len" -eq 0 ]; then
    : >"$out"
  else
    head -c "$len" /dev/urandom >"$out"
  fi
}

echo "oracle-crc32: cross-checking $CL against python zlib"

# Every length 0..64 catches off-by-ones in the byte loop, then a spread of
# larger sizes, then random lengths.
len=0
while [ "$len" -le 64 ]; do
  make_random "$len" "$TMP/len_$len"
  compare_file "$TMP/len_$len" "random len=$len"
  len=$((len + 1))
done

for len in 255 256 257 1024 65536 1048576; do
  make_random "$len" "$TMP/big_$len"
  compare_file "$TMP/big_$len" "random len=$len"
done

i=0
while [ "$i" -lt 15 ]; do
  len=$(( (RANDOM * 32768 + RANDOM) % 100000 ))
  make_random "$len" "$TMP/rand_$i"
  compare_file "$TMP/rand_$i" "random len=$len (run $i)"
  i=$((i + 1))
done

echo "oracle-crc32: $checks comparison(s), $fails failure(s)"
if [ "$fails" -ne 0 ]; then
  exit 1
fi
echo "oracle-crc32: OK"
