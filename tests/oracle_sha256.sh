#!/usr/bin/env bash
#
# Cross-check ChainLog's hand-written SHA-256 against the system's
# implementations.
#
# ChainLog's SHA-256 is the thing under test. shasum(1) and openssl(1) are only
# oracles: the project brief forbids using a library for the hash itself, but
# comparing against one is exactly how you find out whether yours is right.
#
# Why a shell script instead of more C++ unit tests: to check absolute
# correctness at 40-odd different input lengths you need 40-odd reference
# digests. Hardcoding those in a .cpp file means typing them in from somewhere,
# and a digest typed in by hand is a test that can be confidently wrong. Asking
# two independent implementations on this machine is a stronger check and
# scales to as many random inputs as you care to run.
#
# Usage: tests/oracle_sha256.sh [path-to-cl-sha256]

set -euo pipefail

CL="${1:-build/release/cl-sha256}"

if [ ! -x "$CL" ]; then
  echo "oracle: $CL not found or not executable (run 'make' first)" >&2
  exit 2
fi

# --- pick the oracles ------------------------------------------------------
# shasum ships with macOS; openssl is LibreSSL here. Use whichever exist, and
# refuse to "pass" with none of them -- a test that silently checks nothing is
# worse than no test.

have_shasum=0
have_openssl=0
command -v shasum >/dev/null 2>&1 && have_shasum=1
command -v openssl >/dev/null 2>&1 && have_openssl=1

if [ "$have_shasum" -eq 0 ] && [ "$have_openssl" -eq 0 ]; then
  echo "oracle: neither shasum nor openssl found; cannot cross-check" >&2
  exit 2
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/chainlog-oracle.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

checks=0
fails=0

# Hash $1 with every available oracle and with cl-sha256 (at several chunk
# sizes), and report any disagreement.
compare_file() {
  local file="$1"
  local label="$2"

  local ours
  ours="$("$CL" <"$file")"

  if [ "$have_shasum" -eq 1 ]; then
    local ref
    ref="$(shasum -a 256 <"$file" | awk '{print $1}')"
    checks=$((checks + 1))
    if [ "$ours" != "$ref" ]; then
      echo "FAIL $label: cl-sha256=$ours shasum=$ref" >&2
      fails=$((fails + 1))
    fi
  fi

  if [ "$have_openssl" -eq 1 ]; then
    local ref
    ref="$(openssl dgst -sha256 <"$file" | awk '{print $NF}')"
    checks=$((checks + 1))
    if [ "$ours" != "$ref" ]; then
      echo "FAIL $label: cl-sha256=$ours openssl=$ref" >&2
      fails=$((fails + 1))
    fi
  fi

  # Same input through the streaming path with awkward buffer sizes. These must
  # all agree with the one-shot result above; if they do not, update()'s block
  # buffering is broken for this length.
  local chunk
  for chunk in 1 7 63 64 65; do
    local streamed
    streamed="$("$CL" --chunk "$chunk" <"$file")"
    checks=$((checks + 1))
    if [ "$streamed" != "$ours" ]; then
      echo "FAIL $label: chunk=$chunk gave $streamed, expected $ours" >&2
      fails=$((fails + 1))
    fi
  done
}

# BSD head(1) on macOS rejects `-c 0`, so zero-length input gets its own path.
# A zero-length message is not an edge case to skip: it is the one input whose
# digest is entirely padding.
make_random() {
  local len="$1"
  local out="$2"
  if [ "$len" -eq 0 ]; then
    : >"$out"
  else
    head -c "$len" /dev/urandom >"$out"
  fi
}

echo "oracle: cross-checking $CL"
echo "oracle: oracles -> shasum=$have_shasum openssl=$have_openssl"

# --- 1. the published NIST vectors -----------------------------------------
# These are also pinned in tests/test_sha256.cpp. Running them through the
# oracles too means the expected digests in the C++ tests are themselves
# checked against an independent implementation, rather than trusted.

printf '' >"$TMP/nist_empty"
printf 'abc' >"$TMP/nist_abc"
printf 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' >"$TMP/nist_448"
printf 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu' >"$TMP/nist_896"
head -c 1000000 /dev/zero | tr '\0' 'a' >"$TMP/nist_million_a"

for f in nist_empty nist_abc nist_448 nist_896 nist_million_a; do
  compare_file "$TMP/$f" "$f"
done

# --- 2. every length around the padding boundaries -------------------------
# Padding needs 9 spare bytes (0x80 marker + 8-byte bit length), so a final
# block holding 55 bytes fits and 56 spills into another block. Walking every
# length from 0 to 130 covers both boundaries twice and every block edge in
# between, which is where off-by-ones in finish() live.

len=0
while [ "$len" -le 130 ]; do
  make_random "$len" "$TMP/len_$len"
  compare_file "$TMP/len_$len" "random len=$len"
  len=$((len + 1))
done

# --- 3. random inputs at larger sizes --------------------------------------
# Multi-block messages, including sizes that are exact multiples of 64 and
# sizes that are not, plus a few megabyte-scale inputs.

for len in 191 192 193 255 256 257 1023 1024 1025 4096 65535 65536 65537 1048576 3145728; do
  make_random "$len" "$TMP/big_$len"
  compare_file "$TMP/big_$len" "random len=$len"
done

# --- 4. random lengths, random content -------------------------------------
# A handful of unpredictable sizes so repeated runs are not testing the exact
# same shapes every time.

i=0
while [ "$i" -lt 20 ]; do
  len=$(( (RANDOM * 32768 + RANDOM) % 200000 ))
  make_random "$len" "$TMP/rand_$i"
  compare_file "$TMP/rand_$i" "random len=$len (run $i)"
  i=$((i + 1))
done

echo "oracle: $checks comparison(s), $fails failure(s)"
if [ "$fails" -ne 0 ]; then
  exit 1
fi
echo "oracle: OK"
