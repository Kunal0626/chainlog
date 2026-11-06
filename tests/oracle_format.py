#!/usr/bin/env python3
"""Independent parser for the ChainLog v1 on-disk format.

This is an oracle, not a utility. It was written from docs/FORMAT.md rather
than from the C++ source, and it uses Python's own hashlib and zlib instead of
ChainLog's hand-written SHA-256 and CRC-32. If the C++ implementation and the
specification drift apart, this disagrees with one of them and `make oracle`
fails.

It answers a question the C++ tests structurally cannot: is the format
actually specified well enough for somebody else to implement it? A test suite
written against the same code it tests will happily agree with a format that
only exists in that code's head.

Usage:
    oracle_format.py <log-file> [--expect-ok | --expect-problem NAME]

Exit codes mirror the CLI: 0 the log checks out, 1 it does not, 2 usage error.
"""

import hashlib
import struct
import sys
import zlib

HEADER_BYTES = 32
HEADER_MAGIC = b"CHAINLOG"
FORMAT_VERSION = 1

FRAME_MAGIC = b"CHLG"
FRAME_OVERHEAD = 12          # magic(4) + payload_len(4) + crc32(4)
PAYLOAD_FIXED = 8 + 8 + 8 + 32 + 32   # 88
MAX_DATA_LEN = 16 * 1024 * 1024

GENESIS_PREV_HASH = b"\x00" * 32


class Bad(Exception):
    """A log that does not check out. .problem is the kebab-case name."""

    def __init__(self, problem, index, offset, detail):
        super().__init__("%s at index %d (byte offset %d): %s"
                         % (problem, index, offset, detail))
        self.problem = problem
        self.index = index
        self.offset = offset
        self.detail = detail


def crc(data):
    return zlib.crc32(data) & 0xFFFFFFFF


def parse_header(blob):
    if len(blob) < HEADER_BYTES:
        raise Bad("bad-header", 0, 0, "file shorter than the 32-byte header")
    head = blob[:HEADER_BYTES]
    if head[:8] != HEADER_MAGIC:
        raise Bad("bad-header", 0, 0, "magic is not CHAINLOG")
    # CRC before any other field is trusted, including the version.
    stored = struct.unpack_from("<I", head, 28)[0]
    if stored != crc(head[:28]):
        raise Bad("bad-header", 0, 0, "header crc32 mismatch")

    version, flags = struct.unpack_from("<II", head, 8)
    block_size = struct.unpack_from("<Q", head, 16)[0]
    reserved = struct.unpack_from("<I", head, 24)[0]

    if version != FORMAT_VERSION:
        raise Bad("bad-header", 0, 0, "format version %d" % version)
    if flags != 0 or reserved != 0:
        raise Bad("bad-header", 0, 0, "reserved bits are set")
    if block_size == 0:
        raise Bad("bad-header", 0, 0, "block_size is 0")
    return {"version": version, "flags": flags, "block_size": block_size}


def verify(blob):
    """Walks the whole log. Returns (record_count, head_hash_hex, header)."""
    header = parse_header(blob)

    offset = HEADER_BYTES
    expected_index = 0
    prev_hash = GENESIS_PREV_HASH
    last_hash = None

    while offset < len(blob):
        remaining = len(blob) - offset
        if remaining < 8:
            raise Bad("torn-tail", expected_index, offset,
                      "%d byte(s) left, too few for a frame prologue"
                      % remaining)

        if blob[offset:offset + 4] != FRAME_MAGIC:
            raise Bad("bad-magic", expected_index, offset,
                      "frame does not start with CHLG")

        payload_len = struct.unpack_from("<I", blob, offset + 4)[0]
        if payload_len < PAYLOAD_FIXED:
            raise Bad("bad-frame-length", expected_index, offset,
                      "payload length %d below the minimum" % payload_len)
        if payload_len - PAYLOAD_FIXED > MAX_DATA_LEN:
            raise Bad("bad-frame-length", expected_index, offset,
                      "payload length %d over the data limit" % payload_len)

        frame_len = FRAME_OVERHEAD + payload_len
        if remaining < frame_len:
            raise Bad("torn-tail", expected_index, offset,
                      "frame claims %d bytes, only %d left"
                      % (frame_len, remaining))

        payload = blob[offset + 8:offset + 8 + payload_len]
        stored_crc = struct.unpack_from("<I", blob, offset + 8 + payload_len)[0]
        if stored_crc != crc(payload):
            raise Bad("bad-crc", expected_index, offset,
                      "crc32 stored %08x, computed %08x"
                      % (stored_crc, crc(payload)))

        index, _timestamp, data_len = struct.unpack_from("<QQQ", payload, 0)
        if data_len > MAX_DATA_LEN or data_len + PAYLOAD_FIXED != payload_len:
            raise Bad("bad-frame-length", expected_index, offset,
                      "data_len %d disagrees with payload length %d"
                      % (data_len, payload_len))

        cut = 24 + data_len
        record_prev = payload[cut:cut + 32]
        record_hash = payload[cut + 32:cut + 64]
        preimage = payload[:cut + 32]

        if index != expected_index:
            raise Bad("bad-index", expected_index, offset,
                      "expected index %d, frame says %d"
                      % (expected_index, index))
        if record_prev != prev_hash:
            raise Bad("broken-link", expected_index, offset,
                      "prev_hash does not match the previous record's hash")

        computed = hashlib.sha256(preimage).digest()
        if computed != record_hash:
            raise Bad("bad-hash", expected_index, offset,
                      "stored hash is not the hash of this record's bytes")

        # Chain on the recomputed hash, as the spec requires.
        prev_hash = computed
        last_hash = computed
        expected_index += 1
        offset += frame_len

    head_hex = last_hash.hex() if last_hash is not None else None
    return expected_index, head_hex, header


def main(argv):
    expect_ok = False
    expect_problem = None
    path = None

    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "--expect-ok":
            expect_ok = True
        elif arg == "--expect-problem" and i + 1 < len(argv):
            i += 1
            expect_problem = argv[i]
        elif path is None:
            path = arg
        else:
            sys.stderr.write(__doc__)
            return 2
        i += 1

    if path is None:
        sys.stderr.write(__doc__)
        return 2

    with open(path, "rb") as handle:
        blob = handle.read()

    try:
        count, head, header = verify(blob)
    except Bad as bad:
        if expect_problem is not None:
            if bad.problem == expect_problem:
                print("oracle-format: as expected, %s" % bad)
                return 0
            print("oracle-format: expected %s, got %s"
                  % (expect_problem, bad), file=sys.stderr)
            return 1
        print("oracle-format: FAILED: %s" % bad, file=sys.stderr)
        return 1

    if expect_problem is not None:
        print("oracle-format: expected %s, but the log verified"
              % expect_problem, file=sys.stderr)
        return 1

    print("oracle-format: ok, %d record(s), block_size=%d, head=%s"
          % (count, header["block_size"], head))
    if expect_ok:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
