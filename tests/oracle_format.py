#!/usr/bin/env python3
"""Independent implementation of the ChainLog v1 on-disk format.

This is an oracle, not a utility. It was written from docs/FORMAT.md rather
than from the C++ source, and it uses Python's own hashlib and zlib instead of
ChainLog's hand-written SHA-256 and CRC-32. The Merkle code here is RFC 6962's
recursive MTH/PATH written the way the RFC writes it, not the iterative
level-by-level build the C++ uses. If the implementation and the specification
drift apart, this disagrees with one of them and `make oracle` fails.

It answers a question the C++ tests structurally cannot: is the format actually
specified well enough for somebody else to implement? A test suite written
against the same code it tests will happily agree with a format that only
exists in that code's head.

Usage:
    oracle_format.py <log-dir-or-file> [--expect-ok]
    oracle_format.py <log-dir-or-file> --expect-problem NAME
    oracle_format.py <log-dir-or-file> --prove <index>

Exit codes mirror the CLI: 0 it checks out, 1 it does not, 2 usage error.
"""

import hashlib
import os
import struct
import sys
import zlib

# --- log file ---------------------------------------------------------------

HEADER_BYTES = 32
HEADER_MAGIC = b"CHAINLOG"
FORMAT_VERSION = 1

FRAME_MAGIC = b"CHLG"
FRAME_OVERHEAD = 12                   # magic(4) + payload_len(4) + crc32(4)
PAYLOAD_FIXED = 8 + 8 + 8 + 32 + 32   # 88
MAX_DATA_LEN = 16 * 1024 * 1024

GENESIS_PREV_HASH = b"\x00" * 32

# --- checkpoints file -------------------------------------------------------

CKPT_HEADER_BYTES = 32
CKPT_HEADER_MAGIC = b"CHLGCKPT"
CKPT_FORMAT_VERSION = 1
CKPT_FRAME_MAGIC = b"CKPT"
CKPT_PAYLOAD_BYTES = 52               # flags(4) + first(8) + last(8) + root(32)
CKPT_OVERHEAD_BYTES = 12

# --- proof blob -------------------------------------------------------------

PROOF_VERSION = 1
PROOF_HEADER_BYTES = 26
PROOF_STEP_BYTES = 33
PROOF_TRAILER_BYTES = 4


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


def sha(data):
    return hashlib.sha256(data).digest()


# --- RFC 6962, written as the RFC writes it ---------------------------------

def leaf_hash(record_hash):
    return sha(b"\x00" + record_hash)


def node_hash(left, right):
    return sha(b"\x01" + left + right)


def split_point(n):
    """The largest power of two strictly less than n, for n > 1."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves):
    """RFC 6962 section 2.1. Deliberately the slow recursive form."""
    if not leaves:
        return sha(b"")
    if len(leaves) == 1:
        return leaf_hash(leaves[0])
    k = split_point(len(leaves))
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def rfc_path(leaves, m):
    """RFC 6962 PATH(m, D[n]), bottom-up. Returns [(sibling_on_left, hash)]."""
    if len(leaves) <= 1:
        return []
    k = split_point(len(leaves))
    if m < k:
        return rfc_path(leaves[:k], m) + [(False, mth(leaves[k:]))]
    return rfc_path(leaves[k:], m - k) + [(True, mth(leaves[:k]))]


def fold_proof(record_hash, leaf_index, tree_size, steps):
    """Recomputes a root from a leaf and its proof, deriving the path shape
    from (leaf_index, tree_size) and checking the flags against it."""
    if tree_size == 0 or leaf_index >= tree_size:
        raise Bad("bad-proof", leaf_index, 0, "leaf index outside the tree")
    acc = leaf_hash(record_hash)
    i, n, s = leaf_index, tree_size, 0
    while n > 1:
        expect_left = (i % 2 == 1)
        if expect_left or (i + 1 < n):
            if s >= len(steps):
                raise Bad("bad-proof", leaf_index, 0, "proof too short")
            flag, h = steps[s]
            if flag != expect_left:
                raise Bad("bad-proof", leaf_index, 0,
                          "step %d has the sibling on the wrong side" % s)
            acc = node_hash(h, acc) if expect_left else node_hash(acc, h)
            s += 1
        i //= 2
        n = (n + 1) // 2
    if s != len(steps):
        raise Bad("bad-proof", leaf_index, 0,
                  "proof has %d unused step(s)" % (len(steps) - s))
    return acc


def encode_proof(first_index, tree_size, leaf_index, steps):
    raw = bytearray()
    raw.append(PROOF_VERSION)
    raw += struct.pack("<QQQ", first_index, tree_size, leaf_index)
    raw.append(len(steps))
    for sibling_on_left, h in steps:
        raw.append(0 if sibling_on_left else 1)
        raw += h
    raw += struct.pack("<I", crc(bytes(raw)))
    return bytes(raw).hex()


def decode_proof(hexstr):
    raw = bytes.fromhex(hexstr)
    if len(raw) < PROOF_HEADER_BYTES + PROOF_TRAILER_BYTES:
        raise Bad("bad-proof", 0, 0, "proof too short to be a proof")
    body = len(raw) - PROOF_TRAILER_BYTES
    stored = struct.unpack_from("<I", raw, body)[0]
    if stored != crc(raw[:body]):
        raise Bad("bad-proof", 0, 0, "proof crc32 mismatch")
    if raw[0] != PROOF_VERSION:
        raise Bad("bad-proof", 0, 0, "proof version %d" % raw[0])
    first_index, tree_size, leaf_index = struct.unpack_from("<QQQ", raw, 1)
    count = raw[25]
    if PROOF_HEADER_BYTES + count * PROOF_STEP_BYTES != body:
        raise Bad("bad-proof", 0, 0, "step count disagrees with the length")
    steps = []
    for i in range(count):
        at = PROOF_HEADER_BYTES + i * PROOF_STEP_BYTES
        flag = raw[at]
        if flag not in (0, 1):
            raise Bad("bad-proof", 0, 0, "step %d has flag %d" % (i, flag))
        steps.append((flag == 0, raw[at + 1:at + 33]))
    return first_index, tree_size, leaf_index, steps


# --- parsing ----------------------------------------------------------------

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


def parse_records(blob):
    """Walks every frame, checking framing, index sequence, links and hashes.

    Returns the list of records as dicts, each carrying its recomputed hash.
    """
    offset = HEADER_BYTES
    expected_index = 0
    prev_hash = GENESIS_PREV_HASH
    records = []

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

        index, timestamp, data_len = struct.unpack_from("<QQQ", payload, 0)
        if data_len > MAX_DATA_LEN or data_len + PAYLOAD_FIXED != payload_len:
            raise Bad("bad-frame-length", expected_index, offset,
                      "data_len %d disagrees with payload length %d"
                      % (data_len, payload_len))

        cut = 24 + data_len
        data = payload[24:cut]
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

        computed = sha(preimage)
        if computed != record_hash:
            raise Bad("bad-hash", expected_index, offset,
                      "stored hash is not the hash of this record's bytes")

        records.append({"index": index, "timestamp": timestamp, "data": data,
                        "prev_hash": record_prev, "hash": computed})

        # Chain on the recomputed hash, as the spec requires.
        prev_hash = computed
        expected_index += 1
        offset += frame_len

    return records


def parse_checkpoints(blob, expect_block_size):
    if len(blob) < CKPT_HEADER_BYTES:
        raise Bad("bad-checkpoint", 0, 0,
                  "checkpoints file shorter than its header")
    head = blob[:CKPT_HEADER_BYTES]
    if head[:8] != CKPT_HEADER_MAGIC:
        raise Bad("bad-checkpoint", 0, 0, "magic is not CHLGCKPT")
    if struct.unpack_from("<I", head, 28)[0] != crc(head[:28]):
        raise Bad("bad-checkpoint", 0, 0, "checkpoints header crc32 mismatch")

    version, flags = struct.unpack_from("<II", head, 8)
    block_size = struct.unpack_from("<Q", head, 16)[0]
    if version != CKPT_FORMAT_VERSION:
        raise Bad("bad-checkpoint", 0, 0,
                  "checkpoints format version %d" % version)
    if flags != 0:
        raise Bad("bad-checkpoint", 0, 0, "unknown checkpoints header flags")
    if block_size != expect_block_size:
        raise Bad("bad-checkpoint", 0, 0,
                  "checkpoints block_size %d disagrees with the log's %d"
                  % (block_size, expect_block_size))

    out = []
    offset = CKPT_HEADER_BYTES
    while offset < len(blob):
        remaining = len(blob) - offset
        if remaining < 8:
            raise Bad("torn-checkpoint-tail", len(out), offset,
                      "%d byte(s) left, too few for a prologue" % remaining)
        if blob[offset:offset + 4] != CKPT_FRAME_MAGIC:
            raise Bad("bad-checkpoint", len(out), offset,
                      "frame does not start with CKPT")
        payload_len = struct.unpack_from("<I", blob, offset + 4)[0]
        if payload_len != CKPT_PAYLOAD_BYTES:
            raise Bad("bad-checkpoint", len(out), offset,
                      "checkpoint payload length %d" % payload_len)
        frame_len = CKPT_OVERHEAD_BYTES + payload_len
        if remaining < frame_len:
            raise Bad("torn-checkpoint-tail", len(out), offset,
                      "frame needs %d bytes, only %d left"
                      % (frame_len, remaining))
        payload = blob[offset + 8:offset + 8 + payload_len]
        stored = struct.unpack_from("<I", blob, offset + 8 + payload_len)[0]
        if stored != crc(payload):
            raise Bad("bad-checkpoint", len(out), offset,
                      "checkpoint crc32 mismatch")
        cflags = struct.unpack_from("<I", payload, 0)[0]
        first_index, last_index = struct.unpack_from("<QQ", payload, 4)
        root = payload[20:52]
        if cflags != 0:
            raise Bad("bad-checkpoint", len(out), offset,
                      "unknown checkpoint flags")
        if last_index < first_index:
            raise Bad("bad-checkpoint", len(out), offset,
                      "checkpoint range runs backwards")
        out.append({"first_index": first_index, "last_index": last_index,
                    "root": root})
        offset += frame_len
    return block_size, out


def verify_all(log_blob, ckpt_blob):
    """Returns (records, checkpoints, header). Raises Bad on any problem."""
    header = parse_header(log_blob)
    records = parse_records(log_blob)
    block_size = header["block_size"]

    _, checkpoints = parse_checkpoints(ckpt_blob, block_size)

    complete = len(records) // block_size
    if len(checkpoints) != complete:
        raise Bad("bad-checkpoint", complete * block_size, 0,
                  "%d record(s) form %d complete block(s) but there are %d "
                  "checkpoint(s)" % (len(records), complete, len(checkpoints)))

    for b, cp in enumerate(checkpoints):
        want_first = b * block_size
        want_last = want_first + block_size - 1
        if cp["first_index"] != want_first or cp["last_index"] != want_last:
            raise Bad("bad-checkpoint", want_first, 0,
                      "checkpoint %d covers %d..%d, expected %d..%d"
                      % (b, cp["first_index"], cp["last_index"],
                         want_first, want_last))
        leaves = [r["hash"] for r in records[want_first:want_last + 1]]
        root = mth(leaves)
        if root != cp["root"]:
            raise Bad("bad-checkpoint", want_first, 0,
                      "block %d has root %s but the checkpoint says %s"
                      % (b, root.hex(), cp["root"].hex()))

    return records, checkpoints, header


# --- driver -----------------------------------------------------------------

def read_log_dir(path):
    """Accepts either a log directory or the log file inside one."""
    if os.path.isdir(path):
        log_path = os.path.join(path, "log")
        ckpt_path = os.path.join(path, "checkpoints")
    else:
        log_path = path
        ckpt_path = os.path.join(os.path.dirname(path) or ".", "checkpoints")

    with open(log_path, "rb") as handle:
        log_blob = handle.read()
    ckpt_blob = b""
    if os.path.exists(ckpt_path):
        with open(ckpt_path, "rb") as handle:
            ckpt_blob = handle.read()
    return log_blob, ckpt_blob


def do_prove(records, checkpoints, header, index):
    """Builds a proof independently and prints it in the wire format.

    The C++ builds its tree iteratively level by level; this uses RFC 6962's
    recursive PATH. Byte-identical output is strong evidence that the
    iterative build really is the RFC's tree and not merely a tree.
    """
    block_size = header["block_size"]
    block = index // block_size
    if block >= len(checkpoints):
        print("oracle-format: index %d is not in a sealed block" % index,
              file=sys.stderr)
        return 1
    cp = checkpoints[block]
    leaves = [r["hash"] for r in
              records[cp["first_index"]:cp["last_index"] + 1]]
    leaf_index = index - cp["first_index"]
    steps = rfc_path(leaves, leaf_index)

    # Check it against our own fold before printing it.
    root = fold_proof(leaves[leaf_index], leaf_index, len(leaves), steps)
    if root != cp["root"]:
        print("oracle-format: own proof does not verify", file=sys.stderr)
        return 1

    print("proof=%s" % encode_proof(cp["first_index"], len(leaves),
                                    leaf_index, steps))
    print("root=%s" % cp["root"].hex())
    print("record_hash=%s" % records[index]["hash"].hex())
    return 0


def main(argv):
    expect_problem = None
    prove_index = None
    path = None

    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "--expect-ok":
            pass
        elif arg == "--expect-problem" and i + 1 < len(argv):
            i += 1
            expect_problem = argv[i]
        elif arg == "--prove" and i + 1 < len(argv):
            i += 1
            prove_index = int(argv[i])
        elif path is None:
            path = arg
        else:
            sys.stderr.write(__doc__)
            return 2
        i += 1

    if path is None:
        sys.stderr.write(__doc__)
        return 2

    log_blob, ckpt_blob = read_log_dir(path)

    try:
        records, checkpoints, header = verify_all(log_blob, ckpt_blob)
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

    if prove_index is not None:
        return do_prove(records, checkpoints, header, prove_index)

    head = records[-1]["hash"].hex() if records else None
    print("oracle-format: ok, %d record(s), %d checkpoint(s), block_size=%d, "
          "head=%s" % (len(records), len(checkpoints), header["block_size"],
                       head))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
