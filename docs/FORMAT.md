# ChainLog on-disk format, version 1

Everything here is byte-exact and verifiable. `tests/oracle_format.py` is an
independent parser written in Python that re-implements this document from
scratch and re-derives every hash and CRC; `make oracle` runs it against a log
built by the C++ CLI. If this document and the code ever disagree, that script
fails.

## Files

A log is a **directory**, not a file:

| File | Purpose | Added in |
|---|---|---|
| `log` | the append-only record file | phase 2 |
| `log.wal` | write-ahead log, holds at most one in-flight record | phase 4 |
| `checkpoints` | sealed Merkle roots | phase 3 |
| `lock` | `flock` target, so two writers cannot interleave | phase 4 |

A directory rather than a single file because these must be fsynced and locked
as a unit, and because making a new file's *name* durable requires fsyncing the
directory that contains it.

## `log` layout

```
+------------------+
| header, 32 bytes |
+------------------+
| frame 0          |
+------------------+
| frame 1          |
+------------------+
| ...              |
+------------------+
```

### Header (32 bytes)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | magic | ASCII `CHAINLOG` |
| 8 | 4 | `format_version` | u32 LE, currently `1` |
| 12 | 4 | `flags` | u32 LE, reserved, must be `0` |
| 16 | 8 | `block_size` | u64 LE, records per sealed Merkle block |
| 24 | 4 | reserved | u32 LE, must be `0` |
| 28 | 4 | `crc32` | u32 LE over bytes 0..27 |

`block_size` is stored in the file rather than kept as a compile-time constant
because the checkpoints are only meaningful relative to it. If a later release
changed the default, every existing log's checkpoints would silently stop
matching. The CRC is checked **before** the version field is trusted, so a
corrupted version number reads as "damaged header" rather than "log from the
future".

`flags` and the reserved word must be zero. Rejecting unknown bits is what lets
a future version add a feature and have old builds refuse the file loudly
instead of misreading it.

### Frame

```
+--------+-------------+------------------+--------+
| magic  | payload_len |     payload      | crc32  |
| 4 LE   |    4 LE     |   payload_len    |  4 LE  |
+--------+-------------+------------------+--------+
```

- `magic` is `0x474C4843`, which stored little-endian reads `CHLG` in a hex
  dump. Costs nothing and makes the file navigable by eye.
- `payload_len` is a u32. Minimum 88 (`kPayloadFixedBytes`); the implied data
  length (`payload_len - 88`) is capped at 16 MiB.
- `crc32` covers the **payload bytes only**, not the magic or the length.

### Payload

```
+-------+-----------+----------+------+-----------+------+
| index | timestamp | data_len | data | prev_hash | hash |
| 8 LE  |   8 LE    |   8 LE   |  n   |    32     |  32  |
+-------+-----------+----------+------+-----------+------+
 \------------------ hashed preimage ------------/
```

The **preimage** is the first five fields: `index || timestamp || data_len ||
data || prev_hash`. The record's own `hash` is appended after it on disk but is
not part of its own preimage.

```
hash = SHA256(index || timestamp || data_len || data || prev_hash)
```

All integers are fixed-width **little-endian**. Fixed-width and explicitly
little-endian so that two machines of different endianness compute the same
hash for the same record — a `memcpy` of a `uint64_t` would be faster and
wrong.

## Why there are two length fields

`payload_len` (in the frame) and `data_len` (in the preimage) encode the same
number twice. The decoder requires `data_len + 88 == payload_len`, which turns
that redundancy into a consistency check rather than wasted bytes. It is also
the cheapest possible guard against a flipped bit in either field.

## Why the data length is written before the data

The usual one-line answer — "so two different records cannot hash to the same
bytes" — is incomplete, and worth understanding properly.

In *this* layout, `data` is the only variable-length field and it sits between
two fixed-width runs, so `data_len` is already recoverable from the total
preimage length, and SHA-256's own padding commits to that total length. So for
version 1 the prefix is belt-and-braces.

It earns its place anyway:

1. Injectivity becomes a property of the **encoding**, checkable by looking at
   it, instead of a property that depends on an argument about the field layout
   plus the hash function's padding rule.
2. The moment a second variable-length field is added, the unprefixed encoding
   collides: `actor="ab", data="c"` and `actor="a", data="bc"` both serialise to
   `abc`. Nothing about the layout warns you, and every historical hash is
   already wrong by then.

`tests/test_record.cpp` has `length_prefix_is_what_keeps_the_encoding_injective`
demonstrating exactly that collision.

## Genesis record

Index `0`, with `prev_hash` set to **32 zero bytes**. Documented rather than
accidental: the genesis record has no predecessor, and "no predecessor" still
has to be *some* fixed value that goes through the hash like every other field.

## Torn writes versus tampering

Two different failures, detected by two different mechanisms. Conflating them
is the most common mistake in log formats.

| | Torn write | Tampering |
|---|---|---|
| Cause | crash or power loss during a write | someone with write access |
| Where | **always** at end of file | anywhere |
| Detected by | magic + `payload_len` + CRC-32 | SHA-256 chain |
| Reported as | `torn-tail` | `bad-hash`, `broken-link`, `bad-index` |
| Fix | truncate back to the last good frame (phase 4 recovery) | there is no fix; it is evidence |

The key asymmetry: **CRC-32 is not a security mechanism.** Anyone editing a
frame recomputes the CRC for free — it needs no secret. What an attacker cannot
recompute is the SHA-256 chain, because every later record commits to every
earlier one.

So the CRC answers *"did this write finish?"* and the hash chain answers *"did
someone change history?"*. Position carries as much information as the check
itself: a bad CRC at end of file is a crash, the same bad CRC in the middle of
the file is corruption or an attack.

## What `verify` checks, in order

For each frame, left to right through the file:

1. `magic` is `CHLG` — else `bad-magic`
2. `payload_len` is within limits — else `bad-frame-length`
3. enough bytes remain for the whole frame — else `torn-tail`
4. CRC-32 matches — else `bad-crc`
5. `data_len + 88 == payload_len` — else `bad-frame-length`
6. `index == expected` (0, 1, 2, …) — else `bad-index`
7. `prev_hash` equals the previous record's **recomputed** hash — else `broken-link`
8. `SHA256(preimage)` equals the stored `hash` — else `bad-hash`

It stops at the **first** failure and reports its index and byte offset. A
verifier that reported the last failure, or all of them, makes it much harder
to work out what actually happened.

Step 7 chains on the **recomputed** hash of the previous record, never the
stored one. This is what makes blame land correctly: if someone edits the
stored hash field of record *i*, chaining on the recomputed value reports
`bad-hash` at exactly *i*. Chaining on the stored value would instead report a
broken link at *i+1* — pointing the investigator at the one record that was not
touched.

### The escalation ladder

`tests/test_log.cpp` walks an attacker up this ladder, one test per rung:

| Attacker effort | Caught by | Reported at |
|---|---|---|
| flip a byte | CRC-32 | that record |
| flip a byte, fix the CRC | record hash | that record |
| flip a byte, fix CRC + hash | the next record's link | *i+1* |
| flip a byte, re-link the entire tail | **nothing in the file** | — |

## Known limitations of version 1

Both of these are properties of hash chains, not bugs, and both are closed by
anchoring (phase 5) rather than by anything inside the file.

**Truncation at a frame boundary is invisible.** A prefix of a valid chain is
itself a valid chain. Cutting records off the end leaves a log that verifies
perfectly. Detecting it requires remembering, somewhere outside the file, how
long the log was — which is what `head` output and `verify --anchor` are for.

**A full rewrite is invisible.** An attacker with write access to the whole file
can edit a record, re-link every record after it, and produce a chain that is
internally perfect. Nothing in the file remembers the old history. The defence
is the same: get a copy of the head hash out of the attacker's reach.

**Timestamps are not verified.** `verify` does not require timestamps to
increase. `CLOCK_REALTIME` legitimately steps backwards when NTP adjusts it, so
enforcing monotonicity would turn a normal clock correction into a tamper
report. It would also buy nothing against the real attacker: an admin rewriting
history would fix the timestamps too. The timestamp is informational; the
*ordering* guarantee comes from `index` and the chain.

**`block_size` is fixed at creation.** There is no migration path for changing
it on an existing log.

## A real record, byte by byte

Produced by `chainlog --dir D append "hello"` on an empty log, then dumped with
`xxd`. Reproduce it with `make all && ./build/release/chainlog --dir /tmp/d append hello && xxd -g 1 -l 128 /tmp/d/log` (your timestamp and therefore your
hash will differ).

```
00000000: 43 48 41 49 4e 4c 4f 47 01 00 00 00 00 00 00 00  CHAINLOG........
00000010: 00 04 00 00 00 00 00 00 00 00 00 00 d1 c4 35 81  ..............5.
00000020: 43 48 4c 47 5d 00 00 00 00 00 00 00 00 00 00 00  CHLG]...........
00000030: d0 1f 83 fe 18 86 e5 18 05 00 00 00 00 00 00 00  ................
00000040: 68 65 6c 6c 6f 00 00 00 00 00 00 00 00 00 00 00  hello...........
00000050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000060: 00 00 00 00 00 eb a9 90 e1 74 54 77 19 d8 3a 0d  .........tTw..:.
00000070: f7 b8 94 20 fb cb 41 29 fd 44 0c ec 99 46 f6 be  ... ..A).D...F..
```

Reading it:

| Bytes | Value | Meaning |
|---|---|---|
| `00..07` | `CHAINLOG` | header magic |
| `08..0b` | `01 00 00 00` | `format_version = 1` |
| `0c..0f` | `00 00 00 00` | `flags = 0` |
| `10..17` | `00 04 00 00 00 00 00 00` | `block_size = 1024` |
| `18..1b` | `00 00 00 00` | reserved |
| `1c..1f` | `d1 c4 35 81` | header CRC-32 = `0x8135c4d1` |
| `20..23` | `CHLG` | frame magic |
| `24..27` | `5d 00 00 00` | `payload_len = 93`, so the frame is 105 bytes |
| `28..2f` | `00 …` | `index = 0` |
| `30..37` | `d0 1f 83 fe 18 86 e5 18` | `timestamp_ns = 1793987468484354000` |
| `38..3f` | `05 00 00 00 00 00 00 00` | `data_len = 5` |
| `40..44` | `hello` | the data |
| `45..64` | 32 zero bytes | `prev_hash` — genesis |
| `65..84` | `eb a9 90 e1 …` | `hash` |
| `85..88` | (past the dump) | frame CRC-32 = `0x313613f4` |

Note `93 = 8 + 8 + 8 + 5 + 32 + 32` and `105 = 93 + 12`, matching the two-length
consistency rule above. And `SHA256` of bytes `28..64` (the preimage) is
`eba990e1…`, which is the stored hash — that is the check `verify` step 8 does,
and it is reproduced independently in Python by
`tests/oracle_format.py`.

---

# Checkpoints and inclusion proofs (phase 3)

## `checkpoints` layout

```
+------------------+
| header, 32 bytes |
+------------------+
| checkpoint 0     |  64 bytes
+------------------+
| checkpoint 1     |  64 bytes
+------------------+
| ...              |
+------------------+
```

Every frame is the same size in version 1, so the offset of the *n*-th
checkpoint is `32 + n * 64` — exact arithmetic, no walk needed.

### Header (32 bytes)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | magic | ASCII `CHLGCKPT` |
| 8 | 4 | `format_version` | u32 LE, currently `1` |
| 12 | 4 | `flags` | u32 LE, reserved, must be `0` |
| 16 | 8 | `block_size` | u64 LE, **must equal the log's** |
| 24 | 4 | reserved | u32 LE, must be `0` |
| 28 | 4 | `crc32` | u32 LE over bytes 0..27 |

`block_size` is deliberately repeated here. It is derived data, so the
duplication is a consistency check: if the two files disagree, one of them has
been swapped in from a different log. `a_checkpoints_file_from_another_log_is_caught`
in `tests/test_checkpoint.cpp` is that check firing.

### Checkpoint frame (64 bytes)

```
+--------+-------------+--------------------------+--------+
| "CKPT" | payload_len |         payload          | crc32  |
|   4    |    4 LE     |        52 bytes          |  4 LE  |
+--------+-------------+--------------------------+--------+
```

Payload:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `flags` u32 LE (reserved; bit 0 will mean "an HMAC follows") |
| 4 | 8 | `first_index` u64 LE |
| 12 | 8 | `last_index` u64 LE |
| 20 | 32 | `root` |

A range where `last_index < first_index` is rejected at parse time rather than
trusted — otherwise `last - first + 1` underflows into a gigantic leaf count.

## Merkle hashing

RFC 6962 (Certificate Transparency):

```
leaf hash  = SHA256(0x00 || record_hash)
inner node = SHA256(0x01 || left || right)
```

### Why the 0x00 / 0x01 prefixes

An inner node hashes 64 bytes: two concatenated digests. Without domain
separation that input is byte-identical to a *leaf* whose payload happens to be
64 bytes, so an attacker could hand over an interior node and have it accepted
as a leaf — proving membership of something never appended. The prefixes put
leaves and inner nodes in disjoint input spaces (RFC 6962 §2.1).

### Why a lone odd node is promoted, not duplicated

The odd node out is carried up **unchanged**. The tempting alternative — hash
it with a copy of itself, which is what Bitcoin does — is **CVE-2012-2459**.

With duplication, three leaves A, B, C give:

```
root = H(H(A,B), H(C,C))
```

which is byte-identical to the root of the **four**-leaf tree A, B, C, C. The
root therefore stops uniquely committing to the leaf list: two different
histories share a root, and an inclusion proof becomes ambiguous.

Promotion avoids it because the tree's shape then depends only on *n*, and *n*
is committed in the checkpoint next to the root.
`duplicating_the_odd_node_collides` in `tests/test_merkle.cpp` builds the unsafe
variant and exhibits the actual collision, at sizes 3 and 5.

### The iterative build is RFC 6962's tree

ChainLog builds levels bottom-up in a flat vector. RFC 6962 defines `MTH`
recursively, splitting at the largest power of two below *n*. These produce the
same tree, and the reason is worth knowing: a partial node at level *j* covers
*r* leaves, and either

- `r ≤ 2^(j-1)`, so it is promoted and simply *is* its child, or
- `2^(j-1) < r ≤ 2^j`, so it splits at `2^(j-1)` — which is exactly the largest
  power of two below *r*.

That is checked, not assumed: `iterative_build_matches_rfc6962_recursive_mth`
compares against the recursive definition for every size up to 257, and
`tests/oracle_format.py` re-derives proofs with the recursive `PATH` in Python
and `make oracle` requires them to be **byte-identical**.

## Proof wire format

A proof travels between machines as one hex string, so it is self-describing.

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version (`1`) |
| 1 | 8 | `first_index` u64 LE — first record of the sealed block |
| 9 | 8 | `tree_size` u64 LE — leaves in that block's tree |
| 17 | 8 | `leaf_index` u64 LE — position within the block, 0-based |
| 25 | 1 | `step_count` u8 — at most 64 |
| 26 | 33 × *n* | per step: `flag` u8 (`0` = sibling on the left) then 32-byte hash |
| last | 4 | `crc32` u32 LE over every preceding byte |

The CRC is there so a mangled copy-paste reads as **"corrupt proof"** rather
than **"proof does not verify"**. Those are different answers and an operator
needs to tell them apart — the same accident-versus-attack split as the record
frame's CRC. It is why `verify-proof` exits 2 for a truncated proof and 1 for a
proof that is intact but wrong.

## What a proof binds, exactly

Verification derives the path shape from `(leaf_index, tree_size)` and then
checks the proof's flags against it, rather than folding along whatever flags it
was handed.

**The position is pinned.** The left/right flags along a path are the bits of
the leaf index, least significant first, so within a given tree size no two
positions share a shape. Checked exhaustively in
`a_proof_is_bound_to_its_position`: every leaf of a 37-leaf tree, against every
one of the other 36 claimed positions.

**The tree size is only partly pinned**, and it is worth being exact rather than
claiming more. The size changes the shape only where it changes the *promotion
pattern* on that particular path. Leaf 19 has shape `LLRRLR` in trees of 36, 37,
38, 40, 48 and 64 leaves alike — the same siblings fold to the same root, and
the verifier cannot tell those sizes apart. Across a 37-leaf tree, 36 of the 37
leaves have a shape shared with some other size.

This does not weaken the property that matters: producing a proof for a leaf
that is *not* in the tree still requires inverting SHA-256, because the root has
to come out right. What it means is that a proof's self-reported `tree_size` is
convenience, not a committed fact. **The size that counts comes from the trusted
checkpoint** (`last_index - first_index + 1`), alongside the root the verifier
already trusts. Pinned as a passing test named
`a_proof_does_NOT_pin_the_exact_tree_size` so it cannot quietly stop being true.

## Why `verify-proof` needs more than the data

```
chainlog verify-proof <index> <data> <root> <proof> --timestamp N --prev-hash HEX
```

A leaf hash is `SHA256(0x00 || SHA256(index || timestamp || data_len || data || prev_hash))`.
The data alone cannot reproduce it. Accepting a bare leaf hash instead would
hide the fact that **a leaf commits to the whole record**, which is the property
that makes the proof worth anything. `chainlog prove` prints a ready-made
command line with every field filled in, and `<data>` accepts a `hex:` prefix so
records containing NULs survive a shell round trip.

## What sealing changes about the threat model

Checkpoints are not only what a proof proves *against*. They are a second,
independent record of history, and that closes one of phase 2's two holes.

| Attacker effort | Caught by | Reported at |
|---|---|---|
| flip a byte | CRC-32 | that record |
| flip a byte, fix the CRC | record hash | that record |
| flip a byte, fix CRC + hash | the next record's link | *i+1* |
| re-link the entire tail | **the sealed roots** | first record of the affected block |
| re-link the tail **and** re-seal every checkpoint | **nothing in the directory** | — |

The fourth rung used to be undetectable. It is caught now — not because the
hashing got better, but because the attacker has to rewrite a second file too,
and the old roots are still sitting in it.
`tamper_step5_relinking_the_log_is_caught_by_the_checkpoints` is that rung;
`tamper_step6_rewriting_the_checkpoints_too_is_NOT_detected` is the one past it.

## Crash recovery for derived data

A checkpoint holds no information that is not already in its records. That makes
missing or torn checkpoints *recoverable* in a way tampered records never are,
and it makes over-eager repair dangerous.

`open()` therefore performs exactly two narrow repairs:

1. **A torn trailing checkpoint frame** is truncated and re-derived. It is
   always at end of file, so it is a crash artifact.
2. **Exactly one missing trailing checkpoint**, when the log ends precisely on a
   block boundary, is re-sealed.

Why at most one: sealing happens *inside* `append()`, after the record's fsync
and before the next record can be written. So a crash can leave one complete
block unsealed and never two. If two or more are missing, that did not come from
a crash — the file was truncated or edited — and re-deriving those roots would
**destroy the very evidence** that catches the re-link attack above. So that
case is reported (`bad-checkpoint`) and never repaired. See
`deleting_the_last_two_checkpoints_is_reported_not_repaired`.

The write order is record first, checkpoint second, for the same reason: a
checkpoint without its records would be a claim about history that cannot be
checked, while records without their checkpoint are merely incomplete derived
state.

## Additional limitations of phase 3

**Proofs only exist for sealed blocks.** `prove` on a record in the block being
filled fails with the last sealed index, rather than inventing an ephemeral
root. A root published nowhere proves nothing to anybody.

**`prove` walks the log from the start.** Frames are variable-length and there
is no offset index, so finding block *b* is O(records before it). An offset
could be stored in each checkpoint to make this O(block), but that is an
optimisation without a measurement behind it yet; phase 7 measures it.

**`read_checkpoints` loads the whole file.** One 64-byte checkpoint per
`block_size` records, so a million-record log is about 60 KB. A log large
enough for that to matter would need streaming.

**`prove` refuses rather than emitting a known-bad proof.** If a block's records
no longer hash to its sealed root, `prove` reports `bad-checkpoint` instead of
handing over a proof. Emitting it would shift the discovery of tampering onto
whoever checks the proof later.
