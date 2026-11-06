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
