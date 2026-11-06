// CRC-32 (the IEEE 802.3 / zlib / gzip / PNG variant), by hand.
//
// This is NOT a security primitive and is never used as one. It guards the
// on-disk frame against *accidental* damage: a half-completed write, a bad
// sector, a truncated copy. An attacker can recompute a CRC for free, which is
// the whole reason the hash chain exists alongside it.
//
// Parameters (CRC-32/ISO-HDLC): reflected polynomial 0xEDB88320, initial
// register 0xFFFFFFFF, final XOR 0xFFFFFFFF, input and output reflected.
// Those choices are not ours to make -- matching the common variant means
// python's zlib.crc32 can be used as an oracle in the tests.
#ifndef CHAINLOG_CRC32_H
#define CHAINLOG_CRC32_H

#include <cstddef>
#include <cstdint>

namespace chainlog {

uint32_t crc32(const void* data, size_t len);

}  // namespace chainlog

#endif  // CHAINLOG_CRC32_H
