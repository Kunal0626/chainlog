// Lowercase hex encoding.
//
// Digests leave the program as hex (on stdout, in checkpoints, in proofs)
// because hex is the one encoding that survives a copy-paste out of a
// terminal, an email and a README without being mangled.
#ifndef CHAINLOG_HEX_H
#define CHAINLOG_HEX_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "sha256.h"

namespace chainlog {

// Encodes len bytes as 2*len lowercase hex characters.
std::string to_hex(const void* data, size_t len);

// Encodes a 32-byte digest as 64 lowercase hex characters.
std::string to_hex(const Digest& d);

}  // namespace chainlog

#endif  // CHAINLOG_HEX_H
