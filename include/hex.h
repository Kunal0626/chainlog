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

// Decodes hex (either case) into bytes. Returns false, with *detail set, on an
// odd length or a non-hex character. Hex that arrives from a command line or a
// pasted proof is untrusted input: it gets a real parse with a real error,
// never a silent partial decode.
bool from_hex(const std::string& s, std::string* out, std::string* detail);

// Same, for exactly 32 bytes.
bool digest_from_hex(const std::string& s, Digest* out, std::string* detail);

}  // namespace chainlog

#endif  // CHAINLOG_HEX_H
