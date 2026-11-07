#include "hex.h"

#include <algorithm>

namespace chainlog {

std::string to_hex(const void* data, size_t len) {
  static const char kDigits[] = "0123456789abcdef";
  const uint8_t* p = static_cast<const uint8_t*>(data);

  std::string out;
  out.resize(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out[2 * i] = kDigits[p[i] >> 4];
    out[2 * i + 1] = kDigits[p[i] & 0x0f];
  }
  return out;
}

std::string to_hex(const Digest& d) { return to_hex(d.data(), d.size()); }

namespace {

// Returns 0..15, or -1 if c is not a hex digit.
int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

}  // namespace

bool from_hex(const std::string& s, std::string* out, std::string* detail) {
  if (s.size() % 2 != 0) {
    if (detail != nullptr) {
      *detail = "hex string has an odd length (" + std::to_string(s.size()) +
                " characters)";
    }
    return false;
  }
  out->clear();
  out->reserve(s.size() / 2);
  for (size_t i = 0; i < s.size(); i += 2) {
    const int hi = hex_value(s[i]);
    const int lo = hex_value(s[i + 1]);
    if (hi < 0 || lo < 0) {
      if (detail != nullptr) {
        *detail = "not a hex digit at position " +
                  std::to_string(hi < 0 ? i : i + 1);
      }
      return false;
    }
    out->push_back(static_cast<char>((hi << 4) | lo));
  }
  return true;
}

bool digest_from_hex(const std::string& s, Digest* out, std::string* detail) {
  std::string bytes;
  if (!from_hex(s, &bytes, detail)) {
    return false;
  }
  if (bytes.size() != out->size()) {
    if (detail != nullptr) {
      *detail = "expected 64 hex characters for a 32-byte digest, got " +
                std::to_string(s.size());
    }
    return false;
  }
  std::copy(bytes.begin(), bytes.end(), out->begin());
  return true;
}

}  // namespace chainlog
