#include "hex.h"

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

}  // namespace chainlog
