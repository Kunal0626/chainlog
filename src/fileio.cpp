#include "fileio.h"

#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace chainlog {

Fd::~Fd() { reset(); }

Fd::Fd(Fd&& other) : fd_(other.fd_) { other.fd_ = -1; }

Fd& Fd::operator=(Fd&& other) {
  if (this != &other) {
    reset(other.fd_);
    other.fd_ = -1;
  }
  return *this;
}

void Fd::reset(int fd) {
  if (fd_ >= 0 && fd_ != fd) {
    // Nothing useful to do if close() fails here: the descriptor is gone
    // either way, and any unflushed data was already fsync'd by the caller
    // (durability is never left to close()).
    ::close(fd_);
  }
  fd_ = fd;
}

int Fd::release() {
  const int fd = fd_;
  fd_ = -1;
  return fd;
}

std::string errno_text(const std::string& what) {
  return what + ": " + std::strerror(errno);
}

bool pwrite_all(int fd, const void* buf, size_t len, uint64_t off,
                std::string* err) {
  const uint8_t* p = static_cast<const uint8_t*>(buf);
  while (len > 0) {
    const ssize_t n = ::pwrite(fd, p, len, static_cast<off_t>(off));
    if (n < 0) {
      if (errno == EINTR) {
        continue;  // Signal during the call; nothing was written, retry.
      }
      if (err != nullptr) {
        *err = errno_text("pwrite");
      }
      return false;
    }
    if (n == 0) {
      if (err != nullptr) {
        *err = "pwrite: wrote 0 bytes";
      }
      return false;
    }
    p += n;
    len -= static_cast<size_t>(n);
    off += static_cast<uint64_t>(n);
  }
  return true;
}

bool pread_full(int fd, void* buf, size_t len, uint64_t off, size_t* got,
                std::string* err) {
  uint8_t* p = static_cast<uint8_t*>(buf);
  size_t total = 0;
  while (total < len) {
    const ssize_t n =
        ::pread(fd, p + total, len - total, static_cast<off_t>(off + total));
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (err != nullptr) {
        *err = errno_text("pread");
      }
      return false;
    }
    if (n == 0) {
      break;  // End of file. Not an error; the caller inspects *got.
    }
    total += static_cast<size_t>(n);
  }
  if (got != nullptr) {
    *got = total;
  }
  return true;
}

bool full_fsync(int fd, std::string* err) {
#ifdef F_FULLFSYNC
  if (::fcntl(fd, F_FULLFSYNC, 0) == 0) {
    return true;
  }
  // Only fall back when the filesystem genuinely does not implement it.
  // Any other errno is a real failure and must not be swallowed, or we would
  // report an append as durable when it is not.
  if (errno != ENOTSUP && errno != EOPNOTSUPP && errno != EINVAL) {
    if (err != nullptr) {
      *err = errno_text("fcntl(F_FULLFSYNC)");
    }
    return false;
  }
#endif
  if (::fsync(fd) != 0) {
    if (err != nullptr) {
      *err = errno_text("fsync");
    }
    return false;
  }
  return true;
}

bool fsync_dir(const std::string& dir, std::string* err) {
  // O_RDONLY is the portable way to get a directory descriptor; you cannot
  // open a directory for writing.
  const int fd = ::open(dir.c_str(), O_RDONLY);
  if (fd < 0) {
    if (err != nullptr) {
      *err = errno_text("open(" + dir + ")");
    }
    return false;
  }
  Fd guard(fd);
  if (::fsync(fd) != 0) {
    if (err != nullptr) {
      *err = errno_text("fsync(" + dir + ")");
    }
    return false;
  }
  return true;
}

bool file_length(int fd, uint64_t* out, std::string* err) {
  struct stat st;
  if (::fstat(fd, &st) != 0) {
    if (err != nullptr) {
      *err = errno_text("fstat");
    }
    return false;
  }
  *out = static_cast<uint64_t>(st.st_size);
  return true;
}

bool make_dir_if_missing(const std::string& dir, std::string* err) {
  if (::mkdir(dir.c_str(), 0755) == 0) {
    return true;
  }
  if (errno == EEXIST) {
    struct stat st;
    if (::stat(dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
      return true;
    }
    if (err != nullptr) {
      *err = dir + " exists but is not a directory";
    }
    return false;
  }
  if (err != nullptr) {
    *err = errno_text("mkdir(" + dir + ")");
  }
  return false;
}

}  // namespace chainlog
