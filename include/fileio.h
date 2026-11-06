// Thin wrappers over POSIX file I/O.
//
// Three things here are not conveniences but correctness requirements:
//
//   * write()/read() are allowed to transfer fewer bytes than asked for. Code
//     that ignores the return value works until the day it does not.
//   * On macOS, fsync() is not enough to survive power loss (see full_fsync).
//   * A file's *name* lives in its parent directory, so creating a file and
//     fsyncing only the file can still leave the name behind after a crash
//     (see fsync_dir).
#ifndef CHAINLOG_FILEIO_H
#define CHAINLOG_FILEIO_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace chainlog {

// Owning file descriptor: closes on destruction, move-only. Plain ints leak
// on every early return, and there are a lot of early returns in I/O code.
class Fd {
 public:
  Fd() : fd_(-1) {}
  explicit Fd(int fd) : fd_(fd) {}
  ~Fd();

  Fd(Fd&& other);
  Fd& operator=(Fd&& other);
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;

  int get() const { return fd_; }
  bool valid() const { return fd_ >= 0; }
  void reset(int fd = -1);
  int release();

 private:
  int fd_;
};

// "what: strerror(errno)" -- the only error text format used in this project,
// so every failure says both what was attempted and why it failed.
std::string errno_text(const std::string& what);

// Writes all len bytes at absolute offset `off`, looping over short writes.
bool pwrite_all(int fd, const void* buf, size_t len, uint64_t off,
                std::string* err);

// Reads up to len bytes at absolute offset `off`, looping over short reads.
// *got is the number actually read; *got < len means end of file, which is
// not an error here -- the caller decides whether a short read is a problem.
bool pread_full(int fd, void* buf, size_t len, uint64_t off, size_t* got,
                std::string* err);

// Flushes the file's data AND asks the storage device to flush its own write
// cache. Plain fsync(2) on Darwin does the former but not the latter, so a
// log that only calls fsync() is not actually durable across power loss.
// Falls back to fsync() where F_FULLFSYNC is unsupported (some network
// filesystems), because a weaker barrier beats failing the append.
bool full_fsync(int fd, std::string* err);

// fsync()s a directory, which is how a newly created file's *name* is made
// durable. Without it a crash can leave the data on disk with nothing in the
// directory pointing at it.
bool fsync_dir(const std::string& dir, std::string* err);

bool file_length(int fd, uint64_t* out, std::string* err);

// mkdir() that treats "already exists and is a directory" as success.
bool make_dir_if_missing(const std::string& dir, std::string* err);

}  // namespace chainlog

#endif  // CHAINLOG_FILEIO_H
