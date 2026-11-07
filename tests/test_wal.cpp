// Write-ahead log: the header format, and every recovery path.
//
// tests/crash.sh kills the real binary at each point in the append protocol
// and checks the outcome end to end. This file does the complementary job: it
// constructs each intermediate state directly, so the recovery decision for
// that state is tested on its own rather than only as a consequence of a
// crash that happened to land there.
//
// The decisions under test, in one sentence each:
//
//   staged frame complete, not in the log  -> redo it (step 1's fsync
//                                             returned, so the record was
//                                             durable before the log was
//                                             touched)
//   staged frame complete, already the tail -> clear the WAL, nothing else
//   staged frame torn                       -> drop it (step 1's fsync never
//                                             returned, so nobody was told
//                                             the append succeeded)
//   staged frame complete but does not link -> report bad-wal (no crash can
//                                             produce this)

#include <sys/stat.h>

#include <string>
#include <vector>

#include "hex.h"
#include "log.h"
#include "log_fixture.h"
#include "test.h"
#include "wal.h"

using chainlog::Log;
using chainlog::Problem;
using chainlog::Record;
using chainlog::Verdict;
using chainlog::WalHeader;
using chainlog::kWalHeaderBytes;
using chainlog::to_hex;
using chainlog_test::TempDir;
using chainlog_test::build_log;
using chainlog_test::record_label;
using chainlog_test::verify_dir;

namespace {

std::string pname(Problem p) { return chainlog::problem_name(p); }

std::string wal_file(const TempDir& d) { return Log::wal_path(d.path()); }
std::string log_file(const TempDir& d) { return Log::log_path(d.path()); }

// Writes `bytes` into the WAL behind a valid header.
void stage_bytes(const TempDir& d, const std::string& bytes) {
  std::string out;
  chainlog::encode_wal_header(WalHeader(), &out);
  out.append(bytes);
  chainlog_test::write_file(wal_file(d), out);
}

void stage_record(const TempDir& d, const Record& r) {
  std::string frame;
  chainlog::append_frame(r, &frame);
  stage_bytes(d, frame);
}

// The last record of the log in `dir`.
Record tail_of(const TempDir& d) {
  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  Record r;
  CHECK(log.head(&r));
  return r;
}

// The record append() would have written next.
Record next_record_for(const TempDir& d, const std::string& data) {
  const Record tail = tail_of(d);
  Record r;
  r.index = tail.index + 1;
  r.timestamp_ns = 1700000000000000000ull;
  r.data = data;
  r.prev_hash = tail.hash;
  r.hash = chainlog::compute_record_hash(r);
  return r;
}

size_t wal_bytes(const TempDir& d) {
  return chainlog_test::read_file(wal_file(d)).size();
}

}  // namespace

// --- the header ------------------------------------------------------------

TEST(wal_header_round_trips_and_rejects_damage) {
  std::string buf;
  chainlog::encode_wal_header(WalHeader(), &buf);
  CHECK_EQ(buf.size(), kWalHeaderBytes);
  CHECK_EQ(std::string(buf, 0, 8), "CHLGWAL1");

  WalHeader out;
  std::string detail;
  CHECK_EQ(pname(chainlog::decode_wal_header(buf.data(), buf.size(), &out,
                                             &detail)),
           "ok");
  CHECK_EQ(out.format_version, chainlog::kWalFormatVersion);

  // Short file.
  CHECK_EQ(pname(chainlog::decode_wal_header(buf.data(), 8, &out, &detail)),
           "bad-wal");

  // Any flipped bit in the covered range.
  for (size_t i = 0; i < 28; ++i) {
    std::string bad = buf;
    bad[i] = static_cast<char>(bad[i] ^ 0x01);
    CHECK_EQ(pname(chainlog::decode_wal_header(bad.data(), bad.size(), &out,
                                               &detail)),
             "bad-wal");
  }
}

// --- the empty state -------------------------------------------------------

TEST(a_new_log_gets_an_empty_wal_with_a_header) {
  TempDir d;
  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));

  // Step 3 truncates to the header, not to zero, so that "empty" is
  // identifiably an empty WAL rather than a stray zero-length file.
  CHECK_EQ(wal_bytes(d), kWalHeaderBytes);
  CHECK(!log.wal_pending());

  std::string detail;
  WalHeader h;
  const std::string bytes = chainlog_test::read_file(wal_file(d));
  CHECK_EQ(pname(chainlog::decode_wal_header(bytes.data(), bytes.size(), &h,
                                             &detail)),
           "ok");
}

TEST(append_leaves_the_wal_empty) {
  TempDir d;
  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  for (uint64_t i = 0; i < 5; ++i) {
    Record r;
    CHECK(log.append(record_label(i), &r, &err));
    // Checked after every append, not just at the end: a WAL that grows is a
    // WAL that is not being cleared.
    CHECK_EQ(wal_bytes(d), kWalHeaderBytes);
  }
  log.close();
  CHECK_EQ(pname(verify_dir(d.path()).problem), "ok");
}

// --- recovery: redo --------------------------------------------------------

TEST(a_staged_record_not_yet_in_the_log_is_replayed) {
  TempDir d;
  build_log(d.path(), 5);
  const Record staged = next_record_for(d, "staged-and-replayed");
  stage_record(d, staged);

  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));

  CHECK_EQ(pname(log.scan_verdict().problem), "ok");
  CHECK_EQ(log.record_count(), 6ull);
  CHECK(!log.wal_pending());
  CHECK_EQ(wal_bytes(d), kWalHeaderBytes);

  Record h;
  CHECK(log.head(&h));
  CHECK_EQ(h.index, 5ull);
  CHECK_EQ(h.data, "staged-and-replayed");
  CHECK_EQ(to_hex(h.hash), to_hex(staged.hash));

  log.close();  // release the exclusive lock before reopening the directory
  const Verdict v = verify_dir(d.path());
  CHECK_EQ(pname(v.problem), "ok");
  CHECK_EQ(v.records_verified, 6ull);
}

TEST(replay_into_an_empty_log_works) {
  TempDir d;
  Log::Options opt;
  std::string err;
  {
    Log fresh;
    CHECK(fresh.open(d.path(), opt, &err));  // creates the files, 0 records
  }

  // The genesis record, staged but never applied.
  Record staged;
  staged.index = 0;
  staged.timestamp_ns = 1700000000000000000ull;
  staged.data = "genesis-from-the-wal";
  staged.prev_hash = chainlog::genesis_prev_hash();
  staged.hash = chainlog::compute_record_hash(staged);
  stage_record(d, staged);

  Log log;
  CHECK(log.open(d.path(), opt, &err));
  CHECK_EQ(pname(log.scan_verdict().problem), "ok");
  CHECK_EQ(log.record_count(), 1ull);
  Record h;
  CHECK(log.head(&h));
  CHECK_EQ(h.index, 0ull);
  CHECK_EQ(h.data, "genesis-from-the-wal");
  log.close();
  CHECK_EQ(pname(verify_dir(d.path()).problem), "ok");
}

TEST(a_replay_that_completes_a_block_seals_it) {
  TempDir d;
  build_log(d.path(), 3, 4);  // one short of a full block
  const Record staged = next_record_for(d, "completes-the-block");
  stage_record(d, staged);

  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));

  // Recovery runs before the checkpoints are reconciled, precisely so that a
  // replayed record can complete a block and have it sealed in the same open.
  CHECK_EQ(log.record_count(), 4ull);
  CHECK_EQ(log.checkpoint_count(), 1ull);
  log.close();
  CHECK_EQ(pname(verify_dir(d.path()).problem), "ok");
}

// --- recovery: already applied --------------------------------------------

TEST(a_staged_record_already_in_the_log_is_just_cleared) {
  TempDir d;
  build_log(d.path(), 5);
  const std::string before = chainlog_test::read_file(log_file(d));

  // Exactly what a crash between step 2 and step 3 leaves: the log's own tail
  // record, still sitting in the WAL.
  stage_record(d, tail_of(d));

  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));

  CHECK_EQ(pname(log.scan_verdict().problem), "ok");
  CHECK_EQ(log.record_count(), 5ull);  // not 6: no duplication
  CHECK_EQ(wal_bytes(d), kWalHeaderBytes);
  // The log file must be byte-for-byte untouched.
  CHECK_EQ(chainlog_test::read_file(log_file(d)).size(), before.size());
  CHECK(chainlog_test::read_file(log_file(d)) == before);
  log.close();
  CHECK_EQ(pname(verify_dir(d.path()).problem), "ok");
}

// --- recovery: drop --------------------------------------------------------

TEST(a_torn_staged_frame_is_dropped_at_every_cut_point) {
  TempDir d;
  build_log(d.path(), 4);
  const std::string before = chainlog_test::read_file(log_file(d));

  std::string frame;
  chainlog::append_frame(next_record_for(d, "never-acknowledged"), &frame);

  // Every truncation point inside the staged frame. A torn frame means step
  // 1's fsync never returned, so append() never reported success and nobody
  // was told the record existed -- dropping it is correct, not data loss.
  // This is also why the staged frame needs its own CRC: without one, a
  // half-written record would be indistinguishable from a complete one.
  for (size_t keep = 0; keep < frame.size(); ++keep) {
    stage_bytes(d, frame.substr(0, keep));

    Log log;
    Log::Options opt;
    std::string err;
    CHECK(log.open(d.path(), opt, &err));
    CHECK_EQ(pname(log.scan_verdict().problem), "ok");
    CHECK_EQ(log.record_count(), 4ull);
    CHECK_EQ(wal_bytes(d), kWalHeaderBytes);
    CHECK(chainlog_test::read_file(log_file(d)) == before);
  }
  CHECK_EQ(pname(verify_dir(d.path()).problem), "ok");
}

TEST(a_staged_frame_with_a_recomputed_crc_is_still_dropped_if_it_lies) {
  TempDir d;
  build_log(d.path(), 4);

  // A frame whose CRC is correct but whose magic is not: damage rather than a
  // torn write. Still unusable, so still dropped rather than guessed at.
  std::string frame;
  chainlog::append_frame(next_record_for(d, "bad-magic-frame"), &frame);
  frame[0] = 'X';
  stage_bytes(d, frame);

  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  CHECK_EQ(pname(log.scan_verdict().problem), "ok");
  CHECK_EQ(log.record_count(), 4ull);
  CHECK_EQ(wal_bytes(d), kWalHeaderBytes);
}

// --- recovery: report ------------------------------------------------------

TEST(a_staged_record_that_does_not_fit_is_reported) {
  TempDir d;
  build_log(d.path(), 5);

  // A perfectly valid frame for a record far in the future. No crash can
  // produce this: the WAL holds at most one record and is cleared before the
  // next append begins, so this means a file was edited.
  Record alien;
  alien.index = 99;
  alien.timestamp_ns = 1700000000000000000ull;
  alien.data = "from-somewhere-else";
  alien.prev_hash.fill(0x5a);
  alien.hash = chainlog::compute_record_hash(alien);
  stage_record(d, alien);

  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));

  CHECK_EQ(pname(log.scan_verdict().problem), "bad-wal");
  CHECK_EQ(log.scan_verdict().index, 99ull);
  CHECK(log.wal_pending());
  CHECK(log.scan_verdict().detail.find("does not link") != std::string::npos);

  // verify() must surface it too: resolving a WAL needs write access, so
  // open() is the only thing that looks at one, but "does this directory
  // check out" has to include the answer.
  Verdict v;
  CHECK(log.verify(&v, &err));
  CHECK_EQ(pname(v.problem), "bad-wal");

  // And nothing may be built on a state that cannot be explained.
  Record r;
  CHECK(!log.append("should not land", &r, &err));
  CHECK_EQ(log.record_count(), 5ull);
}

TEST(a_staged_record_with_the_right_index_but_a_broken_link_is_reported) {
  TempDir d;
  build_log(d.path(), 5);

  // The subtler version: the index is exactly right, so a naive check would
  // replay it, but prev_hash points at nothing in this log.
  Record forged = next_record_for(d, "wrong-parent");
  forged.prev_hash.fill(0x11);
  forged.hash = chainlog::compute_record_hash(forged);
  stage_record(d, forged);

  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  CHECK_EQ(pname(log.scan_verdict().problem), "bad-wal");
  CHECK_EQ(log.record_count(), 5ull);
}

TEST(a_corrupt_wal_header_is_reported_not_repaired) {
  TempDir d;
  build_log(d.path(), 3);

  std::string bytes = chainlog_test::read_file(wal_file(d));
  bytes[4] = 'X';  // "CHLGWAL1" -> "CHLGXAL1"
  chainlog_test::write_file(wal_file(d), bytes);

  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  CHECK_EQ(pname(log.scan_verdict().problem), "bad-wal");

  Verdict v;
  CHECK(log.verify(&v, &err));
  CHECK_EQ(pname(v.problem), "bad-wal");
}

// --- locking ---------------------------------------------------------------

TEST(a_second_writer_is_refused) {
  TempDir d;
  build_log(d.path(), 2);

  Log first;
  Log::Options opt;
  std::string err;
  CHECK(first.open(d.path(), opt, &err));
  CHECK(first.locked());

  // flock locks belong to the open file description, not the process, so a
  // second open in the same process contends exactly as another process
  // would.
  Log second;
  std::string err2;
  CHECK(!second.open(d.path(), opt, &err2));
  CHECK(err2.find("another chainlog process") != std::string::npos);
  CHECK(err2.find(d.path()) != std::string::npos);

  // And close() releases it, so the second open then succeeds.
  first.close();
  Log third;
  CHECK(third.open(d.path(), opt, &err));
  CHECK(third.locked());
}

TEST(the_lock_is_released_when_the_log_is_closed) {
  TempDir d;
  build_log(d.path(), 2);

  Log::Options opt;
  std::string err;
  {
    Log first;
    CHECK(first.open(d.path(), opt, &err));
    CHECK(first.locked());
  }  // the Fd destructor closes the descriptor, which drops the lock

  Log second;
  CHECK(second.open(d.path(), opt, &err));
  CHECK(second.locked());
  Record r;
  CHECK(second.append("after the lock was released", &r, &err));
}

// --- read-only -------------------------------------------------------------

TEST(a_read_only_log_verifies_but_cannot_replay_or_append) {
  TempDir d;
  build_log(d.path(), 6, 4);
  const Record staged = next_record_for(d, "staged-but-unreplayable");
  stage_record(d, staged);
  const std::string before = chainlog_test::read_file(log_file(d));

  // Drop write permission on the files but not the directory, so the staged
  // record cannot be applied. Refusing to look at a log you cannot write
  // would make the verifier useless in exactly the case where you want it
  // most: inspecting an archive.
  CHECK_EQ(::chmod(log_file(d).c_str(), 0444), 0);
  CHECK_EQ(::chmod(wal_file(d).c_str(), 0444), 0);
  CHECK_EQ(::chmod(Log::checkpoints_path(d.path()).c_str(), 0444), 0);

  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  CHECK(log.read_only());

  // The chain itself is intact, and says so.
  Verdict v;
  CHECK(log.verify(&v, &err));
  CHECK_EQ(pname(v.problem), "ok");
  CHECK_EQ(v.records_verified, 6ull);

  // But the staged record is still staged, and that is reported rather than
  // hidden -- the count above is not the final one.
  CHECK(log.wal_pending());
  CHECK_EQ(log.record_count(), 6ull);
  CHECK(chainlog_test::read_file(log_file(d)) == before);

  Record r;
  CHECK(!log.append("nope", &r, &err));
  CHECK(err.find("read-only") != std::string::npos);
  log.close();

  // Restore permissions so the directory can be cleaned up, then confirm the
  // same staged record IS replayed once writing is possible.
  CHECK_EQ(::chmod(log_file(d).c_str(), 0644), 0);
  CHECK_EQ(::chmod(wal_file(d).c_str(), 0644), 0);
  CHECK_EQ(::chmod(Log::checkpoints_path(d.path()).c_str(), 0644), 0);

  Log writable;
  CHECK(writable.open(d.path(), opt, &err));
  CHECK(!writable.read_only());
  CHECK(!writable.wal_pending());
  CHECK_EQ(writable.record_count(), 7ull);
  writable.close();
  CHECK_EQ(pname(verify_dir(d.path()).problem), "ok");
}
