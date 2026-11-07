// Hash chain tests, including the tamper escalation ladder.
//
// The ladder is the heart of this file. It walks an attacker from the laziest
// possible edit to the most thorough one, and shows which layer of the format
// catches each step -- and where the chain alone runs out of answers. Every
// "NOT detected" test below is a documented limitation, not a bug: those are
// precisely the cases that anchoring (phase 5) exists to close.

#include <cstdio>
#include <string>
#include <vector>

#include "hex.h"
#include "log.h"
#include "log_fixture.h"
#include "test.h"

using chainlog::Log;
using chainlog::Record;
using chainlog::Verdict;
using chainlog::to_hex;
using chainlog_test::FrameSpan;
using chainlog_test::build_log;
using chainlog_test::record_label;
using chainlog_test::TempDir;
using chainlog_test::verify_dir;

namespace {

std::string pname(chainlog::Problem p) { return chainlog::problem_name(p); }

std::string log_file(const TempDir& d) { return Log::log_path(d.path()); }

}  // namespace

// --- the happy path ---------------------------------------------------------

TEST(a_fresh_log_is_empty_and_verifies) {
  TempDir d;
  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  CHECK_EQ(err, "");
  CHECK_EQ(log.record_count(), 0ull);
  CHECK_EQ(log.block_size(), chainlog::kDefaultBlockSize);

  Record r;
  CHECK(!log.head(&r));  // nothing to point at yet

  Verdict v;
  CHECK(log.verify(&v, &err));
  CHECK_EQ(pname(v.problem), "ok");
  CHECK_EQ(v.records_verified, 0ull);
}

TEST(the_genesis_record_links_to_all_zeros) {
  TempDir d;
  build_log(d.path(), 1);
  const std::vector<Record> rs =
      chainlog_test::read_frames(chainlog_test::read_file(log_file(d)));
  CHECK_EQ(rs.size(), static_cast<size_t>(1));
  CHECK_EQ(rs[0].index, 0ull);
  CHECK_EQ(to_hex(rs[0].prev_hash),
           "0000000000000000000000000000000000000000000000000000000000000000");
}

TEST(each_record_links_to_the_previous_one) {
  TempDir d;
  build_log(d.path(), 25);
  const std::vector<Record> rs =
      chainlog_test::read_frames(chainlog_test::read_file(log_file(d)));
  CHECK_EQ(rs.size(), static_cast<size_t>(25));
  for (size_t i = 0; i < rs.size(); ++i) {
    CHECK_EQ(rs[i].index, static_cast<unsigned long long>(i));
    CHECK_EQ(rs[i].data, record_label(i));
    CHECK_EQ(to_hex(rs[i].hash), to_hex(chainlog::compute_record_hash(rs[i])));
    if (i > 0) {
      CHECK_EQ(to_hex(rs[i].prev_hash), to_hex(rs[i - 1].hash));
    }
  }
  CHECK_EQ(pname(verify_dir(d.path()).problem), "ok");
  CHECK_EQ(verify_dir(d.path()).records_verified, 25ull);
}

TEST(reopening_continues_the_chain) {
  TempDir d;
  build_log(d.path(), 10);

  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  CHECK_EQ(log.record_count(), 10ull);

  Record tail;
  CHECK(log.head(&tail));
  CHECK_EQ(tail.index, 9ull);

  Record fresh;
  CHECK(log.append("after reopen", &fresh, &err));
  CHECK_EQ(fresh.index, 10ull);
  // The new record must link to the record that was already on disk, which is
  // the whole point of scanning the tail at open time.
  CHECK_EQ(to_hex(fresh.prev_hash), to_hex(tail.hash));

  // The exclusive lock is held until close(), so verify_dir() -- which opens
  // the directory itself -- has to wait its turn.
  log.close();
  CHECK_EQ(pname(verify_dir(d.path()).problem), "ok");
}

TEST(head_and_stats_describe_the_log) {
  TempDir d;
  Log log;
  Log::Options opt;
  opt.block_size = 8;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  for (uint64_t i = 0; i < 20; ++i) {
    Record r;
    CHECK(log.append(record_label(i), &r, &err));
  }

  Record h;
  CHECK(log.head(&h));
  CHECK_EQ(h.index, 19ull);
  CHECK_EQ(h.data, record_label(19));

  const Log::Stats s = log.stats();
  CHECK_EQ(s.record_count, 20ull);
  CHECK_EQ(s.data_bytes, 20ull * record_label(0).size());
  CHECK_EQ(s.block_size, 8ull);
  CHECK_EQ(s.sealed_blocks, 2ull);  // 20 / 8
  CHECK_EQ(s.log_bytes,
           chainlog::kHeaderBytes +
               20ull * (chainlog::kFrameOverheadBytes +
                        chainlog::kPayloadFixedBytes + record_label(0).size()));

  // block_size came from the options on create; it must survive a reopen,
  // because the checkpoints are only meaningful relative to it.
  log.close();
  Log again;
  Log::Options defaults;
  CHECK(again.open(d.path(), defaults, &err));
  CHECK_EQ(again.block_size(), 8ull);
}

TEST(records_can_hold_arbitrary_bytes) {
  TempDir d;
  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));

  const std::string payloads[] = {
      "",
      std::string("\0", 1),
      std::string("a\0b\0\0c", 6),
      std::string("\xff\x00\xfe\x01", 4),
      std::string(100000, 'q'),
  };
  for (const std::string& p : payloads) {
    Record r;
    CHECK(log.append(p, &r, &err));
  }
  log.close();
  CHECK_EQ(pname(verify_dir(d.path()).problem), "ok");

  const std::vector<Record> rs =
      chainlog_test::read_frames(chainlog_test::read_file(log_file(d)));
  CHECK_EQ(rs.size(), static_cast<size_t>(5));
  for (size_t i = 0; i < rs.size(); ++i) {
    CHECK(rs[i].data == payloads[i]);
  }
}

TEST(oversized_records_are_refused) {
  TempDir d;
  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  Record r;
  CHECK(!log.append(std::string(chainlog::kMaxDataLen + 1, 'x'), &r, &err));
  CHECK(err.find("limit") != std::string::npos);
  CHECK_EQ(log.record_count(), 0ull);
}

// --- the tamper escalation ladder -------------------------------------------
//
// Step 1: edit a byte and walk away.
// Step 2: edit a byte, fix the CRC.
// Step 3: edit a byte, fix the CRC, recompute that record's hash.
// Step 4: edit a byte and re-link the entire rest of the file.
//
// Each step defeats the previous layer. Step 4 defeats everything the file can
// check on its own, which is exactly the argument for publishing the head.

TEST(tamper_step1_a_naive_byte_flip_is_caught_by_the_crc) {
  TempDir d;
  build_log(d.path(), 50);

  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  // Somewhere inside record 20's payload.
  const size_t target = static_cast<size_t>(spans[20].offset) + 30;
  bytes[target] = static_cast<char>(bytes[target] ^ 0x01);
  chainlog_test::write_file(log_file(d), bytes);

  const Verdict v = verify_dir(d.path());
  CHECK_EQ(pname(v.problem), "bad-crc");
  CHECK_EQ(v.index, 20ull);
  CHECK_EQ(v.records_verified, 20ull);
  CHECK_EQ(v.offset, spans[20].offset);
}

TEST(tamper_step2_a_recomputed_crc_is_caught_by_the_record_hash) {
  TempDir d;
  build_log(d.path(), 50);

  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  std::vector<Record> rs = chainlog_test::read_frames(bytes);

  // Change the data and re-frame it, which recomputes the CRC but leaves the
  // stored hash as it was.
  Record forged = rs[20];
  forged.data = "rec-HACKED";  // same length as "rec-000020"
  CHECK_EQ(forged.data.size(), rs[20].data.size());
  chainlog_test::rewrite_frame(&bytes, spans[20].offset, forged);
  chainlog_test::write_file(log_file(d), bytes);

  const Verdict v = verify_dir(d.path());
  CHECK_EQ(pname(v.problem), "bad-hash");
  CHECK_EQ(v.index, 20ull);
}

TEST(tamper_step3_a_recomputed_hash_is_caught_by_the_next_link) {
  TempDir d;
  build_log(d.path(), 50);

  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  std::vector<Record> rs = chainlog_test::read_frames(bytes);

  Record forged = rs[20];
  forged.data = "rec-HACKED";
  forged.hash = chainlog::compute_record_hash(forged);
  chainlog_test::rewrite_frame(&bytes, spans[20].offset, forged);
  chainlog_test::write_file(log_file(d), bytes);

  // Record 20 is now internally perfect: correct CRC, correct hash of its own
  // bytes, correct link to 19. Record 21 still points at the OLD hash of 20,
  // so the break surfaces one record later. That is the hash chain working.
  const Verdict v = verify_dir(d.path());
  CHECK_EQ(pname(v.problem), "broken-link");
  CHECK_EQ(v.index, 21ull);
  CHECK_EQ(v.records_verified, 21ull);
}

TEST(tamper_step4_relinking_the_whole_tail_is_NOT_detected) {
  TempDir d;
  build_log(d.path(), 50);

  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  std::vector<Record> rs = chainlog_test::read_frames(bytes);

  Record forged = rs[20];
  forged.data = "rec-HACKED";
  chainlog_test::rewrite_frame(&bytes, spans[20].offset, forged);
  chainlog_test::relink_from(&bytes, 20);
  chainlog_test::write_file(log_file(d), bytes);

  // DOCUMENTED LIMITATION. An attacker with write access to the whole file can
  // rewrite history and re-link it into a chain that is perfectly
  // self-consistent. Nothing inside the file can detect this, because there is
  // nothing left in the file that remembers the old history.
  //
  // The fix is not a better hash; it is to get a copy of the head out of the
  // attacker's reach. See `chainlog verify --anchor` in phase 5.
  const Verdict v = verify_dir(d.path());
  CHECK_EQ(pname(v.problem), "ok");
  CHECK_EQ(v.records_verified, 50ull);

  // The forgery is nonetheless present, which is what makes the anchor check
  // able to catch it: the head hash is now different from what it was.
  const std::vector<Record> after = chainlog_test::read_frames(bytes);
  CHECK_EQ(after[20].data, "rec-HACKED");
  CHECK(to_hex(after[49].hash) != to_hex(rs[49].hash));
}

TEST(editing_a_stored_hash_blames_that_record_not_the_next_one) {
  TempDir d;
  build_log(d.path(), 30);

  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  std::vector<Record> rs = chainlog_test::read_frames(bytes);

  // Only the stored hash field is touched; the record's own bytes are intact.
  Record forged = rs[12];
  forged.hash.fill(0x77);
  chainlog_test::rewrite_frame(&bytes, spans[12].offset, forged);
  chainlog_test::write_file(log_file(d), bytes);

  // Because verify() chains on the COMPUTED hash rather than the stored one,
  // the blame lands on record 12 -- the record that was actually modified --
  // instead of showing up as a broken link at 13, which was not touched.
  const Verdict v = verify_dir(d.path());
  CHECK_EQ(pname(v.problem), "bad-hash");
  CHECK_EQ(v.index, 12ull);
}

// --- structural attacks -----------------------------------------------------

TEST(deleting_a_record_is_caught_as_a_bad_index) {
  TempDir d;
  build_log(d.path(), 40);

  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  bytes.erase(static_cast<size_t>(spans[15].offset),
              static_cast<size_t>(spans[15].length));
  chainlog_test::write_file(log_file(d), bytes);

  // Record 16 now sits where 15 should be. The index sequence catches it
  // before the link check does, which is why index is checked first: "a
  // record is missing" is a more useful diagnosis than "a hash did not match".
  const Verdict v = verify_dir(d.path());
  CHECK_EQ(pname(v.problem), "bad-index");
  CHECK_EQ(v.index, 15ull);
  CHECK(v.detail.find("frame says 16") != std::string::npos);
}

TEST(swapping_two_records_is_caught_as_a_bad_index) {
  TempDir d;
  build_log(d.path(), 40);

  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  CHECK_EQ(spans[10].length, spans[11].length);  // fixed-width data

  const size_t len = static_cast<size_t>(spans[10].length);
  const std::string a = bytes.substr(static_cast<size_t>(spans[10].offset), len);
  const std::string b = bytes.substr(static_cast<size_t>(spans[11].offset), len);
  bytes.replace(static_cast<size_t>(spans[10].offset), len, b);
  bytes.replace(static_cast<size_t>(spans[11].offset), len, a);
  chainlog_test::write_file(log_file(d), bytes);

  const Verdict v = verify_dir(d.path());
  CHECK_EQ(pname(v.problem), "bad-index");
  CHECK_EQ(v.index, 10ull);
}

TEST(reordering_records_without_changing_the_index_breaks_the_link) {
  TempDir d;
  build_log(d.path(), 40);

  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  std::vector<Record> rs = chainlog_test::read_frames(bytes);

  // Swap only the DATA of two records, keeping indexes and links in place --
  // the subtlest reordering an attacker could attempt. The index check now
  // passes, so this has to be caught by the hash.
  Record x = rs[10];
  Record y = rs[11];
  const std::string tmp = x.data;
  x.data = y.data;
  y.data = tmp;
  chainlog_test::rewrite_frame(&bytes, spans[10].offset, x);
  chainlog_test::rewrite_frame(&bytes, spans[11].offset, y);
  chainlog_test::write_file(log_file(d), bytes);

  const Verdict v = verify_dir(d.path());
  CHECK_EQ(pname(v.problem), "bad-hash");
  CHECK_EQ(v.index, 10ull);
}

TEST(truncating_mid_frame_is_reported_as_a_torn_tail) {
  TempDir d;
  build_log(d.path(), 30);

  const std::string whole = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(whole);

  // Cut the file at every byte inside the last frame. All of these are
  // "a write did not finish", never "someone changed history".
  for (uint64_t cut = spans[29].offset + 1; cut < whole.size(); ++cut) {
    chainlog_test::write_file(log_file(d),
                              whole.substr(0, static_cast<size_t>(cut)));
    const Verdict v = verify_dir(d.path());
    CHECK_EQ(pname(v.problem), "torn-tail");
    CHECK_EQ(v.index, 29ull);
    CHECK_EQ(v.records_verified, 29ull);
  }
}

TEST(truncating_at_a_frame_boundary_is_NOT_detected) {
  TempDir d;
  build_log(d.path(), 30);

  const std::string whole = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(whole);
  // Keep records 0..19, drop the rest cleanly.
  chainlog_test::write_file(
      log_file(d), whole.substr(0, static_cast<size_t>(spans[20].offset)));

  // DOCUMENTED LIMITATION. A hash chain proves that what is present has not
  // been altered. It says nothing about what used to be there: a prefix of a
  // valid chain is itself a valid chain. Cutting the tail off is therefore
  // invisible from inside the file.
  //
  // This is the second reason for anchoring, and it is a different reason from
  // step 4 above: there the content changed, here only the length did.
  const Verdict v = verify_dir(d.path());
  CHECK_EQ(pname(v.problem), "ok");
  CHECK_EQ(v.records_verified, 20ull);
}

TEST(corrupting_the_file_header_is_caught) {
  TempDir d;
  build_log(d.path(), 5);

  std::string bytes = chainlog_test::read_file(log_file(d));
  bytes[2] = 'X';  // "CHAINLOG" -> "CHXINLOG"
  chainlog_test::write_file(log_file(d), bytes);

  const Verdict v = verify_dir(d.path());
  CHECK_EQ(pname(v.problem), "bad-header");
  CHECK_EQ(v.records_verified, 0ull);
}

TEST(a_corrupted_frame_length_does_not_become_a_huge_allocation) {
  TempDir d;
  build_log(d.path(), 5);

  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  uint8_t* p = reinterpret_cast<uint8_t*>(&bytes[0]);
  // Claim a 4 GiB payload. Caught by the cap in parse_frame_header, so the
  // reader never tries to buffer it.
  chainlog::put_u32_le(p + spans[2].offset + 4, 0xFFFFFFFFu);
  chainlog_test::write_file(log_file(d), bytes);

  const Verdict v = verify_dir(d.path());
  CHECK_EQ(pname(v.problem), "bad-frame-length");
  CHECK_EQ(v.index, 2ull);
}

TEST(verify_reports_the_first_problem_not_a_later_one) {
  TempDir d;
  build_log(d.path(), 60);

  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  // Damage records 40 and 10, in that order, so the later edit happens first
  // in time and the earlier one is the one that must be reported.
  for (size_t idx : {size_t(40), size_t(10)}) {
    const size_t at = static_cast<size_t>(spans[idx].offset) + 25;
    bytes[at] = static_cast<char>(bytes[at] ^ 0x80);
  }
  chainlog_test::write_file(log_file(d), bytes);

  const Verdict v = verify_dir(d.path());
  CHECK_EQ(pname(v.problem), "bad-crc");
  CHECK_EQ(v.index, 10ull);
}

TEST(append_refuses_on_a_damaged_log) {
  TempDir d;
  build_log(d.path(), 10);

  const std::string whole = chainlog_test::read_file(log_file(d));
  // Leave a torn frame at the tail, the way a crash would.
  chainlog_test::write_file(log_file(d), whole.substr(0, whole.size() - 7));

  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  CHECK(!log.scan_verdict().ok());
  CHECK_EQ(pname(log.scan_verdict().problem), "torn-tail");

  Record r;
  CHECK(!log.append("should not land", &r, &err));
  CHECK(err.find("damaged") != std::string::npos);

  // And the file is untouched by the refused append.
  CHECK_EQ(chainlog_test::read_file(log_file(d)).size(), whole.size() - 7);
}
