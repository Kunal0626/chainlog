// Checkpoint format, sealing, checkpoint verification, and proofs taken from
// a real log.
//
// Phase 2 ended with two documented holes: re-linking the whole tail, and
// truncating at a frame boundary, were both invisible. Checkpoints close the
// first one -- not because the hash got better, but because the sealed roots
// are a second, independent record of history that the attacker also has to
// rewrite. The ladder here picks up where test_log.cpp left off.

#include <cstdio>
#include <string>
#include <vector>

#include "checkpoint.h"
#include "crc32.h"
#include "hex.h"
#include "log.h"
#include "log_fixture.h"
#include "merkle.h"
#include "test.h"

using chainlog::Checkpoint;
using chainlog::CheckpointHeader;
using chainlog::Digest;
using chainlog::Log;
using chainlog::Problem;
using chainlog::Proof;
using chainlog::Record;
using chainlog::Verdict;
using chainlog::to_hex;
using chainlog_test::FrameSpan;
using chainlog_test::TempDir;
using chainlog_test::build_log;
using chainlog_test::record_label;
using chainlog_test::verify_dir;

namespace {

std::string pname(Problem p) { return chainlog::problem_name(p); }

std::string log_file(const TempDir& d) { return Log::log_path(d.path()); }
std::string ckpt_file(const TempDir& d) {
  return Log::checkpoints_path(d.path());
}

std::vector<Checkpoint> read_cps(const TempDir& d) {
  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  std::vector<Checkpoint> cps;
  Verdict v;
  CHECK(log.read_checkpoints(&cps, &v, &err));
  return cps;
}

// Offsets of the checkpoint frames inside the checkpoints file. Every frame is
// the same size in format version 1, so this is arithmetic.
uint64_t ckpt_offset(size_t i) {
  return chainlog::kCheckpointHeaderBytes +
         i * (chainlog::kCheckpointOverheadBytes +
              chainlog::kCheckpointPayloadBytes);
}

void rewrite_checkpoint(std::string* bytes, size_t i, const Checkpoint& c) {
  std::string frame;
  chainlog::append_checkpoint_frame(c, &frame);
  bytes->replace(static_cast<size_t>(ckpt_offset(i)), frame.size(), frame);
}

}  // namespace

// --- the frame format ------------------------------------------------------

TEST(checkpoint_header_round_trips_and_rejects_damage) {
  CheckpointHeader in;
  in.block_size = 512;
  std::string buf;
  chainlog::encode_checkpoint_header(in, &buf);
  CHECK_EQ(buf.size(), chainlog::kCheckpointHeaderBytes);
  CHECK_EQ(std::string(buf, 0, 8), "CHLGCKPT");

  CheckpointHeader out;
  std::string detail;
  CHECK_EQ(pname(chainlog::decode_checkpoint_header(buf.data(), buf.size(),
                                                    &out, &detail)),
           "ok");
  CHECK_EQ(out.block_size, 512ull);

  // Any flipped bit in the covered range must be caught.
  for (size_t i = 0; i < 28; ++i) {
    std::string bad = buf;
    bad[i] = static_cast<char>(bad[i] ^ 0x01);
    CHECK_EQ(pname(chainlog::decode_checkpoint_header(bad.data(), bad.size(),
                                                      &out, &detail)),
             "bad-checkpoint");
  }
}

TEST(checkpoint_frame_round_trips) {
  Checkpoint in;
  in.first_index = 1024;
  in.last_index = 2047;
  in.root = chainlog::Sha256::hash("a root");

  std::string frame;
  chainlog::append_checkpoint_frame(in, &frame);
  CHECK_EQ(frame.size(), chainlog::kCheckpointOverheadBytes +
                             chainlog::kCheckpointPayloadBytes);
  CHECK_EQ(std::string(frame, 0, 4), "CKPT");

  Checkpoint out;
  size_t consumed = 0;
  std::string detail;
  CHECK_EQ(pname(chainlog::decode_checkpoint_frame(frame.data(), frame.size(),
                                                   &out, &consumed, &detail)),
           "ok");
  CHECK_EQ(consumed, frame.size());
  CHECK_EQ(out.first_index, 1024ull);
  CHECK_EQ(out.last_index, 2047ull);
  CHECK_EQ(out.leaf_count(), 1024ull);
  CHECK_EQ(to_hex(out.root), to_hex(in.root));
}

TEST(checkpoint_frame_decoding_rejects_damage) {
  Checkpoint in;
  in.first_index = 8;
  in.last_index = 15;
  in.root = chainlog::Sha256::hash("x");
  std::string frame;
  chainlog::append_checkpoint_frame(in, &frame);

  Checkpoint out;
  std::string detail;

  // A short buffer is a torn tail, not corruption: it is always at end of
  // file and it means a write did not finish.
  for (size_t keep = 0; keep < frame.size(); ++keep) {
    CHECK_EQ(pname(chainlog::decode_checkpoint_frame(frame.data(), keep, &out,
                                                     nullptr, &detail)),
             "torn-checkpoint-tail");
  }

  std::string bad_magic = frame;
  bad_magic[1] = 'X';
  CHECK_EQ(pname(chainlog::decode_checkpoint_frame(
               bad_magic.data(), bad_magic.size(), &out, nullptr, &detail)),
           "bad-checkpoint");

  std::string bad_crc = frame;
  bad_crc[20] = static_cast<char>(bad_crc[20] ^ 0x01);
  CHECK_EQ(pname(chainlog::decode_checkpoint_frame(
               bad_crc.data(), bad_crc.size(), &out, nullptr, &detail)),
           "bad-checkpoint");

  // A range that runs backwards would make leaf_count() underflow into a
  // gigantic number, so it is rejected at parse time rather than trusted.
  Checkpoint backwards;
  backwards.first_index = 100;
  backwards.last_index = 99;
  std::string rev;
  chainlog::append_checkpoint_frame(backwards, &rev);
  CHECK_EQ(pname(chainlog::decode_checkpoint_frame(rev.data(), rev.size(), &out,
                                                   nullptr, &detail)),
           "bad-checkpoint");
  CHECK(detail.find("backwards") != std::string::npos);
}

// --- sealing ---------------------------------------------------------------

TEST(blocks_are_sealed_at_boundaries_and_nowhere_else) {
  TempDir d;
  Log log;
  Log::Options opt;
  opt.block_size = 4;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));

  // 0,1,2 -> nothing sealed; 3 completes the first block.
  for (uint64_t i = 0; i < 3; ++i) {
    Record r;
    CHECK(log.append(record_label(i), &r, &err));
    CHECK_EQ(log.checkpoint_count(), 0ull);
  }
  Record r;
  CHECK(log.append(record_label(3), &r, &err));
  CHECK_EQ(log.checkpoint_count(), 1ull);

  for (uint64_t i = 4; i < 7; ++i) {
    CHECK(log.append(record_label(i), &r, &err));
    CHECK_EQ(log.checkpoint_count(), 1ull);
  }
  CHECK(log.append(record_label(7), &r, &err));
  CHECK_EQ(log.checkpoint_count(), 2ull);

  const Log::Stats s = log.stats();
  CHECK_EQ(s.record_count, 8ull);
  CHECK_EQ(s.checkpoint_count, 2ull);
  CHECK_EQ(s.pending_records, 0ull);
}

TEST(checkpoints_cover_contiguous_ranges_and_match_recomputed_roots) {
  TempDir d;
  build_log(d.path(), 40, 8);

  const std::vector<Checkpoint> cps = read_cps(d);
  CHECK_EQ(cps.size(), static_cast<size_t>(5));

  const std::vector<Record> rs =
      chainlog_test::read_frames(chainlog_test::read_file(log_file(d)));
  CHECK_EQ(rs.size(), static_cast<size_t>(40));

  for (size_t b = 0; b < cps.size(); ++b) {
    CHECK_EQ(cps[b].first_index, b * 8);
    CHECK_EQ(cps[b].last_index, b * 8 + 7);
    CHECK_EQ(cps[b].leaf_count(), 8ull);

    // Recompute the root from the records and compare with what was sealed.
    std::vector<Digest> leaves;
    for (size_t i = b * 8; i < b * 8 + 8; ++i) {
      leaves.push_back(chainlog::compute_record_hash(rs[i]));
    }
    CHECK_EQ(to_hex(cps[b].root), to_hex(chainlog::merkle_root(leaves)));
  }

  CHECK_EQ(pname(verify_dir(d.path()).problem), "ok");
}

TEST(pending_records_are_not_sealed) {
  TempDir d;
  build_log(d.path(), 21, 8);
  CHECK_EQ(read_cps(d).size(), static_cast<size_t>(2));

  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  const Log::Stats s = log.stats();
  CHECK_EQ(s.record_count, 21ull);
  CHECK_EQ(s.checkpoint_count, 2ull);
  CHECK_EQ(s.pending_records, 5ull);
  CHECK_EQ(pname(verify_dir(d.path()).problem), "ok");
}

// --- checkpoint tampering --------------------------------------------------

TEST(editing_a_checkpoint_root_is_caught) {
  TempDir d;
  build_log(d.path(), 24, 8);

  std::string bytes = chainlog_test::read_file(ckpt_file(d));
  std::vector<Checkpoint> cps = read_cps(d);
  Checkpoint forged = cps[1];
  forged.root[0] ^= 0x01;
  rewrite_checkpoint(&bytes, 1, forged);
  chainlog_test::write_file(ckpt_file(d), bytes);

  const Verdict v = verify_dir(d.path());
  CHECK_EQ(pname(v.problem), "bad-checkpoint");
  CHECK_EQ(v.index, 8ull);  // the first record of the block it covers
  CHECK(v.detail.find("checkpoint says") != std::string::npos);
}

TEST(editing_a_checkpoint_range_is_caught) {
  TempDir d;
  build_log(d.path(), 24, 8);

  std::string bytes = chainlog_test::read_file(ckpt_file(d));
  std::vector<Checkpoint> cps = read_cps(d);
  Checkpoint forged = cps[1];
  forged.first_index = 9;  // claims 9..15 instead of 8..15
  rewrite_checkpoint(&bytes, 1, forged);
  chainlog_test::write_file(ckpt_file(d), bytes);

  const Verdict v = verify_dir(d.path());
  CHECK_EQ(pname(v.problem), "bad-checkpoint");
  CHECK(v.detail.find("expected") != std::string::npos);
}

TEST(deleting_the_last_two_checkpoints_is_reported_not_repaired) {
  TempDir d;
  build_log(d.path(), 32, 8);  // four blocks, four checkpoints
  CHECK_EQ(read_cps(d).size(), static_cast<size_t>(4));

  // Cut the file back to two checkpoints.
  const std::string bytes = chainlog_test::read_file(ckpt_file(d));
  chainlog_test::write_file(ckpt_file(d),
                            bytes.substr(0, static_cast<size_t>(ckpt_offset(2))));

  // Two missing blocks cannot come from a crash: sealing happens inside
  // append() before the next record can be written, so at most one block can
  // ever be unsealed. Re-deriving the roots here would destroy the evidence
  // that makes checkpoints useful, so open() reports instead of repairing.
  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  CHECK_EQ(pname(log.scan_verdict().problem), "bad-checkpoint");
  CHECK(log.scan_verdict().detail.find("at most one") != std::string::npos);
  CHECK_EQ(read_cps(d).size(), static_cast<size_t>(2));  // untouched

  Record r;
  CHECK(!log.append("should not land", &r, &err));
}

TEST(one_missing_checkpoint_is_resealed_on_open) {
  TempDir d;
  build_log(d.path(), 32, 8);

  const std::string before = chainlog_test::read_file(ckpt_file(d));
  const std::vector<Checkpoint> original = read_cps(d);
  CHECK_EQ(original.size(), static_cast<size_t>(4));

  // Exactly the state a crash between the record fsync and the checkpoint
  // fsync leaves behind: the records of a complete block, with no checkpoint.
  chainlog_test::write_file(ckpt_file(d),
                            before.substr(0, static_cast<size_t>(ckpt_offset(3))));

  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));
  CHECK_EQ(pname(log.scan_verdict().problem), "ok");
  CHECK_EQ(log.checkpoint_count(), 4ull);

  // And the re-derived checkpoint must be byte-identical to the original,
  // because a checkpoint is a pure function of the records it covers.
  const std::vector<Checkpoint> after = read_cps(d);
  CHECK_EQ(after.size(), static_cast<size_t>(4));
  CHECK_EQ(to_hex(after[3].root), to_hex(original[3].root));
  CHECK_EQ(after[3].first_index, original[3].first_index);
  CHECK_EQ(after[3].last_index, original[3].last_index);
  CHECK_EQ(chainlog_test::read_file(ckpt_file(d)).size(), before.size());
  CHECK_EQ(pname(verify_dir(d.path()).problem), "ok");
}

TEST(a_torn_checkpoint_tail_is_repaired_on_open) {
  TempDir d;
  build_log(d.path(), 32, 8);
  const std::string whole = chainlog_test::read_file(ckpt_file(d));

  // A crash part-way through the last checkpoint write. Derived data, so
  // cutting the partial frame off and recomputing loses nothing.
  for (uint64_t keep = ckpt_offset(3) + 1; keep < whole.size(); ++keep) {
    chainlog_test::write_file(ckpt_file(d),
                              whole.substr(0, static_cast<size_t>(keep)));
    Log log;
    Log::Options opt;
    std::string err;
    CHECK(log.open(d.path(), opt, &err));
    CHECK_EQ(pname(log.scan_verdict().problem), "ok");
    CHECK_EQ(log.checkpoint_count(), 4ull);
    CHECK_EQ(chainlog_test::read_file(ckpt_file(d)), whole);
  }
}

TEST(a_checkpoints_file_from_another_log_is_caught) {
  TempDir a;
  TempDir b;
  build_log(a.path(), 16, 8);
  build_log(b.path(), 16, 4);  // different block size

  // Swap in the other log's checkpoints file.
  chainlog_test::write_file(ckpt_file(a),
                            chainlog_test::read_file(ckpt_file(b)));

  // This is the duplicated block_size in the two headers earning its keep.
  const Verdict v = verify_dir(a.path());
  CHECK_EQ(pname(v.problem), "bad-checkpoint");
  CHECK(v.detail.find("disagrees with the log's") != std::string::npos);
}

// --- the ladder continues ---------------------------------------------------

// Phase 2's step 4 -- edit a record and re-link the whole tail -- was
// undetectable with the chain alone. It is not any more: the sealed roots are
// a second copy of history, and the attacker did not update them.
TEST(tamper_step5_relinking_the_log_is_caught_by_the_checkpoints) {
  TempDir d;
  build_log(d.path(), 40, 8);
  CHECK_EQ(pname(verify_dir(d.path()).problem), "ok");

  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  std::vector<Record> rs = chainlog_test::read_frames(bytes);

  Record forged = rs[20];
  forged.data = "rec-HACKED";  // same length as "rec-000020"
  CHECK_EQ(forged.data.size(), rs[20].data.size());
  chainlog_test::rewrite_frame(&bytes, spans[20].offset, forged);
  chainlog_test::relink_from(&bytes, 20);
  chainlog_test::write_file(log_file(d), bytes);

  // The chain is now perfectly self-consistent -- and the root of block 2
  // (records 16..23) no longer matches what was sealed.
  const Verdict v = verify_dir(d.path());
  CHECK_EQ(pname(v.problem), "bad-checkpoint");
  CHECK_EQ(v.index, 16ull);
  CHECK_EQ(v.records_verified, 24ull);  // the whole block read before the check
}

// The final rung. An attacker who rewrites the records AND re-seals the
// checkpoints leaves nothing inside the log directory to contradict them.
TEST(tamper_step6_rewriting_the_checkpoints_too_is_NOT_detected) {
  TempDir d;
  build_log(d.path(), 40, 8);

  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  std::vector<Record> rs = chainlog_test::read_frames(bytes);
  const Digest original_head = rs[39].hash;

  Record forged = rs[20];
  forged.data = "rec-HACKED";
  chainlog_test::rewrite_frame(&bytes, spans[20].offset, forged);
  chainlog_test::relink_from(&bytes, 20);
  chainlog_test::write_file(log_file(d), bytes);
  chainlog_test::reseal_all_checkpoints(d.path());

  // DOCUMENTED LIMITATION. Everything inside the directory now agrees with
  // everything else, because the attacker controlled all of it. No amount of
  // hashing fixes this: the only remedy is to have published the head hash
  // somewhere the attacker cannot reach, which is what phase 5's
  // `verify --anchor` checks.
  const Verdict v = verify_dir(d.path());
  CHECK_EQ(pname(v.problem), "ok");
  CHECK_EQ(v.records_verified, 40ull);

  // The forgery is nonetheless visible from outside: the head hash changed.
  // That single 32-byte value is what an anchor stores.
  const std::vector<Record> after = chainlog_test::read_frames(bytes);
  CHECK_EQ(after[20].data, "rec-HACKED");
  CHECK(to_hex(after[39].hash) != to_hex(original_head));
}

// --- proofs against a real log ---------------------------------------------

TEST(every_sealed_record_can_be_proved_and_verified) {
  TempDir d;
  build_log(d.path(), 24, 8);

  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));

  for (uint64_t i = 0; i < 24; ++i) {
    Log::ProveResult res;
    CHECK(log.prove(i, &res, &err));
    CHECK(res.outcome == Log::ProveOutcome::kOk);

    const uint64_t tree_size = res.checkpoint.leaf_count();
    const uint64_t leaf_index = i - res.checkpoint.first_index;
    CHECK_EQ(tree_size, 8ull);
    CHECK_EQ(res.checkpoint.first_index, (i / 8) * 8);
    CHECK_EQ(res.record.index, i);
    CHECK_EQ(res.record.data, record_label(i));

    // The proof must verify from the record's fields alone, with no access to
    // the log -- that is the whole point of an inclusion proof.
    std::string detail;
    const Digest record_hash = chainlog::compute_record_hash(res.record);
    CHECK_EQ(to_hex(record_hash), to_hex(res.record.hash));
    if (!chainlog::merkle_verify_proof(record_hash, leaf_index, tree_size,
                                       res.proof, res.checkpoint.root,
                                       &detail)) {
      CHECK_EQ(detail, "(should have verified)");
    }

    // 8 leaves, so every path is exactly 3 steps.
    CHECK_EQ(res.proof.size(), static_cast<size_t>(3));

    // And it must survive the wire format.
    const std::string hex = chainlog::encode_proof(
        res.checkpoint.first_index, tree_size, leaf_index, res.proof);
    uint64_t first = 0;
    uint64_t size = 0;
    uint64_t leaf = 0;
    Proof back;
    CHECK(chainlog::decode_proof(hex, &first, &size, &leaf, &back, &detail));
    CHECK_EQ(first + leaf, i);
    CHECK(chainlog::merkle_verify_proof(record_hash, leaf, size, back,
                                        res.checkpoint.root, &detail));
  }
}

TEST(unsealed_and_missing_records_cannot_be_proved) {
  TempDir d;
  build_log(d.path(), 21, 8);  // 16 sealed, 17..20 pending

  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));

  // In the block being filled: there is no root to prove against yet, and
  // inventing an ephemeral one would prove nothing because it is published
  // nowhere.
  for (uint64_t i = 16; i < 21; ++i) {
    Log::ProveResult res;
    CHECK(log.prove(i, &res, &err));
    CHECK(res.outcome == Log::ProveOutcome::kNotSealed);
    CHECK(res.detail.find("15") != std::string::npos);
  }

  // Past the end entirely.
  Log::ProveResult res;
  CHECK(log.prove(21, &res, &err));
  CHECK(res.outcome == Log::ProveOutcome::kOutOfRange);
  CHECK(log.prove(1000000, &res, &err));
  CHECK(res.outcome == Log::ProveOutcome::kOutOfRange);

  // A log with nothing sealed at all gets a message that says where the first
  // checkpoint will land, rather than a bare failure.
  TempDir fresh;
  build_log(fresh.path(), 3, 8);
  Log small;
  CHECK(small.open(fresh.path(), opt, &err));
  CHECK(small.prove(1, &res, &err));
  CHECK(res.outcome == Log::ProveOutcome::kNotSealed);
  CHECK(res.detail.find("no block has been sealed") != std::string::npos);
}

TEST(prove_refuses_when_the_block_disagrees_with_its_checkpoint) {
  TempDir d;
  build_log(d.path(), 24, 8);

  // Re-link the log so the records are self-consistent but the sealed roots
  // are stale.
  std::string bytes = chainlog_test::read_file(log_file(d));
  const std::vector<FrameSpan> spans = chainlog_test::frame_spans(bytes);
  std::vector<Record> rs = chainlog_test::read_frames(bytes);
  Record forged = rs[9];
  forged.data = "rec-HACKED";
  chainlog_test::rewrite_frame(&bytes, spans[9].offset, forged);
  chainlog_test::relink_from(&bytes, 9);
  chainlog_test::write_file(log_file(d), bytes);

  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));

  // Handing out a proof here would push the discovery of the tampering onto
  // whoever checks the proof later, so prove() refuses and says why.
  Log::ProveResult res;
  CHECK(log.prove(9, &res, &err));
  CHECK(res.outcome == Log::ProveOutcome::kProblem);
  CHECK_EQ(pname(res.why.problem), "bad-checkpoint");
  CHECK(res.why.detail.find("but its checkpoint says") != std::string::npos);

  // Block 0 was not touched, so proofs from it still work.
  CHECK(log.prove(3, &res, &err));
  CHECK(res.outcome == Log::ProveOutcome::kOk);
}

TEST(a_proof_does_not_verify_against_another_blocks_root) {
  TempDir d;
  build_log(d.path(), 24, 8);

  Log log;
  Log::Options opt;
  std::string err;
  CHECK(log.open(d.path(), opt, &err));

  Log::ProveResult a;
  Log::ProveResult b;
  CHECK(log.prove(3, &a, &err));
  CHECK(log.prove(11, &b, &err));
  CHECK(a.outcome == Log::ProveOutcome::kOk);
  CHECK(b.outcome == Log::ProveOutcome::kOk);
  CHECK(to_hex(a.checkpoint.root) != to_hex(b.checkpoint.root));

  std::string detail;
  // Record 3's proof, checked against block 1's root.
  CHECK(!chainlog::merkle_verify_proof(chainlog::compute_record_hash(a.record),
                                       3, 8, a.proof, b.checkpoint.root,
                                       &detail));
}
