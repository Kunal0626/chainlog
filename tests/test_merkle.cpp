// Merkle tree, proof and wire-format tests.
//
// The important ones here are the two that check the design rather than the
// code:
//
//   iterative_build_matches_rfc6962_recursive_mth  -- the fast level-by-level
//       build is compared against RFC 6962's recursive definition, written
//       out below exactly as the RFC writes it, for every tree size up to 257.
//
//   duplicating_the_odd_node_collides -- builds the Bitcoin-style
//       "duplicate the last node" variant and exhibits the actual collision
//       (CVE-2012-2459), so the comment in merkle.cpp claiming duplication is
//       unsafe is backed by a demonstration rather than an assertion.

#include <string>
#include <vector>

#include "crc32.h"
#include "hex.h"
#include "merkle.h"
#include "record.h"
#include "sha256.h"
#include "test.h"

using chainlog::Digest;
using chainlog::MerkleTree;
using chainlog::Proof;
using chainlog::ProofStep;
using chainlog::Sha256;
using chainlog::merkle_leaf_hash;
using chainlog::merkle_node_hash;
using chainlog::merkle_prove;
using chainlog::merkle_root;
using chainlog::merkle_verify_proof;
using chainlog::to_hex;

namespace {

// Distinct, deterministic stand-ins for record hashes.
std::vector<Digest> fake_hashes(size_t n) {
  std::vector<Digest> out;
  out.reserve(n);
  for (size_t i = 0; i < n; ++i) {
    out.push_back(Sha256::hash("leaf-" + std::to_string(i)));
  }
  return out;
}

// RFC 6962: the largest power of two strictly less than n, for n > 1.
size_t split_point(size_t n) {
  size_t k = 1;
  while (k * 2 < n) {
    k *= 2;
  }
  return k;
}

// RFC 6962 section 2.1, MTH, written recursively the way the RFC writes it.
// This is the oracle: it is deliberately the slow, obvious, allocating
// implementation, so that agreeing with it says something.
Digest mth(const std::vector<Digest>& d) {
  if (d.empty()) {
    return Sha256::hash("", 0);
  }
  if (d.size() == 1) {
    return merkle_leaf_hash(d[0]);
  }
  const size_t k = split_point(d.size());
  const std::vector<Digest> left(d.begin(), d.begin() + k);
  const std::vector<Digest> right(d.begin() + k, d.end());
  return merkle_node_hash(mth(left), mth(right));
}

// RFC 6962 PATH(m, D[n]), also recursive, also bottom-up.
void rfc_path(const std::vector<Digest>& d, size_t m, Proof* out) {
  if (d.size() <= 1) {
    return;
  }
  const size_t k = split_point(d.size());
  const std::vector<Digest> left(d.begin(), d.begin() + k);
  const std::vector<Digest> right(d.begin() + k, d.end());
  ProofStep step;
  if (m < k) {
    rfc_path(left, m, out);
    step.sibling_on_left = false;  // the right subtree is the sibling
    step.hash = mth(right);
  } else {
    rfc_path(right, m - k, out);
    step.sibling_on_left = true;  // the left subtree is the sibling
    step.hash = mth(left);
  }
  out->push_back(step);
}

// The unsafe variant: hash a lone odd node with a copy of itself instead of
// promoting it. Present ONLY in this test file, to demonstrate the collision.
Digest duplicating_root(const std::vector<Digest>& record_hashes) {
  if (record_hashes.empty()) {
    return Sha256::hash("", 0);
  }
  std::vector<Digest> level;
  for (size_t i = 0; i < record_hashes.size(); ++i) {
    level.push_back(merkle_leaf_hash(record_hashes[i]));
  }
  while (level.size() > 1) {
    std::vector<Digest> next;
    for (size_t i = 0; i < level.size(); i += 2) {
      const Digest& l = level[i];
      const Digest& r = (i + 1 < level.size()) ? level[i + 1] : level[i];
      next.push_back(merkle_node_hash(l, r));
    }
    level = next;
  }
  return level[0];
}

std::string proof_hex(const Proof& p) {
  std::string s;
  for (size_t i = 0; i < p.size(); ++i) {
    s += p[i].sibling_on_left ? "L" : "R";
    s += to_hex(p[i].hash);
    s += " ";
  }
  return s;
}

size_t ceil_log2(size_t n) {
  size_t bits = 0;
  while ((static_cast<size_t>(1) << bits) < n) {
    ++bits;
  }
  return bits;
}

}  // namespace

// --- hashing ---------------------------------------------------------------

TEST(leaf_hash_is_sha256_of_a_zero_prefix) {
  const Digest d = Sha256::hash("a record hash");
  std::string pre;
  pre.push_back('\x00');
  pre.append(reinterpret_cast<const char*>(d.data()), d.size());
  CHECK_EQ(to_hex(merkle_leaf_hash(d)), to_hex(Sha256::hash(pre)));
}

TEST(node_hash_is_sha256_of_a_one_prefix) {
  const Digest l = Sha256::hash("left");
  const Digest r = Sha256::hash("right");
  std::string pre;
  pre.push_back('\x01');
  pre.append(reinterpret_cast<const char*>(l.data()), l.size());
  pre.append(reinterpret_cast<const char*>(r.data()), r.size());
  CHECK_EQ(to_hex(merkle_node_hash(l, r)), to_hex(Sha256::hash(pre)));
}

// Why the 0x00/0x01 prefixes exist. An inner node hashes 64 bytes: two
// concatenated digests. Without domain separation that is byte-identical to
// hashing a 64-byte *leaf payload*, so an attacker could hand over an
// interior node and have it accepted as a leaf.
TEST(domain_separation_keeps_leaves_and_inner_nodes_apart) {
  const Digest l = Sha256::hash("left");
  const Digest r = Sha256::hash("right");

  // Unprefixed forms, as a format without domain separation would compute.
  std::string concat;
  concat.append(reinterpret_cast<const char*>(l.data()), l.size());
  concat.append(reinterpret_cast<const char*>(r.data()), r.size());

  const Digest naive_node = Sha256::hash(concat);   // inner node, no prefix
  const Digest naive_leaf = Sha256::hash(concat);   // leaf payload, no prefix
  CHECK_EQ(to_hex(naive_node), to_hex(naive_leaf)); // indistinguishable

  // With the prefixes they cannot collide: the inputs differ in their first
  // byte, and one is 65 bytes while the other is 33.
  CHECK(to_hex(merkle_node_hash(l, r)) != to_hex(merkle_leaf_hash(l)));
}

// --- tree shape ------------------------------------------------------------

TEST(empty_tree_root_is_sha256_of_the_empty_string) {
  CHECK_EQ(to_hex(merkle_root({})),
           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(single_leaf_root_is_its_leaf_hash) {
  const std::vector<Digest> h = fake_hashes(1);
  CHECK_EQ(to_hex(merkle_root(h)), to_hex(merkle_leaf_hash(h[0])));
}

TEST(two_leaf_root_is_one_node) {
  const std::vector<Digest> h = fake_hashes(2);
  CHECK_EQ(to_hex(merkle_root(h)),
           to_hex(merkle_node_hash(merkle_leaf_hash(h[0]),
                                   merkle_leaf_hash(h[1]))));
}

TEST(three_leaves_promote_the_odd_node) {
  const std::vector<Digest> h = fake_hashes(3);
  const Digest l0 = merkle_leaf_hash(h[0]);
  const Digest l1 = merkle_leaf_hash(h[1]);
  const Digest l2 = merkle_leaf_hash(h[2]);

  // Promotion: H(H(l0,l1), l2). The lone node goes up untouched.
  CHECK_EQ(to_hex(merkle_root(h)),
           to_hex(merkle_node_hash(merkle_node_hash(l0, l1), l2)));
  // Not duplication: H(H(l0,l1), H(l2,l2)).
  CHECK(to_hex(merkle_root(h)) !=
        to_hex(merkle_node_hash(merkle_node_hash(l0, l1),
                                merkle_node_hash(l2, l2))));
}

// CVE-2012-2459, demonstrated rather than asserted.
//
// With the "duplicate the odd node" rule, a tree of n leaves can be
// byte-identically rooted as a tree of a different leaf list. The root then no
// longer uniquely commits to what is in the log, so two different histories
// share a root and an inclusion proof stops being unambiguous.
TEST(duplicating_the_odd_node_collides) {
  const std::vector<Digest> three = fake_hashes(3);
  std::vector<Digest> four = three;
  four.push_back(three[2]);  // ... A, B, C, C

  // The unsafe rule: three leaves and four leaves give the SAME root.
  CHECK_EQ(to_hex(duplicating_root(three)), to_hex(duplicating_root(four)));

  // RFC 6962 promotion: they differ, as they must.
  CHECK(to_hex(merkle_root(three)) != to_hex(merkle_root(four)));

  // The same collision at a larger odd size, to show it is not a quirk of 3.
  const std::vector<Digest> five = fake_hashes(5);
  std::vector<Digest> six = five;
  six.push_back(five[4]);
  CHECK_EQ(to_hex(duplicating_root(five)), to_hex(duplicating_root(six)));
  CHECK(to_hex(merkle_root(five)) != to_hex(merkle_root(six)));
}

// The claim made in merkle.cpp: the level-by-level build with promotion
// produces exactly RFC 6962's recursive MTH. Checked for every size up to
// 257, which covers both powers of two and the awkward sizes either side.
TEST(iterative_build_matches_rfc6962_recursive_mth) {
  for (size_t n = 0; n <= 257; ++n) {
    const std::vector<Digest> h = fake_hashes(n);
    CHECK_EQ(to_hex(merkle_root(h)), to_hex(mth(h)));
  }
}

TEST(iterative_prove_matches_rfc6962_recursive_path) {
  for (size_t n = 1; n <= 65; ++n) {
    const std::vector<Digest> h = fake_hashes(n);
    const MerkleTree tree = MerkleTree::build(h);
    for (size_t m = 0; m < n; ++m) {
      Proof mine;
      CHECK(merkle_prove(tree, m, &mine));
      Proof theirs;
      rfc_path(h, m, &theirs);
      CHECK_EQ(proof_hex(mine), proof_hex(theirs));
    }
  }
}

// --- proofs ----------------------------------------------------------------

TEST(every_leaf_of_every_tree_up_to_130_verifies) {
  for (uint64_t n = 1; n <= 130; ++n) {
    const std::vector<Digest> h = fake_hashes(static_cast<size_t>(n));
    const MerkleTree tree = MerkleTree::build(h);
    const Digest root = tree.root();
    CHECK_EQ(tree.leaf_count(), n);

    for (uint64_t m = 0; m < n; ++m) {
      Proof p;
      CHECK(merkle_prove(tree, m, &p));
      std::string detail;
      if (!merkle_verify_proof(h[static_cast<size_t>(m)], m, n, p, root,
                               &detail)) {
        CHECK_EQ(detail, "(should have verified)");
      }
      // A proof is one sibling per level at most, and none where a node was
      // promoted, so it can never exceed ceil(log2(n)).
      CHECK(p.size() <= ceil_log2(static_cast<size_t>(n)));
    }
  }
}

TEST(proving_outside_the_tree_fails) {
  const std::vector<Digest> h = fake_hashes(10);
  const MerkleTree tree = MerkleTree::build(h);
  Proof p;
  CHECK(!merkle_prove(tree, 10, &p));
  CHECK(!merkle_prove(tree, 1000, &p));
}

TEST(a_flipped_bit_anywhere_breaks_the_proof) {
  const std::vector<Digest> h = fake_hashes(37);
  const MerkleTree tree = MerkleTree::build(h);
  const Digest root = tree.root();
  const uint64_t m = 19;

  Proof good;
  CHECK(merkle_prove(tree, m, &good));
  std::string detail;
  CHECK(merkle_verify_proof(h[m], m, 37, good, root, &detail));

  // The leaf.
  Digest bad_leaf = h[m];
  bad_leaf[0] ^= 0x01;
  CHECK(!merkle_verify_proof(bad_leaf, m, 37, good, root, &detail));

  // The root.
  Digest bad_root = root;
  bad_root[31] ^= 0x80;
  CHECK(!merkle_verify_proof(h[m], m, 37, good, bad_root, &detail));

  // Each sibling in turn.
  for (size_t i = 0; i < good.size(); ++i) {
    Proof bad = good;
    bad[i].hash[5] ^= 0x01;
    CHECK(!merkle_verify_proof(h[m], m, 37, bad, root, &detail));
  }
}

// A proof pins the POSITION exactly. The left/right flags along the path are
// the bits of the leaf index, least significant first, so within a given tree
// size no two positions share a path shape -- and a shape that disagrees with
// the claimed index is rejected before the hashing matters.
TEST(a_proof_is_bound_to_its_position) {
  const std::vector<Digest> h = fake_hashes(37);
  const MerkleTree tree = MerkleTree::build(h);
  const Digest root = tree.root();
  std::string detail;

  // Every leaf's proof must fail for every OTHER claimed position.
  for (uint64_t m = 0; m < 37; ++m) {
    Proof p;
    CHECK(merkle_prove(tree, m, &p));
    CHECK(merkle_verify_proof(h[m], m, 37, p, root, &detail));
    for (uint64_t lie = 0; lie < 37; ++lie) {
      if (lie == m) {
        continue;
      }
      CHECK(!merkle_verify_proof(h[m], lie, 37, p, root, &detail));
    }
  }

  // Out of range.
  Proof p;
  CHECK(merkle_prove(tree, 19, &p));
  CHECK(!merkle_verify_proof(h[19], 37, 37, p, root, &detail));
  CHECK(!merkle_verify_proof(h[0], 0, 0, p, root, &detail));
}

// What a proof does NOT pin: the exact tree size.
//
// The path shape depends on the tree size only where the size changes the
// PROMOTION pattern along that particular path. Leaf 19 of a 37-leaf tree hits
// no promotion, so its shape (LLRRLR) is identical for 36, 38, 40, 48 and 64
// leaves -- the same siblings fold to the same root, and the verifier cannot
// tell those sizes apart. Across a 37-leaf tree, 36 of the 37 leaves have a
// shape shared with some other size.
//
// This does not weaken the security property that matters. Producing a proof
// for a leaf that is not in the tree still requires inverting SHA-256,
// because the root must come out right. What it means is that the tree size
// carried in a proof blob is self-reported convenience, not a committed fact:
// in ChainLog the size that matters comes from the trusted CHECKPOINT
// (last_index - first_index + 1), alongside the root the verifier already
// trusts. See docs/FORMAT.md.
//
// Pinned as a passing test so the limitation cannot quietly stop being true.
TEST(a_proof_does_NOT_pin_the_exact_tree_size) {
  const std::vector<Digest> h = fake_hashes(37);
  const MerkleTree tree = MerkleTree::build(h);
  const Digest root = tree.root();
  const uint64_t m = 19;
  Proof p;
  CHECK(merkle_prove(tree, m, &p));
  std::string detail;

  // The honest truth: these all verify, because the path shape is the same.
  CHECK(merkle_verify_proof(h[m], m, 37, p, root, &detail));
  CHECK(merkle_verify_proof(h[m], m, 36, p, root, &detail));
  CHECK(merkle_verify_proof(h[m], m, 64, p, root, &detail));

  // A size that DOES change the promotion pattern is caught, which is why
  // the parameter is not useless. Leaf 4 of a 5-leaf tree is promoted twice
  // and needs a single left sibling; in an 8-leaf tree the same position
  // needs three siblings starting with a right one, so the very first flag
  // disagrees and the proof is rejected there -- before the step count is
  // ever reached.
  const std::vector<Digest> five = fake_hashes(5);
  const MerkleTree small = MerkleTree::build(five);
  Proof q;
  CHECK(merkle_prove(small, 4, &q));
  CHECK_EQ(q.size(), static_cast<size_t>(1));
  CHECK(q[0].sibling_on_left);
  CHECK(merkle_verify_proof(five[4], 4, 5, q, small.root(), &detail));
  CHECK(!merkle_verify_proof(five[4], 4, 8, q, small.root(), &detail));
  CHECK(detail.find("requires it on the right") != std::string::npos);

  // And a size change that alters only the step count is caught by the count.
  // Leaf 0 of a 2-leaf tree needs one sibling; of a 4-leaf tree, two. Both
  // are right siblings, so the flags agree and only the length catches it.
  const std::vector<Digest> two = fake_hashes(2);
  const MerkleTree pair = MerkleTree::build(two);
  Proof r;
  CHECK(merkle_prove(pair, 0, &r));
  CHECK_EQ(r.size(), static_cast<size_t>(1));
  CHECK(!merkle_verify_proof(two[0], 0, 4, r, pair.root(), &detail));
  CHECK(detail.find("too short") != std::string::npos);
}

TEST(a_proof_of_the_wrong_length_fails) {
  const std::vector<Digest> h = fake_hashes(37);
  const MerkleTree tree = MerkleTree::build(h);
  const Digest root = tree.root();
  const uint64_t m = 19;
  Proof p;
  CHECK(merkle_prove(tree, m, &p));
  std::string detail;

  Proof too_long = p;
  too_long.push_back(p[0]);
  CHECK(!merkle_verify_proof(h[m], m, 37, too_long, root, &detail));
  CHECK(detail.find("unused") != std::string::npos);

  Proof too_short = p;
  too_short.pop_back();
  CHECK(!merkle_verify_proof(h[m], m, 37, too_short, root, &detail));
  CHECK(detail.find("too short") != std::string::npos);
}

// The left/right flags are checked against the shape derived from
// (index, tree_size) rather than trusted. A proof whose flags disagree with
// the position it claims is rejected before any hashing matters.
TEST(a_flipped_side_flag_fails) {
  const std::vector<Digest> h = fake_hashes(37);
  const MerkleTree tree = MerkleTree::build(h);
  const Digest root = tree.root();
  const uint64_t m = 19;
  Proof p;
  CHECK(merkle_prove(tree, m, &p));
  std::string detail;

  for (size_t i = 0; i < p.size(); ++i) {
    Proof bad = p;
    bad[i].sibling_on_left = !bad[i].sibling_on_left;
    CHECK(!merkle_verify_proof(h[m], m, 37, bad, root, &detail));
    CHECK(detail.find("requires it on the") != std::string::npos);
  }
}

// --- the wire format -------------------------------------------------------

TEST(proof_encoding_round_trips) {
  for (uint64_t n : {uint64_t(1), uint64_t(2), uint64_t(7), uint64_t(64),
                     uint64_t(1024)}) {
    const std::vector<Digest> h = fake_hashes(static_cast<size_t>(n));
    const MerkleTree tree = MerkleTree::build(h);
    for (uint64_t m = 0; m < n; m += (n / 7) + 1) {
      Proof p;
      CHECK(merkle_prove(tree, m, &p));
      const std::string hex = chainlog::encode_proof(1000, n, m, p);
      CHECK_EQ(hex.size(),
               2 * (chainlog::kProofHeaderBytes +
                    p.size() * chainlog::kProofStepBytes +
                    chainlog::kProofTrailerBytes));

      uint64_t first = 0;
      uint64_t size = 0;
      uint64_t leaf = 0;
      Proof back;
      std::string detail;
      CHECK(chainlog::decode_proof(hex, &first, &size, &leaf, &back, &detail));
      CHECK_EQ(first, 1000ull);
      CHECK_EQ(size, n);
      CHECK_EQ(leaf, m);
      CHECK_EQ(proof_hex(back), proof_hex(p));
    }
  }
}

TEST(proof_decoding_rejects_corruption) {
  const std::vector<Digest> h = fake_hashes(16);
  const MerkleTree tree = MerkleTree::build(h);
  Proof p;
  CHECK(merkle_prove(tree, 5, &p));
  const std::string good = chainlog::encode_proof(0, 16, 5, p);

  uint64_t first = 0;
  uint64_t size = 0;
  uint64_t leaf = 0;
  Proof back;
  std::string detail;
  CHECK(chainlog::decode_proof(good, &first, &size, &leaf, &back, &detail));

  // Odd length.
  CHECK(!chainlog::decode_proof(good.substr(1), &first, &size, &leaf, &back,
                                &detail));
  // Not hex.
  std::string not_hex = good;
  not_hex[4] = 'z';
  CHECK(!chainlog::decode_proof(not_hex, &first, &size, &leaf, &back, &detail));
  // Too short to be a proof at all.
  CHECK(!chainlog::decode_proof("0100", &first, &size, &leaf, &back, &detail));
  // Truncated: caught by the CRC, so it reads as corrupt rather than invalid.
  CHECK(!chainlog::decode_proof(good.substr(0, good.size() - 8), &first, &size,
                                &leaf, &back, &detail));

  // Every single-hex-digit change must be caught. This is what makes a
  // mangled copy-paste report "corrupt proof" instead of "proof failed",
  // which are different answers for an operator.
  for (size_t i = 0; i < good.size(); i += 7) {
    std::string flipped = good;
    flipped[i] = (flipped[i] == '0') ? '1' : '0';
    if (flipped == good) {
      continue;
    }
    CHECK(!chainlog::decode_proof(flipped, &first, &size, &leaf, &back,
                                  &detail));
  }
}

TEST(proof_decoding_rejects_an_unknown_version) {
  const std::vector<Digest> h = fake_hashes(8);
  const MerkleTree tree = MerkleTree::build(h);
  Proof p;
  CHECK(merkle_prove(tree, 3, &p));
  std::string raw;
  CHECK(chainlog::from_hex(chainlog::encode_proof(0, 8, 3, p), &raw, nullptr));

  // Bump the version and repair the CRC, so the only thing wrong is that this
  // build does not know the format.
  uint8_t* bytes = reinterpret_cast<uint8_t*>(&raw[0]);
  bytes[0] = chainlog::kProofVersion + 1;
  const size_t body = raw.size() - chainlog::kProofTrailerBytes;
  chainlog::put_u32_le(bytes + body, chainlog::crc32(bytes, body));

  uint64_t first = 0;
  uint64_t size = 0;
  uint64_t leaf = 0;
  Proof back;
  std::string detail;
  CHECK(!chainlog::decode_proof(chainlog::to_hex(raw.data(), raw.size()),
                                &first, &size, &leaf, &back, &detail));
  CHECK(detail.find("version") != std::string::npos);
}
