// Merkle tree, inclusion proofs, and the proof wire format.
//
// Hashing follows RFC 6962 (Certificate Transparency):
//
//     leaf hash  = SHA256(0x00 || record_hash)
//     inner node = SHA256(0x01 || left || right)
//
// Two decisions in there are load-bearing and both are explained at the
// definitions below: the 0x00/0x01 domain separation, and promoting a lone
// odd node instead of duplicating it.
#ifndef CHAINLOG_MERKLE_H
#define CHAINLOG_MERKLE_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "sha256.h"

namespace chainlog {

// Domain separation prefixes. Without them, an inner node hash -- SHA-256 over
// 64 bytes, being two concatenated digests -- is computable as a LEAF hash of
// a 64-byte payload. An attacker could then present an interior node as if it
// were a leaf and "prove" membership of something that was never appended.
// The prefixes put leaves and inner nodes in disjoint input spaces, which is
// RFC 6962 section 2.1.
constexpr uint8_t kMerkleLeafPrefix = 0x00;
constexpr uint8_t kMerkleNodePrefix = 0x01;

Digest merkle_leaf_hash(const Digest& record_hash);
Digest merkle_node_hash(const Digest& left, const Digest& right);

// A Merkle tree over a list of record hashes, with every level kept so that
// proofs are a walk rather than a recomputation.
//
// Stored as one flat vector with per-level offsets rather than a
// vector-of-vectors: the node count is at most 2n, so for a 1M-leaf tree this
// is one 64 MB allocation instead of 20 smaller ones.
class MerkleTree {
 public:
  // Builds the tree bottom-up, level by level.
  //
  // The level-by-level build with promotion produces exactly RFC 6962's
  // recursive MTH, which splits at the largest power of two below n. The
  // reason: a partial node at level j covers r leaves, and either r <= 2^(j-1)
  // -- in which case it is promoted and is just its child -- or
  // 2^(j-1) < r <= 2^j, in which case it splits at 2^(j-1), which is exactly
  // the largest power of two below r. tests/test_merkle.cpp checks the two
  // against each other for every size up to 257 rather than taking that on
  // trust.
  static MerkleTree build(const std::vector<Digest>& record_hashes);

  size_t levels() const { return level_off_.size(); }
  size_t level_size(size_t level) const { return level_len_[level]; }
  const Digest& node(size_t level, size_t i) const {
    return nodes_[level_off_[level] + i];
  }
  const Digest& root() const { return nodes_[nodes_.size() - 1]; }
  uint64_t leaf_count() const { return leaf_count_; }

 private:
  std::vector<Digest> nodes_;
  std::vector<size_t> level_off_;
  std::vector<size_t> level_len_;
  uint64_t leaf_count_ = 0;
};

// Convenience: the root over `record_hashes`. An empty list gives
// SHA256(""), as RFC 6962 specifies for the empty tree.
Digest merkle_root(const std::vector<Digest>& record_hashes);

// One sibling on the path from a leaf to the root.
struct ProofStep {
  // true: the sibling is the LEFT child, so the accumulator is the right one.
  bool sibling_on_left = false;
  Digest hash{};
};

using Proof = std::vector<ProofStep>;

// Inclusion proof for `leaf_index`, bottom-up. Returns false if the index is
// outside the tree. Size is at most ceil(log2(n)) steps: one sibling per
// level, and none at a level where the node was promoted.
bool merkle_prove(const MerkleTree& tree, uint64_t leaf_index, Proof* out);

// Recomputes the root from a record hash and its proof, and compares it with
// `expected_root`.
//
// Takes leaf_index and tree_size rather than trusting the proof's own
// left/right flags: the path shape is DERIVED from the position and the tree
// size, and the flags in the proof are then checked against it. A verifier
// that merely folded along whatever flags it was handed would still be
// unforgeable -- you cannot invent sibling hashes -- but it would not pin the
// leaf to a position, and "this record is in the log" is a weaker claim than
// "this record is entry 637".
//
// The position IS pinned: the flags along the path are the bits of the leaf
// index, least significant first, so within a given tree size no two
// positions share a shape.
//
// The tree SIZE is only partly pinned, and it is worth being exact about
// this. The size changes the shape only where it changes the promotion
// pattern on that particular path, so many sizes are indistinguishable --
// leaf 19 has shape LLRRLR in trees of 36, 37, 38, 40, 48 and 64 leaves
// alike. Forging membership is still infeasible (the root has to come out
// right), but a proof's self-reported tree_size is not a committed fact. In
// ChainLog the size that counts comes from the trusted checkpoint, next to
// the root the verifier already trusts. See
// a_proof_does_NOT_pin_the_exact_tree_size in tests/test_merkle.cpp.
bool merkle_verify_proof(const Digest& record_hash, uint64_t leaf_index,
                         uint64_t tree_size, const Proof& proof,
                         const Digest& expected_root, std::string* detail);

// --- the proof wire format -------------------------------------------------
//
// A proof is pasted between machines as one hex string, so it is
// self-describing: it carries the block it belongs to and the position it
// claims, and a CRC-32 so that a mangled copy-paste reads as "corrupt proof"
// rather than "proof does not verify". Those are different answers and an
// operator needs to be able to tell them apart.
//
//   0       version (1)
//   1..8    first_index  u64 LE  -- first record index of the sealed block
//   9..16   tree_size    u64 LE  -- leaves in that block's tree
//   17..24  leaf_index   u64 LE  -- position within the block, 0-based
//   25      step_count   u8      -- at most 64
//   26..    step_count x (flag u8 || hash 32); flag 0 = sibling on the left
//   last 4  crc32 u32 LE over every preceding byte
constexpr uint8_t kProofVersion = 1;
constexpr size_t kProofHeaderBytes = 26;
constexpr size_t kProofStepBytes = 33;
constexpr size_t kProofTrailerBytes = 4;

std::string encode_proof(uint64_t first_index, uint64_t tree_size,
                         uint64_t leaf_index, const Proof& proof);

bool decode_proof(const std::string& hex, uint64_t* first_index,
                  uint64_t* tree_size, uint64_t* leaf_index, Proof* proof,
                  std::string* detail);

}  // namespace chainlog

#endif  // CHAINLOG_MERKLE_H
