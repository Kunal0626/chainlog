#include "merkle.h"

#include <cstring>

#include "crc32.h"
#include "hex.h"
#include "record.h"

namespace chainlog {

Digest merkle_leaf_hash(const Digest& record_hash) {
  Sha256 h;
  const uint8_t prefix = kMerkleLeafPrefix;
  h.update(&prefix, 1);
  h.update(record_hash.data(), record_hash.size());
  return h.finish();
}

Digest merkle_node_hash(const Digest& left, const Digest& right) {
  Sha256 h;
  const uint8_t prefix = kMerkleNodePrefix;
  h.update(&prefix, 1);
  h.update(left.data(), left.size());
  h.update(right.data(), right.size());
  return h.finish();
}

MerkleTree MerkleTree::build(const std::vector<Digest>& record_hashes) {
  MerkleTree t;
  t.leaf_count_ = record_hashes.size();

  if (record_hashes.empty()) {
    // RFC 6962: MTH({}) = SHA-256 of the empty string. Defining the empty
    // tree at all matters because "no records" must still have a root that a
    // verifier can compare against, rather than an undefined value.
    t.nodes_.push_back(Sha256::hash("", 0));
    t.level_off_.push_back(0);
    t.level_len_.push_back(1);
    return t;
  }

  // Total nodes over all levels is n + ceil(n/2) + ... < 2n. Reserving up
  // front keeps every node address stable during the build.
  t.nodes_.reserve(2 * record_hashes.size() + 2);

  t.level_off_.push_back(0);
  t.level_len_.push_back(record_hashes.size());
  for (size_t i = 0; i < record_hashes.size(); ++i) {
    t.nodes_.push_back(merkle_leaf_hash(record_hashes[i]));
  }

  size_t off = 0;
  size_t len = record_hashes.size();
  while (len > 1) {
    const size_t next_off = off + len;
    size_t next_len = 0;
    for (size_t i = 0; i < len; i += 2) {
      if (i + 1 < len) {
        t.nodes_.push_back(
            merkle_node_hash(t.nodes_[off + i], t.nodes_[off + i + 1]));
      } else {
        // Odd node out: PROMOTE it unchanged, as RFC 6962 does.
        //
        // The tempting alternative -- hash it with a copy of itself, which is
        // what Bitcoin does -- is CVE-2012-2459. With duplication, three
        // leaves A,B,C give root = H(H(A,B), H(C,C)), which is byte-identical
        // to the root of the FOUR-leaf tree A,B,C,C. So the root stops
        // uniquely committing to the leaf list: two different logs share a
        // root, and an inclusion proof becomes ambiguous.
        //
        // Promotion avoids it because the tree's shape then depends only on
        // n, and n is committed in the checkpoint alongside the root.
        // tests/test_merkle.cpp builds the duplicating variant and exhibits
        // the collision, so this comment is backed by a failing alternative
        // rather than an assertion.
        const Digest promoted = t.nodes_[off + i];
        t.nodes_.push_back(promoted);
      }
      ++next_len;
    }
    t.level_off_.push_back(next_off);
    t.level_len_.push_back(next_len);
    off = next_off;
    len = next_len;
  }

  return t;
}

Digest merkle_root(const std::vector<Digest>& record_hashes) {
  return MerkleTree::build(record_hashes).root();
}

bool merkle_prove(const MerkleTree& tree, uint64_t leaf_index, Proof* out) {
  if (leaf_index >= tree.leaf_count()) {
    return false;
  }
  out->clear();

  size_t i = static_cast<size_t>(leaf_index);
  for (size_t level = 0; level + 1 < tree.levels(); ++level) {
    const size_t len = tree.level_size(level);
    if (i % 2 == 1) {
      // Right child: the sibling is immediately to the left.
      ProofStep step;
      step.sibling_on_left = true;
      step.hash = tree.node(level, i - 1);
      out->push_back(step);
    } else if (i + 1 < len) {
      // Left child with a partner: the sibling is immediately to the right.
      ProofStep step;
      step.sibling_on_left = false;
      step.hash = tree.node(level, i + 1);
      out->push_back(step);
    }
    // Otherwise this node was promoted: it has no sibling at this level, so
    // the proof records nothing and the path simply moves up. This is why a
    // proof can be shorter than the tree is deep.
    i /= 2;
  }
  return true;
}

bool merkle_verify_proof(const Digest& record_hash, uint64_t leaf_index,
                         uint64_t tree_size, const Proof& proof,
                         const Digest& expected_root, std::string* detail) {
  if (tree_size == 0) {
    if (detail != nullptr) {
      *detail = "tree size is 0, so it contains no leaves to prove";
    }
    return false;
  }
  if (leaf_index >= tree_size) {
    if (detail != nullptr) {
      *detail = "leaf index " + std::to_string(leaf_index) +
                " is outside a tree of " + std::to_string(tree_size) +
                " leaves";
    }
    return false;
  }

  Digest acc = merkle_leaf_hash(record_hash);
  uint64_t i = leaf_index;
  uint64_t len = tree_size;
  size_t step = 0;

  while (len > 1) {
    const bool expect_left_sibling = (i % 2 == 1);
    const bool has_sibling = expect_left_sibling || (i + 1 < len);

    if (has_sibling) {
      if (step >= proof.size()) {
        if (detail != nullptr) {
          *detail = "proof is too short: a tree of " +
                    std::to_string(tree_size) + " leaves needs a sibling at " +
                    "this level but the proof has only " +
                    std::to_string(proof.size()) + " step(s)";
        }
        return false;
      }
      if (proof[step].sibling_on_left != expect_left_sibling) {
        // The path shape is a function of (leaf_index, tree_size), so a flag
        // that disagrees with it means the proof does not describe the
        // position it claims.
        if (detail != nullptr) {
          *detail = "step " + std::to_string(step) + " says the sibling is on " +
                    "the " + (proof[step].sibling_on_left ? "left" : "right") +
                    ", but position " + std::to_string(leaf_index) +
                    " in a tree of " + std::to_string(tree_size) +
                    " requires it on the " +
                    (expect_left_sibling ? "left" : "right");
        }
        return false;
      }
      acc = expect_left_sibling ? merkle_node_hash(proof[step].hash, acc)
                                : merkle_node_hash(acc, proof[step].hash);
      ++step;
    }

    i /= 2;
    len = (len + 1) / 2;  // ceil: a promoted node still occupies a slot above
  }

  if (step != proof.size()) {
    if (detail != nullptr) {
      *detail = "proof has " + std::to_string(proof.size() - step) +
                " unused step(s); the path for position " +
                std::to_string(leaf_index) + " in a tree of " +
                std::to_string(tree_size) + " leaves needs exactly " +
                std::to_string(step);
    }
    return false;
  }

  if (acc != expected_root) {
    if (detail != nullptr) {
      *detail = "recomputed root " + to_hex(acc) + " does not match " +
                to_hex(expected_root);
    }
    return false;
  }
  return true;
}

// --- wire format -----------------------------------------------------------

std::string encode_proof(uint64_t first_index, uint64_t tree_size,
                         uint64_t leaf_index, const Proof& proof) {
  std::string raw;
  raw.reserve(kProofHeaderBytes + proof.size() * kProofStepBytes +
              kProofTrailerBytes);

  uint8_t head[kProofHeaderBytes];
  head[0] = kProofVersion;
  put_u64_le(head + 1, first_index);
  put_u64_le(head + 9, tree_size);
  put_u64_le(head + 17, leaf_index);
  head[25] = static_cast<uint8_t>(proof.size());
  raw.append(reinterpret_cast<const char*>(head), sizeof(head));

  for (size_t i = 0; i < proof.size(); ++i) {
    raw.push_back(proof[i].sibling_on_left ? '\x00' : '\x01');
    raw.append(reinterpret_cast<const char*>(proof[i].hash.data()),
               proof[i].hash.size());
  }

  uint8_t crc[4];
  put_u32_le(crc, crc32(raw.data(), raw.size()));
  raw.append(reinterpret_cast<const char*>(crc), sizeof(crc));

  return to_hex(raw.data(), raw.size());
}

bool decode_proof(const std::string& hex, uint64_t* first_index,
                  uint64_t* tree_size, uint64_t* leaf_index, Proof* proof,
                  std::string* detail) {
  std::string raw;
  if (!from_hex(hex, &raw, detail)) {
    return false;
  }
  if (raw.size() < kProofHeaderBytes + kProofTrailerBytes) {
    if (detail != nullptr) {
      *detail = "proof is " + std::to_string(raw.size()) +
                " bytes, below the " +
                std::to_string(kProofHeaderBytes + kProofTrailerBytes) +
                "-byte minimum";
    }
    return false;
  }

  const uint8_t* p = reinterpret_cast<const uint8_t*>(raw.data());
  const size_t body = raw.size() - kProofTrailerBytes;

  // CRC before anything else is interpreted, exactly as the record framing
  // does it: a mangled paste should read as "corrupt", not as "invalid".
  const uint32_t stored_crc = get_u32_le(p + body);
  const uint32_t actual_crc = crc32(p, body);
  if (stored_crc != actual_crc) {
    if (detail != nullptr) {
      *detail = "proof crc32 mismatch; the hex was probably truncated or "
                "mistyped";
    }
    return false;
  }

  if (p[0] != kProofVersion) {
    if (detail != nullptr) {
      *detail = "proof version " + std::to_string(p[0]) +
                ", this build understands " + std::to_string(kProofVersion);
    }
    return false;
  }

  *first_index = get_u64_le(p + 1);
  *tree_size = get_u64_le(p + 9);
  *leaf_index = get_u64_le(p + 17);
  const size_t step_count = p[25];

  const size_t want = kProofHeaderBytes + step_count * kProofStepBytes;
  if (want != body) {
    if (detail != nullptr) {
      *detail = "proof declares " + std::to_string(step_count) +
                " step(s), which needs " + std::to_string(want) +
                " bytes, but the body is " + std::to_string(body);
    }
    return false;
  }

  proof->clear();
  proof->reserve(step_count);
  for (size_t i = 0; i < step_count; ++i) {
    const uint8_t* s = p + kProofHeaderBytes + i * kProofStepBytes;
    if (s[0] != 0 && s[0] != 1) {
      if (detail != nullptr) {
        *detail = "step " + std::to_string(i) + " has flag " +
                  std::to_string(s[0]) + ", expected 0 or 1";
      }
      return false;
    }
    ProofStep step;
    step.sibling_on_left = (s[0] == 0);
    std::memcpy(step.hash.data(), s + 1, 32);
    proof->push_back(step);
  }
  return true;
}

}  // namespace chainlog
