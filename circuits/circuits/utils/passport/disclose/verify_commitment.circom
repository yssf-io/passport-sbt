pragma circom 2.1.9;

include "@openpassport/zk-email-circuits/utils/bytes.circom";
include "@zk-kit/binary-merkle-root.circom/src/binary-merkle-root.circom";
include "../customHashers.circom";

/// @notice VerifyCommitment template — verifies user's commitment is included in the merkle tree
/// @param nLevels Maximum size of the merkle tree
/// @input secret Secret for commitment generation
/// @input attestation_id Attestation ID
/// @input dg1 Data group 1 of the passport
/// @input eContent_shaBytes_packed_hash hash of the eContent
/// @input dsc_tree_leaf Leaf of the DSC tree, to keep a record of the full CSCA and DSC that were used
/// @input merkle_root Root of the commitment merkle tree
/// @input merkletree_size Actual size of the merkle tree
/// @input path Path to the user's commitment in the merkle tree
/// @input siblings Siblings of the user's commitment in the merkle tree
template VERIFY_COMMITMENT(nLevels) {
    signal input secret;
    signal input attestation_id;
    signal input dg1[93];
    signal input eContent_shaBytes_packed_hash;
    signal input dsc_tree_leaf;

    signal input merkle_root;
    signal input merkletree_size;
    signal input path[nLevels];
    signal input siblings[nLevels];

    signal dg1_packed_hash <== PackBytesAndPoseidon(93)(dg1);

    signal commitment <== Poseidon(5)([
        secret,
        attestation_id,
        dg1_packed_hash,
        eContent_shaBytes_packed_hash,
        dsc_tree_leaf
    ]);
    
    // Verify commitment inclusion
    signal computedRoot <== BinaryMerkleRoot(nLevels)(commitment, merkletree_size, path, siblings);
    merkle_root === computedRoot;
}