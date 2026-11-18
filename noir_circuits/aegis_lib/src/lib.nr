//! AEGIS shared ZK primitives.
//!
//! Everything here is built on the Poseidon2 permutation shipped with the Noir
//! standard library (same sponge as Barretenberg's `poseidon2Hash`, so values
//! can be recomputed off-chain with bb.js), ECDSA-secp256k1 and the embedded
//! Grumpkin curve. No hand-rolled "commitments" over field arithmetic.

pub mod hash;
pub mod note;
pub mod merkle;
pub mod credential;
pub mod disclosure;

/// Depth of the note commitment tree (2^20 ≈ 1M notes).
pub global TREE_DEPTH: u32 = 20;

/// Domain separators: every hash in the protocol starts with one, so a value
/// produced for one purpose can never be replayed as another.
pub global DOMAIN_PK: Field = 1;
pub global DOMAIN_NOTE: Field = 2;
pub global DOMAIN_NULLIFIER: Field = 3;
pub global DOMAIN_CREDENTIAL: Field = 4;
pub global DOMAIN_KEYSTREAM: Field = 5;
pub global DOMAIN_BALANCE: Field = 6;
