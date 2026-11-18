use crate::{DOMAIN_NOTE, DOMAIN_NULLIFIER, DOMAIN_PK};
use crate::hash::poseidon2;

/// Public "address" of a shielded account, derived from its spending secret.
pub fn owner_pubkey(spending_secret: Field) -> Field {
    poseidon2([DOMAIN_PK, spending_secret])
}

/// Hiding + binding commitment to a note (Poseidon2 is collision resistant and
/// the random blinding hides the content).
pub fn note_commitment(amount: u64, owner: Field, asset: Field, blinding: Field) -> Field {
    poseidon2([DOMAIN_NOTE, amount as Field, owner, asset, blinding])
}

/// Nullifier published when a note is spent. Only the owner (who knows the
/// secret) can compute it, and it is unique per note, which prevents double spends.
pub fn nullifier(spending_secret: Field, commitment: Field, leaf_index: Field) -> Field {
    poseidon2([DOMAIN_NULLIFIER, spending_secret, commitment, leaf_index])
}
