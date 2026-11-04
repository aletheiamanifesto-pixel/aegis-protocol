//! Proof of compliance with no transaction: "I hold a valid KYC credential, tier ≥ min_tier,
//! in an allowed jurisdiction", without revealing identity, tier or exact jurisdiction.
//! Useful for gated access (e.g. a merchant or a DeFi protocol requiring KYC).
//!
//! `scope` + `scope_nullifier` make the proof single-use per context
//! (e.g. one registration per service) without making it linkable across services.

use aegis_lib::note::owner_pubkey;
use aegis_lib::credential::{Credential, verify_credential};
use aegis_lib::hash::poseidon2;

fn main(
    issuer_pk_x: pub [u8; 32],
    issuer_pk_y: pub [u8; 32],
    now: pub u64,
    allowed_jurisdictions: pub u64,
    min_tier: pub u8,
    scope: pub Field,
    spending_secret: Field,
    credential: Credential,
) -> pub Field {
    let owner = owner_pubkey(spending_secret);
    let _ = verify_credential(owner, credential, issuer_pk_x, issuer_pk_y, now, allowed_jurisdictions);
    assert(credential.tier >= min_tier, "tier too low");
    poseidon2([scope, spending_secret])
}
