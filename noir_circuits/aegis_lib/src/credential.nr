use crate::DOMAIN_CREDENTIAL;
use crate::hash::poseidon2;

/// Number of KYC tiers (0 = no KYC ... 3 = enhanced due diligence).
pub global NUM_TIERS: u32 = 4;

/// A KYC credential issued off-chain by a regulated entity (CASP / EMI / bank).
/// The issuer keeps the real identity; on-chain only `owner` (a pseudonym) appears.
pub struct Credential {
    pub tier: u8,
    pub jurisdiction: u8, // index in the 64-bit jurisdiction bitmask (e.g. IT = 0)
    pub expiry: u64,      // unix timestamp
    pub signature: [u8; 64],
}

pub fn credential_hash(owner: Field, c: Credential) -> Field {
    poseidon2([DOMAIN_CREDENTIAL, owner, c.tier as Field, c.jurisdiction as Field, c.expiry as Field])
}

/// Checks that:
/// 1. the issuer signed (owner, tier, jurisdiction, expiry) with ECDSA-secp256k1;
/// 2. the credential has not expired at time `now`;
/// 3. the jurisdiction is in `allowed_jurisdictions`;
/// 4. the tier is valid.
/// Returns the credential hash (used to bind the disclosure ciphertext).
pub fn verify_credential(
    owner: Field,
    c: Credential,
    issuer_pk_x: [u8; 32],
    issuer_pk_y: [u8; 32],
    now: u64,
    allowed_jurisdictions: u64,
) -> Field {
    let h = credential_hash(owner, c);
    let digest: [u8; 32] = h.to_be_bytes();
    assert(
        std::ecdsa_secp256k1::verify_signature(issuer_pk_x, issuer_pk_y, c.signature, digest),
        "invalid KYC credential signature",
    );
    assert(c.expiry >= now, "KYC credential expired");
    assert(c.jurisdiction < 64, "invalid jurisdiction");
    assert(((allowed_jurisdictions >> (c.jurisdiction as u64)) & 1) == 1, "jurisdiction not allowed");
    assert((c.tier as u32) < NUM_TIERS, "invalid tier");
    h
}
