use crate::{DOMAIN_CREDENTIAL, DOMAIN_SCHNORR};
use crate::hash::poseidon2;
use std::embedded_curve_ops::{
    embedded_curve_add, fixed_base_scalar_mul, multi_scalar_mul, EmbeddedCurvePoint, EmbeddedCurveScalar,
};

/// Number of KYC tiers (0 = no KYC ... 3 = enhanced due diligence).
pub global NUM_TIERS: u32 = 4;

/// A KYC credential issued off-chain by a regulated entity (CASP / EMI / bank).
///
/// - `owner` (outside the struct) is the pseudonym of the notes; the issuer knows who it belongs to.
/// - `person_tag` is ONE per person (the same on every credential of that person, whatever the
///   pseudonym): it is used for the daily rate limit, so N pseudonyms do not multiply the limit.
/// - Schnorr signature on Grumpkin (the circuit's native curve): far fewer gates than
///   ECDSA-secp256k1.
pub struct Credential {
    pub tier: u8,
    pub jurisdiction: u8, // index in the 64-bit jurisdiction bitmask (e.g. IT = 0)
    pub expiry: u64,      // unix timestamp
    pub person_tag: Field,
    pub sig_r: EmbeddedCurvePoint,
    pub sig_s_lo: Field, // s split into two 128-bit halves (s is a Grumpkin scalar)
    pub sig_s_hi: Field,
}

pub fn credential_hash(owner: Field, c: Credential) -> Field {
    poseidon2([DOMAIN_CREDENTIAL, owner, c.tier as Field, c.jurisdiction as Field, c.expiry as Field, c.person_tag])
}

pub fn on_curve(p: EmbeddedCurvePoint) -> bool {
    (!p.is_infinite()) & (p.y * p.y == p.x * p.x * p.x - 17)
}

/// Schnorr on Grumpkin: s·G == R + e·PK, with e = Poseidon2(DOMAIN_SCHNORR, R, PK, msg).
pub fn verify_schnorr(issuer: EmbeddedCurvePoint, msg: Field, r: EmbeddedCurvePoint, s_lo: Field, s_hi: Field) -> bool {
    assert(on_curve(issuer), "issuer key not on curve");
    assert(on_curve(r), "signature R not on curve");
    s_lo.assert_max_bit_size::<128>();
    s_hi.assert_max_bit_size::<128>();
    let e = poseidon2([DOMAIN_SCHNORR, r.x, r.y, issuer.x, issuer.y, msg]);
    let lhs = fixed_base_scalar_mul(EmbeddedCurveScalar::new(s_lo, s_hi));
    let rhs = embedded_curve_add(r, multi_scalar_mul([issuer], [EmbeddedCurveScalar::from_field(e)]));
    (lhs.x == rhs.x) & (lhs.y == rhs.y)
}

/// Checks that:
/// 1. the issuer signed (owner, tier, jurisdiction, expiry, person_tag) with Schnorr-Grumpkin;
/// 2. the credential has not expired at time `now`;
/// 3. the jurisdiction is in `allowed_jurisdictions`;
/// 4. the tier is valid.
/// Returns the credential hash (used to bind the disclosure ciphertext).
pub fn verify_credential(
    owner: Field,
    c: Credential,
    issuer: EmbeddedCurvePoint,
    now: u64,
    allowed_jurisdictions: u64,
) -> Field {
    let h = credential_hash(owner, c);
    assert(verify_schnorr(issuer, h, c.sig_r, c.sig_s_lo, c.sig_s_hi), "invalid KYC credential signature");
    assert(c.expiry >= now, "KYC credential expired");
    assert(c.jurisdiction < 64, "invalid jurisdiction");
    assert(((allowed_jurisdictions >> (c.jurisdiction as u64)) & 1) == 1, "jurisdiction not allowed");
    assert((c.tier as u32) < NUM_TIERS, "invalid tier");
    h
}
