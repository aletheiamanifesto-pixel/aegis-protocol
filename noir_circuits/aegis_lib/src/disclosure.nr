use crate::DOMAIN_KEYSTREAM;
use crate::hash::poseidon2;
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul, multi_scalar_mul,
};

/// Verifiable encryption of `plaintext` to `auditor` (a Grumpkin public key).
///
/// ECDH on Grumpkin: eph = r·G, shared = r·A, ct[i] = pt[i] + Poseidon2(shared, i).
/// Because it is computed inside the proof, the network has the guarantee that
/// the holder of the auditor key CAN decrypt it (a user cannot submit garbage).
/// The auditor key is meant to be a threshold key (t-of-n committee): it decrypts
/// computing sk·eph via shares, without ever rebuilding sk, and one ciphertext at a
/// time: disclosure is per transaction, not all-or-nothing.
pub fn encrypt<let N: u32>(
    plaintext: [Field; N],
    auditor: EmbeddedCurvePoint,
    randomness: Field,
) -> (EmbeddedCurvePoint, [Field; N]) {
    assert(randomness != 0, "zero encryption randomness");
    // Coordinates are not checked by the stdlib: require a point on Grumpkin
    // (y^2 = x^3 - 17) other than the point at infinity.
    assert(!auditor.is_infinite(), "auditor key is infinity");
    assert(auditor.y * auditor.y == auditor.x * auditor.x * auditor.x - 17, "auditor key not on curve");
    let r = EmbeddedCurveScalar::from_field(randomness);
    let eph = fixed_base_scalar_mul(r);
    let shared = multi_scalar_mul([auditor], [r]);
    let mut ct: [Field; N] = [0; N];
    for i in 0..N {
        ct[i] = plaintext[i] + poseidon2([DOMAIN_KEYSTREAM, shared.x, shared.y, i as Field]);
    }
    (eph, ct)
}
