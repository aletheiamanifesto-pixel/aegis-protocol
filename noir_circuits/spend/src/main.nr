//! AEGIS shielded transaction (join-split 2 inputs → 2 outputs).
//!
//! A single circuit covers deposits (public_in > 0), private transfers and
//! withdrawals (public_out > 0). In one proof it proves:
//!
//!  1. Ownership: the input notes exist in the tree (`root`) and belong to whoever
//!     knows `spending_secret`; their nullifiers are correct (no double spend).
//!  2. Conservation: in0 + in1 + public_in == out0 + out1 + public_out.
//!  3. Compliance: the sender holds a valid, unexpired KYC credential signed by a
//!     registered issuer, in an allowed jurisdiction, and the amount moved
//!     does not exceed its tier's limit.
//!  4. Graduated disclosure: two verifiable ciphertexts are produced
//!       - TAX  (level 2): who pays and how much, without the counterparty;
//!       - AML  (level 3): full transaction detail.
//!     Each is encrypted to a different (threshold) key: the tax authority cannot
//!     see what is only for the FIU, and nobody can see anything without the key.
//!
//! Convention: out[0] = payment, out[1] = change (always back to the sender).

use aegis_lib::{TREE_DEPTH};
use aegis_lib::note::{note_commitment, nullifier, owner_pubkey};
use aegis_lib::merkle::compute_root;
use aegis_lib::credential::{Credential, verify_credential};
use aegis_lib::disclosure::encrypt;
use std::embedded_curve_ops::EmbeddedCurvePoint;

fn main(
    // ---- public inputs (checked by ShieldedPool.sol) ----
    root: pub Field,
    nullifiers: pub [Field; 2],
    out_commitments: pub [Field; 2],
    public_in: pub u64,
    public_out: pub u64,
    asset: pub Field,
    ext_data_hash: pub Field, // binds recipient/relayer/fee: blocks front-running
    now: pub u64,
    allowed_jurisdictions: pub u64,
    tier_limits: pub [u64; 4],
    issuer_pk_x: pub [u8; 32],
    issuer_pk_y: pub [u8; 32],
    tax_key: pub EmbeddedCurvePoint,
    aml_key: pub EmbeddedCurvePoint,
    // ---- private witness ----
    spending_secret: Field,
    in_amounts: [u64; 2],
    in_blindings: [Field; 2],
    in_leaf_indices: [Field; 2],
    in_paths: [[Field; TREE_DEPTH]; 2],
    out_amounts: [u64; 2],
    out_owners: [Field; 2],
    out_blindings: [Field; 2],
    credential: Credential,
    tax_randomness: Field,
    aml_randomness: Field,
) -> pub (EmbeddedCurvePoint, [Field; 4], EmbeddedCurvePoint, [Field; 8]) {
    let owner = owner_pubkey(spending_secret);

    // 1. Input notes: existence + nullifiers. Notes with amount 0 are "dummies"
    //    (needed for deposits) and skip the tree check.
    for i in 0..2 {
        let cm = note_commitment(in_amounts[i], owner, asset, in_blindings[i]);
        if in_amounts[i] != 0 {
            assert(compute_root(cm, in_leaf_indices[i], in_paths[i]) == root, "note not in tree");
        }
        assert(nullifier(spending_secret, cm, in_leaf_indices[i]) == nullifiers[i], "bad nullifier");
    }
    assert(nullifiers[0] != nullifiers[1], "duplicate nullifier");

    // Output notes.
    assert(out_owners[1] == owner, "change must return to sender");
    for i in 0..2 {
        assert(
            note_commitment(out_amounts[i], out_owners[i], asset, out_blindings[i]) == out_commitments[i],
            "bad output commitment",
        );
    }

    // 2. Conservation (u64 values summed in the field: no overflow possible).
    let total_in = in_amounts[0] as Field + in_amounts[1] as Field + public_in as Field;
    let total_out = out_amounts[0] as Field + out_amounts[1] as Field + public_out as Field;
    assert(total_in == total_out, "value not conserved");

    // 3. Compliance.
    let cred_hash = verify_credential(owner, credential, issuer_pk_x, issuer_pk_y, now, allowed_jurisdictions);
    let moved = out_amounts[0] as u128 + public_out as u128;
    assert(moved <= tier_limits[credential.tier as u32] as u128, "amount above tier limit");

    // Binds ext_data_hash to the proof (otherwise the compiler would treat it as unused).
    assert(ext_data_hash != 0, "missing ext data hash");

    // 4. Graduated disclosure (verifiable encryption).
    let (tax_eph, tax_ct) = encrypt(
        [owner, out_amounts[0] as Field, public_in as Field, public_out as Field],
        tax_key,
        tax_randomness,
    );
    let (aml_eph, aml_ct) = encrypt(
        [
            owner,
            out_owners[0],
            out_amounts[0] as Field,
            out_amounts[1] as Field,
            public_in as Field,
            public_out as Field,
            cred_hash,
            (credential.tier as Field) * 256 + credential.jurisdiction as Field,
        ],
        aml_key,
        aml_randomness,
    );
    (tax_eph, tax_ct, aml_eph, aml_ct)
}
