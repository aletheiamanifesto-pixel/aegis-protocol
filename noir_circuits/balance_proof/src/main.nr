//! Proves "balance ≥ threshold" for a committed balance, without revealing the balance.
//! commitment = Poseidon2(DOMAIN_BALANCE, balance, blinding): binding (the prover
//! cannot "open" the commitment to a different balance, unlike the old
//! balance*g + r*h field-arithmetic version) and hiding (the blinding is random).

use aegis_lib::DOMAIN_BALANCE;
use aegis_lib::hash::poseidon2;

fn main(private_balance: u64, blinding_factor: Field, threshold: pub u64, commitment: pub Field) {
    assert(blinding_factor != 0, "zero blinding");
    assert(
        poseidon2([DOMAIN_BALANCE, private_balance as Field, blinding_factor]) == commitment,
        "bad commitment",
    );
    assert(private_balance >= threshold, "balance below threshold");
}
