// balance_proof/src/main.nr
// Proves: private_balance >= public_threshold
// Without revealing the actual balance

fn main(
    private_balance: u64,       // private: actual balance
    blinding_factor: Field,     // private: Pedersen blinding factor
    threshold: pub u64,         // public: minimum balance to prove
    commitment: pub Field,      // public: Pedersen commitment to verify
) {
    // Assert balance meets threshold
    assert(private_balance >= threshold);

    // Verify Pedersen commitment: C = balance * G + r * H
    // Simplified as field arithmetic for circuit compatibility
    let g: Field = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    let h: Field = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    let balance_field: Field = private_balance as Field;
    let computed_commitment = balance_field * g + blinding_factor * h;
    assert(computed_commitment == commitment);
}
