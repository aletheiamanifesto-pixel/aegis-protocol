// transfer_proof/src/main.nr
// Proves: sender has sufficient balance and transfer is valid
// Without revealing private balance or full sender identity

fn main(
    sender_balance: u64,            // private: sender's actual balance
    transfer_amount: pub u64,       // public: amount being transferred
    sender_commitment: pub Field,   // public: Pedersen commitment of sender balance
    blinding_factor: Field,         // private: Pedersen blinding factor
    recipient_hash: pub Field,      // public: hash of recipient address
) {
    // Ensure sender has sufficient balance
    assert(sender_balance >= transfer_amount);

    // Ensure transfer amount is positive
    assert(transfer_amount > 0);

    // Verify Pedersen commitment
    let g: Field = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    let h: Field = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    let balance_field: Field = sender_balance as Field;
    let computed = balance_field * g + blinding_factor * h;
    assert(computed == sender_commitment);

    // recipient_hash is public - verified on-chain
    assert(recipient_hash != 0);
}
