use std::hash::poseidon2_permutation;

/// Poseidon2 sponge over BN254 (t = 4, rate 3), identical to Barretenberg's
/// `poseidon2Hash` (IV = input length * 2^64).
pub fn poseidon2<let N: u32>(input: [Field; N]) -> Field {
    let two_pow_64 = 18446744073709551616;
    let mut state: [Field; 4] = [0, 0, 0, (N as Field) * two_pow_64];
    let mut cache: [Field; 3] = [0; 3];
    let mut cache_size: u32 = 0;
    for i in 0..N {
        if cache_size == 3 {
            for j in 0..3 {
                state[j] += cache[j];
            }
            state = poseidon2_permutation(state);
            cache = [0; 3];
            cache[0] = input[i];
            cache_size = 1;
        } else {
            cache[cache_size] = input[i];
            cache_size += 1;
        }
    }
    for j in 0..3 {
        if j < cache_size {
            state[j] += cache[j];
        }
    }
    state = poseidon2_permutation(state);
    state[0]
}

/// Two-to-one compression used for Merkle nodes. Must match `Poseidon2.hash2`
/// in contracts/lib/Poseidon2.sol.
pub fn hash2(left: Field, right: Field) -> Field {
    poseidon2([left, right])
}
