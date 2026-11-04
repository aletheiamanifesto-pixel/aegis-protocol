use crate::hash::hash2;

/// Root of the tree obtained by hashing `leaf` up along `path`, with the
/// left/right order given by the bits of `index`.
pub fn compute_root<let D: u32>(leaf: Field, index: Field, path: [Field; D]) -> Field {
    let bits: [bool; D] = index.to_le_bits();
    let mut node = leaf;
    for i in 0..D {
        let sibling = path[i];
        node = if bits[i] {
            hash2(sibling, node)
        } else {
            hash2(node, sibling)
        };
    }
    node
}
