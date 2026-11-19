// sdk/aegis-core.mjs — AEGIS cryptography in pure JavaScript (no WASM, no dependencies).
//
// Runs in the phone browser and in Node. It computes EXACTLY the same values as the Noir
// circuits (noir_circuits/aegis_lib) and as sdk/aegis.mjs (bb.js): the tests in
// noir_circuits/test/core.test.mjs check this.
//
// It contains:
//   - Poseidon2 (BN254, t=4) and the protocol hashes (notes, nullifiers, credentials)
//   - Merkle tree (same rules as ShieldedPool.sol)
//   - Grumpkin (curve y^2 = x^3 - 17) for the auditor keys
//   - decryption of the disclosure ciphertexts, including THRESHOLD decryption
//     (Shamir t-of-n): no committee member ever holds the whole key.
//
// ECDSA signing of KYC credentials is delegated to the caller (ethers / noble).
import { RC_FULL, RC_PARTIAL, DIAG } from './poseidon2-constants.mjs';

/** BN254 scalar field = Grumpkin base field. */
export const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
/** Order of the Grumpkin group (= BN254 base field). */
export const Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
export const TREE_DEPTH = 20;
export const DOMAIN = { PK: 1n, NOTE: 2n, NULLIFIER: 3n, CREDENTIAL: 4n, KEYSTREAM: 5n, BALANCE: 6n };

const mod = (a, m = P) => ((a % m) + m) % m;
const pow5 = (x) => { const x2 = (x * x) % P; return (((x2 * x2) % P) * x) % P; };

// ---------------------------------------------------------------- Poseidon2
function extLayer(s) {
  const [a, b, c, d] = s;
  return [
    (5n * a + 7n * b + c + 3n * d) % P,
    (4n * a + 6n * b + c + d) % P,
    (a + 3n * b + 5n * c + 7n * d) % P,
    (a + b + 4n * c + 6n * d) % P,
  ];
}

export function poseidon2Permutation(state) {
  let s = extLayer(state.map((x) => mod(BigInt(x))));
  for (let r = 0; r < 4; r++) s = extLayer(s.map((x, j) => pow5((x + RC_FULL[r][j]) % P)));
  for (let r = 0; r < 56; r++) {
    s[0] = pow5((s[0] + RC_PARTIAL[r]) % P);
    const t = (s[0] + s[1] + s[2] + s[3]) % P;
    s = s.map((x, j) => (x * DIAG[j] + t) % P);
  }
  for (let r = 4; r < 8; r++) s = extLayer(s.map((x, j) => pow5((x + RC_FULL[r][j]) % P)));
  return s;
}

/** Poseidon2 sponge, identical to bb.js poseidon2Hash and to aegis_lib::hash::poseidon2. */
export function poseidon2(inputs) {
  let state = [0n, 0n, 0n, BigInt(inputs.length) << 64n];
  let cache = [];
  for (const x of inputs) {
    if (cache.length === 3) {
      for (let j = 0; j < 3; j++) state[j] = (state[j] + cache[j]) % P;
      state = poseidon2Permutation(state);
      cache = [];
    }
    cache.push(mod(BigInt(x)));
  }
  for (let j = 0; j < cache.length; j++) state[j] = (state[j] + cache[j]) % P;
  return poseidon2Permutation(state)[0];
}

export const hash2 = (l, r) => poseidon2([l, r]);
export const ownerPubkey = (secret) => poseidon2([DOMAIN.PK, secret]);
export const noteCommitment = (amount, owner, asset, blinding) => poseidon2([DOMAIN.NOTE, amount, owner, asset, blinding]);
export const nullifier = (secret, commitment, leafIndex) => poseidon2([DOMAIN.NULLIFIER, secret, commitment, leafIndex]);
export const credentialHash = (owner, { tier, jurisdiction, expiry }) =>
  poseidon2([DOMAIN.CREDENTIAL, owner, BigInt(tier), BigInt(jurisdiction), BigInt(expiry)]);
export const balanceCommitment = (balance, blinding) => poseidon2([DOMAIN.BALANCE, balance, blinding]);

export function randomScalar(m = P) {
  const b = new Uint8Array(48); // 384 bits → negligible bias after the reduction
  globalThis.crypto.getRandomValues(b);
  let x = 0n;
  for (const v of b) x = (x << 8n) | BigInt(v);
  return mod(x, m - 1n) + 1n; // never zero
}
export const randomField = () => randomScalar(P);
export const toHex = (x) => '0x' + BigInt(x).toString(16).padStart(64, '0');

// ---------------------------------------------------------------- Merkle tree
export class MerkleTree {
  constructor(depth = TREE_DEPTH) {
    this.depth = depth;
    this.zeros = [0n];
    for (let i = 1; i <= depth; i++) this.zeros.push(hash2(this.zeros[i - 1], this.zeros[i - 1]));
    this.levels = Array.from({ length: depth + 1 }, () => []);
  }
  get size() { return this.levels[0].length; }
  insert(leaf) {
    let idx = this.levels[0].length;
    this.levels[0].push(mod(BigInt(leaf)));
    for (let d = 0; d < this.depth; d++) {
      const left = idx & ~1, cur = this.levels[d];
      const node = hash2(cur[left], left + 1 < cur.length ? cur[left + 1] : this.zeros[d]);
      idx >>= 1;
      this.levels[d + 1][idx] = node;
    }
    return this.levels[0].length - 1;
  }
  root() { return this.size === 0 ? this.zeros[this.depth] : this.levels[this.depth][0]; }
  path(index) {
    const out = [];
    let idx = index;
    for (let d = 0; d < this.depth; d++) {
      const sib = idx ^ 1;
      out.push(sib < this.levels[d].length ? this.levels[d][sib] : this.zeros[d]);
      idx >>= 1;
    }
    return out;
  }
  static verify(leaf, index, path, root) {
    let node = mod(BigInt(leaf)), idx = index;
    for (const sib of path) { node = idx & 1 ? hash2(sib, node) : hash2(node, sib); idx >>= 1; }
    return node === root;
  }
}

// ---------------------------------------------------------------- Grumpkin
export const G = { x: 1n, y: 0x0000000000000002cf135e7506a45d632d270d45f1181294833fc48d823f272cn };
export const INF = null;
const inv = (a) => {
  let [r0, r1, s0, s1] = [mod(a), P, 1n, 0n];
  while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
  return mod(s0);
};
export const onCurve = (pt) => pt !== INF && mod(pt.y * pt.y - (pt.x * pt.x * pt.x - 17n)) === 0n;

export function pointAdd(a, b) {
  if (a === INF) return b;
  if (b === INF) return a;
  if (a.x === b.x) {
    if (mod(a.y + b.y) === 0n) return INF;
    const l = mod(3n * a.x * a.x * inv(2n * a.y));
    const x = mod(l * l - 2n * a.x);
    return { x, y: mod(l * (a.x - x) - a.y) };
  }
  const l = mod((b.y - a.y) * inv(b.x - a.x));
  const x = mod(l * l - a.x - b.x);
  return { x, y: mod(l * (a.x - x) - a.y) };
}

export function scalarMul(pt, k) {
  let n = mod(BigInt(k), Q), acc = INF, add = pt;
  while (n > 0n) { if (n & 1n) acc = pointAdd(acc, add); add = pointAdd(add, add); n >>= 1n; }
  return acc;
}

export function auditorKeypair(secret = randomScalar(Q)) {
  return { secret, pub: scalarMul(G, secret) };
}

// ---------------------------------------------------------------- disclosure
const keystream = (shared, i) => poseidon2([DOMAIN.KEYSTREAM, shared.x, shared.y, BigInt(i)]);

/** Same encryption as aegis_lib::disclosure::encrypt (useful for simulations and tests). */
export function encrypt(plaintext, auditorPub, r = randomField()) {
  const eph = scalarMul(G, r), shared = scalarMul(auditorPub, r);
  return { eph, ct: plaintext.map((m, i) => mod(BigInt(m) + keystream(shared, i))) };
}

/** Decryption with the whole key (only for tests / single auditor). */
export function decrypt(secret, eph, ct) {
  return decryptWithShared(scalarMul(eph, secret), ct);
}
export const decryptWithShared = (shared, ct) => ct.map((c, i) => mod(BigInt(c) - keystream(shared, i)));

// ---------------------------------------------------------------- threshold (t-of-n)
// The committee key is split with Shamir over the Grumpkin scalar field. Each member
// computes ONLY its own partial share D_i = s_i · eph for the authorized transaction;
// combining t shares with the Lagrange coefficients gives s · eph without anyone ever
// reconstructing s. (In production: distributed key generation (DKG) so that not even
// the dealer knows s, plus a DLEQ proof for each partial share.)

export function splitSecret(secret, t, n) {
  if (t < 1 || t > n) throw new Error('invalid threshold');
  const coeffs = [mod(BigInt(secret), Q)];
  for (let i = 1; i < t; i++) coeffs.push(randomScalar(Q));
  const shares = [];
  for (let i = 1n; i <= BigInt(n); i++) {
    let y = 0n;
    for (let j = coeffs.length - 1; j >= 0; j--) y = mod(y * i + coeffs[j], Q);
    shares.push({ index: i, secret: y, pub: scalarMul(G, y) });
  }
  return shares;
}

export function partialDecrypt(share, eph) {
  return { index: share.index, point: scalarMul(eph, share.secret) };
}

const invQ = (a) => {
  let [r0, r1, s0, s1] = [mod(a, Q), Q, 1n, 0n];
  while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
  return mod(s0, Q);
};

export function combinePartials(partials) {
  const ids = partials.map((p) => p.index);
  if (new Set(ids.map(String)).size !== ids.length) throw new Error('duplicate share');
  let acc = INF;
  for (const p of partials) {
    let num = 1n, den = 1n;
    for (const j of ids) if (j !== p.index) { num = mod(num * j, Q); den = mod(den * (j - p.index), Q); }
    acc = pointAdd(acc, scalarMul(p.point, mod(num * invQ(den), Q)));
  }
  return acc;
}

export function thresholdDecrypt(partials, ct) {
  return decryptWithShared(combinePartials(partials), ct);
}

// ---------------------------------------------------------------- Schnorr (KYC credentials)
// Same scheme as aegis_lib::credential::verify_schnorr:
//   e = Poseidon2(DOMAIN_SCHNORR=7, R.x, R.y, PK.x, PK.y, msg);  s = k + e·sk (mod Q);  check s·G == R + e·PK
export const DOMAIN_SCHNORR = 7n;
export const DOMAIN_RATE = 8n;
export const EPOCH_SECONDS = 86400n;

export const credentialHashV2 = (owner, { tier, jurisdiction, expiry, personTag }) =>
  poseidon2([DOMAIN.CREDENTIAL, owner, BigInt(tier), BigInt(jurisdiction), BigInt(expiry), BigInt(personTag)]);

export function schnorrSign(secret, msg, k = randomScalar(Q)) {
  const pub = scalarMul(G, secret);
  const R = scalarMul(G, k);
  const e = poseidon2([DOMAIN_SCHNORR, R.x, R.y, pub.x, pub.y, msg]);
  const s = mod(k + mod(e, Q) * mod(BigInt(secret), Q), Q);
  return { R, s, sLo: s & ((1n << 128n) - 1n), sHi: s >> 128n };
}

export function schnorrVerify(pub, msg, { R, s }) {
  if (!onCurve(pub) || !onCurve(R)) return false;
  const e = poseidon2([DOMAIN_SCHNORR, R.x, R.y, pub.x, pub.y, msg]);
  const lhs = scalarMul(G, s);
  const rhs = pointAdd(R, scalarMul(pub, e));
  return lhs !== INF && rhs !== INF && lhs.x === rhs.x && lhs.y === rhs.y;
}

/** Issuer side (e.g. the backend): credential for `owner` with the person's `personTag`. */
export function issueCredentialV2(issuerSecret, owner, { tier, jurisdiction, expiry, personTag }) {
  const h = credentialHashV2(owner, { tier, jurisdiction, expiry, personTag });
  return { tier, jurisdiction, expiry: BigInt(expiry), personTag: BigInt(personTag), sig: schnorrSign(issuerSecret, h), hash: h };
}

export const rateNullifier = (personTag, now, slot) =>
  poseidon2([DOMAIN_RATE, BigInt(personTag), BigInt(now) / EPOCH_SECONDS, BigInt(slot)]);

// ---------------------------------------------------------------- DLEQ (Chaum-Pedersen)
// Proves that log_G(Y) == log_E(D), i.e. that the partial share D = s_i·E was computed with the SAME
// secret as the published public share Y = s_i·G. A dishonest member cannot send a fake share.
export function dleqProve(secret, E, Y = scalarMul(G, secret), D = scalarMul(E, secret)) {
  const w = randomScalar(Q);
  const A = scalarMul(G, w), B = scalarMul(E, w);
  const c = mod(poseidon2([9n, Y.x, Y.y, E.x, E.y, D.x, D.y, A.x, A.y, B.x, B.y]), Q);
  return { c, z: mod(w + c * mod(BigInt(secret), Q), Q) };
}

export function dleqVerify(Y, E, D, { c, z }) {
  // A = z·G − c·Y ; B = z·E − c·D
  const neg = (P) => (P === INF ? INF : { x: P.x, y: mod(-P.y) });
  const A = pointAdd(scalarMul(G, z), neg(scalarMul(Y, c)));
  const B = pointAdd(scalarMul(E, z), neg(scalarMul(D, c)));
  if (A === INF || B === INF) return false;
  return mod(poseidon2([9n, Y.x, Y.y, E.x, E.y, D.x, D.y, A.x, A.y, B.x, B.y]), Q) === c;
}

/** Partial share WITH proof: the committee can check it before combining. */
export function partialDecryptWithProof(share, eph) {
  const point = scalarMul(eph, share.secret);
  return { index: share.index, point, proof: dleqProve(share.secret, eph, share.pub, point) };
}

/** Combine ONLY verified shares (Y_i are the members' public shares). Throws on a fake share. */
export function thresholdDecryptVerified(partials, publicShares, eph, ct) {
  for (const p of partials) {
    const Y = publicShares.get(String(p.index));
    if (!Y || !dleqVerify(Y, eph, p.point, p.proof)) throw new Error(`invalid partial share from member ${p.index}`);
  }
  return thresholdDecrypt(partials, ct);
}

// ---------------------------------------------------------------- DKG (Pedersen/Feldman)
// No "dealer": each member chooses their own polynomial, publishes the commitments of the coefficients
// and sends every other member their share. The committee key is the SUM of the constant terms:
// nobody ever knows it in full.
export function dkgDeal(t, n) {
  const coeffs = Array.from({ length: t }, () => randomScalar(Q));
  const commitments = coeffs.map((a) => scalarMul(G, a));
  const shares = new Map();
  for (let j = 1n; j <= BigInt(n); j++) {
    let y = 0n;
    for (let k = coeffs.length - 1; k >= 0; k--) y = mod(y * j + coeffs[k], Q);
    shares.set(String(j), y);
  }
  return { commitments, shares };
}

/** Feldman check: the share received from a dealer is consistent with their public commitments. */
export function dkgVerifyShare(j, share, commitments) {
  let acc = INF, jPow = 1n;
  for (const C of commitments) { acc = pointAdd(acc, scalarMul(C, jPow)); jPow = mod(jPow * BigInt(j), Q); }
  const lhs = scalarMul(G, share);
  return acc !== INF && lhs.x === acc.x && lhs.y === acc.y;
}

/** Run by member j: verify the shares received and build its final share. */
export function dkgFinalize(j, deals) {
  let secret = 0n;
  for (const d of deals) {
    const s = d.shares.get(String(j));
    if (!dkgVerifyShare(j, s, d.commitments)) throw new Error(`dealer gave an invalid share to member ${j}`);
    secret = mod(secret + s, Q);
  }
  return { index: BigInt(j), secret, pub: scalarMul(G, secret) };
}

/** Committee public key = sum of the commitments to the constant terms. */
export const dkgPublicKey = (deals) => deals.reduce((acc, d) => pointAdd(acc, d.commitments[0]), INF);
