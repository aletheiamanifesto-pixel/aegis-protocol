// sdk/aegis.mjs — off-chain helpers for the AEGIS shielded pool.
//
// Mirrors exactly the Noir functions in noir_circuits/aegis_lib (same Poseidon2,
// same domain separators), so the values computed here satisfy the circuits.
import { Barretenberg, BN254_FR_MODULUS, GRUMPKIN_G1_GENERATOR } from '@aztec/bb.js';
import { createRequire } from 'module';
import * as core from './aegis-core.mjs';

const require = createRequire(import.meta.url);
const { ethers } = require('ethers');

export const P = BN254_FR_MODULUS;
export const TREE_DEPTH = 20;
export const DOMAIN = { PK: 1n, NOTE: 2n, NULLIFIER: 3n, CREDENTIAL: 4n, KEYSTREAM: 5n, BALANCE: 6n };

const toBytes = (x) => ethers.getBytes(ethers.toBeHex(((BigInt(x) % P) + P) % P, 32));
const toBig = (b) => BigInt(ethers.hexlify(b));
export const hex = (x) => ethers.toBeHex(BigInt(x), 32);
export const randomField = () => toBig(ethers.randomBytes(32)) % P;

export class Aegis {
  static async create() {
    const a = new Aegis();
    a.bb = await Barretenberg.new({ threads: 1 });
    return a;
  }
  async destroy() { await this.bb.destroy(); }

  async poseidon2(inputs) {
    const r = await this.bb.poseidon2Hash({ inputs: inputs.map(toBytes) });
    return toBig(r.hash);
  }
  hash2(l, r) { return this.poseidon2([l, r]); }
  ownerPubkey(secret) { return this.poseidon2([DOMAIN.PK, secret]); }
  noteCommitment(amount, owner, asset, blinding) {
    return this.poseidon2([DOMAIN.NOTE, amount, owner, asset, blinding]);
  }
  nullifier(secret, commitment, leafIndex) {
    return this.poseidon2([DOMAIN.NULLIFIER, secret, commitment, leafIndex]);
  }
  balanceCommitment(balance, blinding) { return this.poseidon2([DOMAIN.BALANCE, balance, blinding]); }

  // ---- KYC credential: Schnorr on Grumpkin, same scheme as aegis_lib::credential ----
  async credentialHash(owner, c) { return core.credentialHashV2(owner, c); }
  async issueCredential(issuerSecret, owner, { tier, jurisdiction, expiry, personTag }) {
    return core.issueCredentialV2(BigInt(issuerSecret), owner, { tier, jurisdiction, expiry, personTag });
  }
  static issuerPublicKey(issuerSecret) { return core.scalarMul(core.G, BigInt(issuerSecret)); }

  // ---- Auditor keys (Grumpkin) and decryption of the disclosure ciphertexts ----
  async grumpkinMul(point, scalar) {
    const r = await this.bb.grumpkinMul({ point: { x: toBytes(point.x), y: toBytes(point.y) }, scalar: toBytes(scalar) });
    return { x: toBig(r.point.x), y: toBig(r.point.y) };
  }
  async auditorKeypair(secret = randomField()) {
    const G = { x: toBig(GRUMPKIN_G1_GENERATOR.x), y: toBig(GRUMPKIN_G1_GENERATOR.y) };
    return { secret, pub: await this.grumpkinMul(G, secret) };
  }
  // In production `secret * eph` is computed by the t-of-n committee with
  // threshold shares; here with the whole key, for the tests.
  async decrypt(auditorSecret, eph, ct) {
    const shared = await this.grumpkinMul(eph, auditorSecret);
    const out = [];
    for (let i = 0; i < ct.length; i++) {
      const ks = await this.poseidon2([DOMAIN.KEYSTREAM, shared.x, shared.y, BigInt(i)]);
      out.push((((BigInt(ct[i]) - ks) % P) + P) % P);
    }
    return out;
  }
}

// Incremental Merkle tree with zeros[i] = hash2(zeros[i-1], zeros[i-1]) and zeros[0] = 0.
// Same rule as ShieldedPool.sol.
export class MerkleTree {
  static async create(aegis, depth = TREE_DEPTH) {
    const t = new MerkleTree();
    t.aegis = aegis; t.depth = depth; t.leaves = []; t.zeros = [0n];
    for (let i = 1; i <= depth; i++) t.zeros.push(await aegis.hash2(t.zeros[i - 1], t.zeros[i - 1]));
    return t;
  }
  insert(leaf) { this.leaves.push(BigInt(leaf)); return this.leaves.length - 1; }
  async _levels() {
    const levels = [this.leaves.slice()];
    for (let d = 0; d < this.depth; d++) {
      const cur = levels[d], next = [];
      for (let i = 0; i < cur.length; i += 2) {
        next.push(await this.aegis.hash2(cur[i], i + 1 < cur.length ? cur[i + 1] : this.zeros[d]));
      }
      levels.push(next);
    }
    return levels;
  }
  async root() {
    if (this.leaves.length === 0) return this.zeros[this.depth];
    const levels = await this._levels();
    return levels[this.depth][0];
  }
  async path(index) {
    const levels = await this._levels();
    const path = [];
    let idx = index;
    for (let d = 0; d < this.depth; d++) {
      const sib = idx ^ 1;
      path.push(sib < levels[d].length ? levels[d][sib] : this.zeros[d]);
      idx >>= 1;
    }
    return path;
  }
}

export const toNoirBytes = (b) => Array.from(b).map(String);
export const toNoirField = (x) => hex(x);
