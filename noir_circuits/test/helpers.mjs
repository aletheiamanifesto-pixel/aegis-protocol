import { compile, createFileManager } from '@noir-lang/noir_wasm';
import { Noir } from '@noir-lang/noir_js';
import path from 'path';
import { fileURLToPath } from 'url';
import { Aegis, MerkleTree, hex, randomField, toNoirBytes, TREE_DEPTH } from '../../sdk/aegis.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
export const CIRCUITS_DIR = path.resolve(here, '..');

const cache = {};
export async function loadCircuit(name) {
  if (!cache[name]) {
    const res = await compile(createFileManager(path.join(CIRCUITS_DIR, name)));
    cache[name] = res.program;
  }
  return cache[name];
}

export const ISSUER_KEY = '0x' + '42'.repeat(32);
export const NOW = 1_800_000_000n;
export const IT = 0; // bit 0 of the jurisdiction mask = Italy
export const ALLOWED = (1n << 0n) | (1n << 1n); // IT + DE, for example
export const TIER_LIMITS = [0n, 1_000n * 100n, 15_000n * 100n, 1_000_000n * 100n]; // cents

const point = (p) => ({ x: hex(p.x), y: hex(p.y) });

// Builds a full spend witness. `opts` lets the tests break one rule at a time.
export async function buildSpend(aegis, tree, w, opts = {}) {
  const owner = await aegis.ownerPubkey(w.secret);
  const ins = [];
  for (let i = 0; i < 2; i++) {
    const n = w.inputs[i] ?? { amount: 0n, blinding: randomField(), leafIndex: 0 };
    const cm = await aegis.noteCommitment(n.amount, owner, w.asset, n.blinding);
    const nf = await aegis.nullifier(w.secret, cm, BigInt(n.leafIndex));
    const p = n.amount === 0n ? Array(TREE_DEPTH).fill(0n) : await tree.path(n.leafIndex);
    ins.push({ ...n, cm, nf, path: p });
  }
  const outs = [];
  for (let i = 0; i < 2; i++) {
    const o = w.outputs[i];
    outs.push({ ...o, cm: await aegis.noteCommitment(o.amount, o.owner, w.asset, o.blinding) });
  }
  const cred = w.credential;
  const issuer = Aegis.issuerPublicKey(opts.issuerKey ?? ISSUER_KEY);
  const inputs = {
    root: hex(await tree.root()),
    nullifiers: [hex(ins[0].nf), hex(opts.duplicateNullifier ? ins[0].nf : ins[1].nf)],
    out_commitments: outs.map((o) => hex(o.cm)),
    public_in: (w.publicIn ?? 0n).toString(),
    public_out: (w.publicOut ?? 0n).toString(),
    asset: hex(w.asset),
    ext_data_hash: hex(w.extDataHash ?? 1n),
    now: (opts.now ?? NOW).toString(),
    allowed_jurisdictions: (opts.allowed ?? ALLOWED).toString(),
    tier_limits: TIER_LIMITS.map(String),
    issuer_pk_x: toNoirBytes(issuer.x),
    issuer_pk_y: toNoirBytes(issuer.y),
    tax_key: point(w.taxKey),
    aml_key: point(w.amlKey),
    spending_secret: hex(w.secret),
    in_amounts: ins.map((n) => n.amount.toString()),
    in_blindings: ins.map((n) => hex(n.blinding)),
    in_leaf_indices: ins.map((n) => n.leafIndex.toString()),
    in_paths: ins.map((n) => n.path.map(hex)),
    out_amounts: outs.map((o) => o.amount.toString()),
    out_owners: outs.map((o) => hex(o.owner)),
    out_blindings: outs.map((o) => hex(o.blinding)),
    credential: {
      tier: cred.tier.toString(),
      jurisdiction: cred.jurisdiction.toString(),
      expiry: cred.expiry.toString(),
      signature: toNoirBytes(cred.signature),
    },
    tax_randomness: hex(randomField()),
    aml_randomness: hex(randomField()),
  };
  return { inputs, ins, outs, owner };
}

export async function execute(name, inputs) {
  const noir = new Noir(await loadCircuit(name));
  return noir.execute(inputs);
}

export { Aegis, MerkleTree, hex, randomField, toNoirBytes };
