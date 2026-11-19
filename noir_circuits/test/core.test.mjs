// The pure-JS SDK (sdk/aegis-core.mjs, used by the mobile app) must match bb.js and the circuits exactly.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as core from '../../sdk/aegis-core.mjs';
import { Aegis, MerkleTree as BbTree } from '../../sdk/aegis.mjs';
import { buildSpend, execute, ISSUER_KEY, NOW, IT } from './helpers.mjs';

let bb;
before(async () => { bb = await Aegis.create(); });
after(async () => bb.destroy());

test('Poseidon2: pure JS == bb.js for 0..7 inputs', async () => {
  for (let n = 0; n <= 7; n++) {
    const xs = Array.from({ length: n }, () => core.randomField());
    assert.equal(core.poseidon2(xs), await bb.poseidon2(xs));
  }
});

test('Merkle tree: same root and paths as the bb.js SDK', async () => {
  const a = new core.MerkleTree(), b = await BbTree.create(bb);
  assert.equal(a.root(), await b.root());
  for (let i = 0; i < 5; i++) { const l = core.randomField(); a.insert(l); b.insert(l); }
  assert.equal(a.root(), await b.root());
  assert.deepEqual(a.path(3), await b.path(3));
  assert.ok(core.MerkleTree.verify(b.leaves[3], 3, a.path(3), a.root()));
});

test('Grumpkin: same public key as bb.js and point on the curve', async () => {
  const s = core.randomScalar(core.Q);
  const mine = core.scalarMul(core.G, s);
  const theirs = await bb.grumpkinMul(core.G, s);
  assert.deepEqual(mine, theirs);
  assert.ok(core.onCurve(mine));
});

test('decrypts the ciphertexts produced by the REAL circuit, also with a 2-of-3 threshold key', async () => {
  const aml = core.auditorKeypair();
  const tax = core.auditorKeypair();
  const shares = core.splitSecret(aml.secret, 2, 3);
  // the public key derived from the shares is the same as the committee's
  assert.deepEqual(core.combinePartials(shares.slice(0, 2).map((s) => ({ index: s.index, point: s.pub }))), aml.pub);

  const secret = core.randomField();
  const owner = core.ownerPubkey(secret);
  const credential = await bb.issueCredential(ISSUER_KEY, owner, { tier: 1, jurisdiction: IT, expiry: NOW + 100n, personTag: 77n });
  const tree = await BbTree.create(bb);
  const { inputs } = await buildSpend(bb, tree, {
    secret, asset: 7n, credential, taxKey: tax.pub, amlKey: aml.pub, inputs: [], publicIn: 4_200n,
    outputs: [{ amount: 4_200n, owner, blinding: core.randomField() }, { amount: 0n, owner, blinding: core.randomField() }],
  });
  const { returnValue } = await execute('spend', inputs);
  const [, , amlEph, amlCt] = returnValue;
  const eph = { x: BigInt(amlEph.x), y: BigInt(amlEph.y) };

  // two members out of three (1 and 3), each computing only its own partial share
  const pt = core.thresholdDecrypt([core.partialDecrypt(shares[0], eph), core.partialDecrypt(shares[2], eph)], amlCt);
  assert.equal(pt[0], owner);
  assert.equal(pt[4], 4_200n);
  // a single member decrypts nothing
  const one = core.thresholdDecrypt([core.partialDecrypt(shares[1], eph)], amlCt);
  assert.notEqual(one[0], owner);
  // and the full key gives the same result
  assert.deepEqual(core.decrypt(aml.secret, eph, amlCt), pt);
});

test('protocol hashes: pure JS == bb.js', async () => {
  const s = core.randomField(), o = core.ownerPubkey(s);
  assert.equal(o, await bb.ownerPubkey(s));
  assert.equal(core.noteCommitment(5n, o, 9n, 11n), await bb.noteCommitment(5n, o, 9n, 11n));
  assert.equal(core.nullifier(s, 3n, 4n), await bb.nullifier(s, 3n, 4n));
  const c = { tier: 2, jurisdiction: 0, expiry: 99n, personTag: 5n };
  assert.equal(core.credentialHashV2(o, c), await bb.credentialHash(o, c));
});

test('DKG without dealer + DLEQ: 2 of 3 decrypt the REAL circuit, a fake share is rejected', async () => {
  const deals = [1, 2, 3].map(() => core.dkgDeal(2, 3));
  const members = [1, 2, 3].map((j) => core.dkgFinalize(j, deals));
  const committeeKey = core.dkgPublicKey(deals);
  const tax = core.auditorKeypair();
  const secret = core.randomField();
  const owner = core.ownerPubkey(secret);
  const credential = await bb.issueCredential(ISSUER_KEY, owner, { tier: 1, jurisdiction: IT, expiry: NOW + 100n, personTag: 9n });
  const tree = await BbTree.create(bb);
  const { inputs } = await buildSpend(bb, tree, {
    secret, asset: 7n, credential, taxKey: tax.pub, amlKey: committeeKey, inputs: [], publicIn: 4_200n,
    outputs: [{ amount: 4_200n, owner, blinding: core.randomField() }, { amount: 0n, owner, blinding: core.randomField() }],
  });
  const [, , amlEph, amlCt] = (await execute('spend', inputs)).returnValue;
  const eph = { x: BigInt(amlEph.x), y: BigInt(amlEph.y) };
  const pubs = new Map(members.map((m) => [String(m.index), m.pub]));
  const parts = [members[0], members[2]].map((m) => core.partialDecryptWithProof(m, eph));
  assert.equal(core.thresholdDecryptVerified(parts, pubs, eph, amlCt)[0], owner);
  const fake = { ...parts[1], point: core.scalarMul(eph, 12345n) };
  assert.throws(() => core.thresholdDecryptVerified([parts[0], fake], pubs, eph, amlCt), /invalid partial share/);
  // a dealer cheating on a share is caught by the Feldman check
  const bad = core.dkgDeal(2, 3);
  bad.shares.set('2', bad.shares.get('2') + 1n);
  assert.throws(() => core.dkgFinalize(2, [deals[0], bad]), /invalid share/);
});

test('Schnorr: signature valid only for the right message and key', () => {
  const sk = core.randomScalar(core.Q), pk = core.scalarMul(core.G, sk);
  const sig = core.schnorrSign(sk, 42n);
  assert.ok(core.schnorrVerify(pk, 42n, sig));
  assert.ok(!core.schnorrVerify(pk, 43n, sig));
  assert.ok(!core.schnorrVerify(core.scalarMul(core.G, 7n), 42n, sig));
});
