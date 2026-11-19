// End-to-end tests of the Noir circuits (real execution, real UltraHonk proof).
// Run: npm run test:circuits
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js';
import {
  Aegis, MerkleTree, buildSpend, execute, loadCircuit, hex, randomField, toNoirBytes,
  ISSUER_KEY, NOW, IT, ALLOWED,
} from './helpers.mjs';

let aegis, tax, aml;
const ASSET = 0xe0c0n; // EURC token address (placeholder in the tests)

before(async () => {
  aegis = await Aegis.create();
  tax = await aegis.auditorKeypair();
  aml = await aegis.auditorKeypair();
});
after(async () => aegis.destroy());

async function alice(tier = 1, opts = {}) {
  const secret = randomField();
  const owner = await aegis.ownerPubkey(secret);
  const credential = await aegis.issueCredential(opts.issuerKey ?? ISSUER_KEY, owner, {
    tier, jurisdiction: opts.jurisdiction ?? IT, expiry: opts.expiry ?? NOW + 86_400n,
  });
  return { secret, owner, credential };
}

// Deposit of 500 € → Alice has a 500 € note in the tree.
async function depositedNote(user, amount = 50_000n) {
  const tree = await MerkleTree.create(aegis);
  const blinding = randomField();
  const cm = await aegis.noteCommitment(amount, user.owner, ASSET, blinding);
  tree.insert(cm);
  tree.insert(await aegis.noteCommitment(0n, user.owner, ASSET, randomField()));
  return { tree, note: { amount, blinding, leafIndex: 0 } };
}

const expectFail = async (p, msg) => {
  await assert.rejects(p, (e) => { assert.match(String(e.message ?? e), msg); return true; });
};

test('deposit: 2 dummy notes in, public_in out', async () => {
  const u = await alice();
  const tree = await MerkleTree.create(aegis);
  const { inputs } = await buildSpend(aegis, tree, {
    secret: u.secret, asset: ASSET, credential: u.credential, taxKey: tax.pub, amlKey: aml.pub,
    inputs: [], publicIn: 50_000n,
    outputs: [{ amount: 50_000n, owner: u.owner, blinding: randomField() }, { amount: 0n, owner: u.owner, blinding: randomField() }],
  });
  await execute('spend', inputs);
});

test('private transfer + graduated disclosure decryptable by the right key only', async () => {
  const u = await alice();
  const bob = await aegis.ownerPubkey(randomField());
  const { tree, note } = await depositedNote(u);
  const { inputs } = await buildSpend(aegis, tree, {
    secret: u.secret, asset: ASSET, credential: u.credential, taxKey: tax.pub, amlKey: aml.pub,
    inputs: [note],
    outputs: [{ amount: 12_000n, owner: bob, blinding: randomField() }, { amount: 38_000n, owner: u.owner, blinding: randomField() }],
  });
  const { returnValue } = await execute('spend', inputs);
  const [taxEph, taxCt, amlEph, amlCt] = returnValue;

  // Level 2 (tax): who pays and how much, NOT to whom.
  const taxPt = await aegis.decrypt(tax.secret, { x: BigInt(taxEph.x), y: BigInt(taxEph.y) }, taxCt);
  assert.deepEqual(taxPt, [u.owner, 12_000n, 0n, 0n]);

  // Level 3 (AML): full detail including recipient and credential.
  const amlPt = await aegis.decrypt(aml.secret, { x: BigInt(amlEph.x), y: BigInt(amlEph.y) }, amlCt);
  assert.equal(amlPt[0], u.owner);
  assert.equal(amlPt[1], bob);
  assert.equal(amlPt[2], 12_000n);
  assert.equal(amlPt[3], 38_000n);
  assert.equal(amlPt[6], await aegis.credentialHash(u.owner, u.credential));

  // The tax key does not open the AML ciphertext.
  const wrong = await aegis.decrypt(tax.secret, { x: BigInt(amlEph.x), y: BigInt(amlEph.y) }, amlCt);
  assert.notEqual(wrong[1], bob);
});

test('rejects: note not in tree / wrong owner', async () => {
  const u = await alice();
  const { tree, note } = await depositedNote(u);
  const thief = await alice();
  const { inputs } = await buildSpend(aegis, tree, {
    secret: thief.secret, asset: ASSET, credential: thief.credential, taxKey: tax.pub, amlKey: aml.pub,
    inputs: [note],
    outputs: [{ amount: 50_000n, owner: thief.owner, blinding: randomField() }, { amount: 0n, owner: thief.owner, blinding: randomField() }],
  });
  await expectFail(execute('spend', inputs), /note not in tree/);
});

test('rejects: value not conserved (money out of thin air)', async () => {
  const u = await alice();
  const { tree, note } = await depositedNote(u);
  const { inputs } = await buildSpend(aegis, tree, {
    secret: u.secret, asset: ASSET, credential: u.credential, taxKey: tax.pub, amlKey: aml.pub,
    inputs: [note],
    outputs: [{ amount: 60_000n, owner: u.owner, blinding: randomField() }, { amount: 0n, owner: u.owner, blinding: randomField() }],
  });
  await expectFail(execute('spend', inputs), /value not conserved/);
});

test('rejects: duplicate nullifier', async () => {
  const u = await alice();
  const { tree, note } = await depositedNote(u);
  const { inputs } = await buildSpend(aegis, tree, {
    secret: u.secret, asset: ASSET, credential: u.credential, taxKey: tax.pub, amlKey: aml.pub,
    inputs: [note],
    outputs: [{ amount: 50_000n, owner: u.owner, blinding: randomField() }, { amount: 0n, owner: u.owner, blinding: randomField() }],
  }, { duplicateNullifier: true });
  await expectFail(execute('spend', inputs), /bad nullifier|duplicate nullifier/);
});

test('rejects: credential from an unregistered issuer', async () => {
  const u = await alice(1, { issuerKey: '0x' + '99'.repeat(32) });
  const tree = await MerkleTree.create(aegis);
  const { inputs } = await buildSpend(aegis, tree, {
    secret: u.secret, asset: ASSET, credential: u.credential, taxKey: tax.pub, amlKey: aml.pub,
    inputs: [], publicIn: 100n,
    outputs: [{ amount: 100n, owner: u.owner, blinding: randomField() }, { amount: 0n, owner: u.owner, blinding: randomField() }],
  });
  await expectFail(execute('spend', inputs), /invalid KYC credential signature/);
});

test('rejects: expired credential', async () => {
  const u = await alice(1, { expiry: NOW - 1n });
  const tree = await MerkleTree.create(aegis);
  const { inputs } = await buildSpend(aegis, tree, {
    secret: u.secret, asset: ASSET, credential: u.credential, taxKey: tax.pub, amlKey: aml.pub,
    inputs: [], publicIn: 100n,
    outputs: [{ amount: 100n, owner: u.owner, blinding: randomField() }, { amount: 0n, owner: u.owner, blinding: randomField() }],
  });
  await expectFail(execute('spend', inputs), /KYC credential expired/);
});

test('rejects: jurisdiction not allowed', async () => {
  const u = await alice(1, { jurisdiction: 5 });
  const tree = await MerkleTree.create(aegis);
  const { inputs } = await buildSpend(aegis, tree, {
    secret: u.secret, asset: ASSET, credential: u.credential, taxKey: tax.pub, amlKey: aml.pub,
    inputs: [], publicIn: 100n,
    outputs: [{ amount: 100n, owner: u.owner, blinding: randomField() }, { amount: 0n, owner: u.owner, blinding: randomField() }],
  });
  await expectFail(execute('spend', inputs), /jurisdiction not allowed/);
});

test('rejects: amount above tier limit (tier 1 = 1,000 €)', async () => {
  const u = await alice(1);
  const bob = await aegis.ownerPubkey(randomField());
  const { tree, note } = await depositedNote(u, 200_000n);
  const { inputs } = await buildSpend(aegis, tree, {
    secret: u.secret, asset: ASSET, credential: u.credential, taxKey: tax.pub, amlKey: aml.pub,
    inputs: [note],
    outputs: [{ amount: 150_000n, owner: bob, blinding: randomField() }, { amount: 50_000n, owner: u.owner, blinding: randomField() }],
  });
  await expectFail(execute('spend', inputs), /amount above tier limit/);
});

test('rejects: auditor key not on the curve', async () => {
  const u = await alice();
  const tree = await MerkleTree.create(aegis);
  const { inputs } = await buildSpend(aegis, tree, {
    secret: u.secret, asset: ASSET, credential: u.credential, taxKey: { x: 1n, y: 1n }, amlKey: aml.pub,
    inputs: [], publicIn: 100n,
    outputs: [{ amount: 100n, owner: u.owner, blinding: randomField() }, { amount: 0n, owner: u.owner, blinding: randomField() }],
  });
  await expectFail(execute('spend', inputs), /auditor key not on curve/);
});

test('balance_proof: binding commitment (no fake balance)', async () => {
  const blinding = randomField();
  const commitment = await aegis.balanceCommitment(70_000n, blinding);
  await execute('balance_proof', { private_balance: '70000', blinding_factor: hex(blinding), threshold: '50000', commitment: hex(commitment) });
  await expectFail(
    execute('balance_proof', { private_balance: '90000', blinding_factor: hex(blinding), threshold: '50000', commitment: hex(commitment) }),
    /bad commitment/,
  );
  await expectFail(
    execute('balance_proof', { private_balance: '70000', blinding_factor: hex(blinding), threshold: '80000', commitment: hex(commitment) }),
    /balance below threshold/,
  );
});

test('compliance_proof: minimum tier and scope nullifier', async () => {
  const u = await alice(2);
  const issuer = Aegis.issuerPublicKey(ISSUER_KEY);
  const base = {
    issuer_pk_x: toNoirBytes(issuer.x), issuer_pk_y: toNoirBytes(issuer.y), now: NOW.toString(),
    allowed_jurisdictions: ALLOWED.toString(), scope: hex(777n), spending_secret: hex(u.secret),
    credential: { tier: '2', jurisdiction: String(IT), expiry: u.credential.expiry.toString(), signature: toNoirBytes(u.credential.signature) },
  };
  const { returnValue } = await execute('compliance_proof', { ...base, min_tier: '2' });
  assert.equal(BigInt(returnValue), await aegis.poseidon2([777n, u.secret]));
  await expectFail(execute('compliance_proof', { ...base, min_tier: '3' }), /tier too low/);
});

test('real UltraHonk proof for spend (generate + verify)', { timeout: 900_000 }, async (t) => {
  const u = await alice();
  const { tree, note } = await depositedNote(u);
  const { inputs } = await buildSpend(aegis, tree, {
    secret: u.secret, asset: ASSET, credential: u.credential, taxKey: tax.pub, amlKey: aml.pub,
    inputs: [note], publicOut: 10_000n,
    outputs: [{ amount: 0n, owner: u.owner, blinding: randomField() }, { amount: 40_000n, owner: u.owner, blinding: randomField() }],
  });
  const program = await loadCircuit('spend');
  const { witness } = await execute('spend', inputs);
  const api = await Barretenberg.new({ threads: 4 });
  const backend = new UltraHonkBackend(program.bytecode, api);
  const t0 = Date.now();
  let proof;
  try {
    proof = await backend.generateProof(witness, { verifierTarget: 'evm' });
  } catch (e) {
    // Proving needs Aztec's public CRS (downloaded from crs.aztec-labs.com on first use).
    if (/crs\.aztec-labs\.com|Could not establish connection/.test(String(e.message ?? e))) {
      await api.destroy();
      t.skip('CRS not downloadable from this network: run on a machine with internet access');
      return;
    }
    throw e;
  }
  console.log(`# spend proof generated in ${((Date.now() - t0) / 1000).toFixed(1)}s, ${proof.proof.length} bytes, ${proof.publicInputs.length} public inputs`);
  assert.equal(await backend.verifyProof(proof, { verifierTarget: 'evm' }), true);
  // Tampering with one public input (withdraw 1 cent more) → invalid proof.
  const tampered = { ...proof, publicInputs: proof.publicInputs.slice() };
  tampered.publicInputs[6] = hex(10_001n);
  assert.equal(await backend.verifyProof(tampered, { verifierTarget: 'evm' }).catch(() => false), false);
  // ext_data_hash (index 8) binds recipient/relayer/fee: a front-runner who changes the recipient
  // produces a different ext_data_hash and the SAME proof no longer verifies.
  for (const idx of [8, 9 /* now */, 1 /* nullifier */, 99 - 16 /* first disclosure output */]) {
    const t = { ...proof, publicInputs: proof.publicInputs.slice() };
    t.publicInputs[idx] = hex(BigInt(t.publicInputs[idx]) + 1n);
    assert.equal(await backend.verifyProof(t, { verifierTarget: 'evm' }).catch(() => false), false, `public input ${idx} not bound`);
  }
  await api.destroy();
});
