const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");
const path = require("path");
const { pathToFileURL } = require("url");

// The ESM SDK and helpers are shared with the circuit tests (noir_circuits/test).
const importEsm = (p) => import(pathToFileURL(path.join(__dirname, "..", p)).href);

describe("Poseidon2.sol", function () {
  let harness, aegis;
  before(async function () {
    const { Aegis } = await importEsm("sdk/aegis.mjs");
    aegis = await Aegis.create();
    harness = await (await ethers.getContractFactory("Poseidon2Harness")).deploy();
  });
  after(async () => aegis.destroy());

  it("matches bb.js / Noir on random inputs", async function () {
    const { randomField } = await importEsm("sdk/aegis.mjs");
    for (const [a, b] of [[0n, 0n], [1n, 2n], [randomField(), randomField()], [randomField(), 0n]]) {
      expect(await harness.hash2(a, b)).to.equal(await aegis.hash2(a, b));
    }
  });

  it("rejects inputs outside the field", async function () {
    await expect(harness.hash2(2n ** 255n, 0n)).to.be.revertedWith("Poseidon2: input not in field");
  });
});

describe("ShieldedPool", function () {
  this.timeout(600_000);

  let sdk, helpers, aegis, tax, aml;
  let owner, alice, relayer, other;
  let token, verifier, pool;
  const TIER_LIMITS = [0n, 100_000_000n, 1_500_000_000n, 10n ** 14n]; // 6 decimals: 100 €, 1,500 €, ...
  const ALLOWED = 0b11n;
  const ISSUER_KEY = "0x" + "42".repeat(32);

  async function deploy(opts = {}) {
    token = await (await ethers.getContractFactory("MockERC20")).deploy();
    verifier = await (await ethers.getContractFactory("MockSpendVerifier")).deploy();
    pool = await (await ethers.getContractFactory("ShieldedPool")).deploy(
      await token.getAddress(),
      await verifier.getAddress(),
      owner.address,
      ALLOWED,
      TIER_LIMITS,
      { x: tax.pub.x, y: tax.pub.y },
      { x: aml.pub.x, y: aml.pub.y },
      opts.tvlCap ?? 10_000_000_000n,
      opts.maxDeposit ?? 1_000_000_000n,
    );
    const issuer = sdk.Aegis.issuerPublicKey(ISSUER_KEY);
    await pool.setIssuer(ethers.hexlify(issuer.x), ethers.hexlify(issuer.y), true);
    await token.mint(alice.address, 5_000_000_000n);
    await token.connect(alice).approve(await pool.getAddress(), ethers.MaxUint256);
  }

  // Builds the calldata with values that are consistent with a real execution of the circuit
  // (the mock verifier only skips the cryptographic check).
  async function realTx({ publicIn = 0n, publicOut = 0n, inputs = [], outputs, secret, tree, ext }) {
    const owner_ = await aegis.ownerPubkey(secret);
    const now = BigInt(await time.latest());
    const credential = await aegis.issueCredential(ISSUER_KEY, owner_, { tier: 2, jurisdiction: 0, expiry: now + 86_400n });
    const extData = {
      recipient: ext?.recipient ?? ethers.ZeroAddress,
      relayer: ext?.relayer ?? ethers.ZeroAddress,
      fee: ext?.fee ?? 0n,
      encryptedOutput0: "0x01",
      encryptedOutput1: "0x02",
    };
    const extHash = await pool.extDataHash(extData);
    const { inputs: w } = await helpers.buildSpend(aegis, tree, {
      secret, asset: BigInt(await token.getAddress()), credential, taxKey: tax.pub, amlKey: aml.pub,
      inputs, outputs, publicIn, publicOut, extDataHash: extHash,
    }, { now, allowed: ALLOWED });
    w.tier_limits = TIER_LIMITS.map(String);
    const { returnValue } = await helpers.execute("spend", w);
    const [taxEph, taxCt, amlEph, amlCt] = returnValue;
    const issuer = sdk.Aegis.issuerPublicKey(ISSUER_KEY);
    const proof = {
      proof: "0x",
      root: w.root,
      nullifiers: w.nullifiers,
      outCommitments: w.out_commitments,
      publicIn, publicOut,
      timestamp: now,
      issuer: { x: ethers.hexlify(issuer.x), y: ethers.hexlify(issuer.y) },
      taxEph: { x: taxEph.x, y: taxEph.y }, taxCt,
      amlEph: { x: amlEph.x, y: amlEph.y }, amlCt,
    };
    return { proof, extData, witness: w, returnValue };
  }

  // Flattening of the circuit's public inputs (same order as the Noir ABI), independent of the contract.
  function flattenPublic(w, ret) {
    const f = (x) => ethers.toBeHex(BigInt(x), 32);
    const [te, tc, ae, ac] = ret;
    return [
      w.root, ...w.nullifiers, ...w.out_commitments, w.public_in, w.public_out, w.asset, w.ext_data_hash,
      w.now, w.allowed_jurisdictions, ...w.tier_limits, ...w.issuer_pk_x, ...w.issuer_pk_y,
      w.tax_key.x, w.tax_key.y, w.aml_key.x, w.aml_key.y, te.x, te.y, ...tc, ae.x, ae.y, ...ac,
    ].map(f);
  }

  before(async function () {
    [owner, alice, relayer, other] = await ethers.getSigners();
    sdk = await importEsm("sdk/aegis.mjs");
    helpers = await importEsm("noir_circuits/test/helpers.mjs");
    aegis = await sdk.Aegis.create();
    tax = await aegis.auditorKeypair();
    aml = await aegis.auditorKeypair();
  });
  after(async () => aegis.destroy());
  beforeEach(async () => deploy());

  it("empty tree has the same root as the SDK", async function () {
    const tree = await sdk.MerkleTree.create(aegis);
    expect(await pool.getLastRoot()).to.equal(await tree.root());
  });

  it("deposit → private transfer → withdrawal, with the tree in sync with the SDK", async function () {
    const secret = sdk.randomField();
    const me = await aegis.ownerPubkey(secret);
    const tree = await sdk.MerkleTree.create(aegis);

    // 1. Deposit of 500 EURC
    const b0 = sdk.randomField();
    const dep = await realTx({
      secret, tree, publicIn: 500_000_000n,
      outputs: [{ amount: 500_000_000n, owner: me, blinding: b0 }, { amount: 0n, owner: me, blinding: sdk.randomField() }],
    });
    await expect(pool.connect(alice).transact(dep.proof, dep.extData)).to.emit(pool, "Disclosure");
    expect(await token.balanceOf(await pool.getAddress())).to.equal(500_000_000n);
    tree.insert(BigInt(dep.witness.out_commitments[0]));
    tree.insert(BigInt(dep.witness.out_commitments[1]));
    expect(await pool.getLastRoot()).to.equal(await tree.root());

    // The contract passes the verifier EXACTLY the circuit's public inputs.
    expect(await verifier.lastPublicInputs()).to.deep.equal(flattenPublic(dep.witness, dep.returnValue));

    // 2. Withdrawal of 120 EURC to `other`, 1 EURC fee to the relayer, from any wallet.
    const wd = await realTx({
      secret, tree, publicOut: 120_000_000n,
      inputs: [{ amount: 500_000_000n, blinding: b0, leafIndex: 0 }],
      outputs: [{ amount: 0n, owner: me, blinding: sdk.randomField() }, { amount: 380_000_000n, owner: me, blinding: sdk.randomField() }],
      ext: { recipient: other.address, relayer: relayer.address, fee: 1_000_000n },
    });
    await pool.connect(relayer).transact(wd.proof, wd.extData);
    expect(await token.balanceOf(other.address)).to.equal(119_000_000n);
    expect(await token.balanceOf(relayer.address)).to.equal(1_000_000n);
    expect(await pool.totalDeposited()).to.equal(380_000_000n);
    tree.insert(BigInt(wd.witness.out_commitments[0]));
    tree.insert(BigInt(wd.witness.out_commitments[1]));
    expect(await pool.getLastRoot()).to.equal(await tree.root());

    // 3. Replay of the same withdrawal → rejected (nullifiers already spent).
    await expect(pool.connect(relayer).transact(wd.proof, wd.extData)).to.be.revertedWith("note already spent");

    // 4. The AML committee decrypts the detail of the withdrawal from the event.
    const amlPt = await aegis.decrypt(aml.secret, { x: BigInt(wd.proof.amlEph.x), y: BigInt(wd.proof.amlEph.y) }, wd.proof.amlCt);
    expect(amlPt[0]).to.equal(me);
    expect(amlPt[5]).to.equal(120_000_000n);
  });

  it("rejects invalid proof, unknown root, unregistered issuer, stale proof", async function () {
    const secret = sdk.randomField();
    const me = await aegis.ownerPubkey(secret);
    const tree = await sdk.MerkleTree.create(aegis);
    const outputs = [{ amount: 1_000_000n, owner: me, blinding: sdk.randomField() }, { amount: 0n, owner: me, blinding: sdk.randomField() }];
    const tx = await realTx({ secret, tree, publicIn: 1_000_000n, outputs });

    await verifier.setResult(false);
    await expect(pool.connect(alice).transact(tx.proof, tx.extData)).to.be.revertedWith("invalid proof");
    await verifier.setResult(true);

    await expect(pool.connect(alice).transact({ ...tx.proof, root: 123n }, tx.extData)).to.be.revertedWith("unknown root");

    const bad = { x: ethers.hexlify(ethers.randomBytes(32)), y: ethers.hexlify(ethers.randomBytes(32)) };
    await expect(pool.connect(alice).transact({ ...tx.proof, issuer: bad }, tx.extData)).to.be.revertedWith("issuer not allowed");

    await time.increase(3601);
    await expect(pool.connect(alice).transact(tx.proof, tx.extData)).to.be.revertedWith("stale proof");
  });

  it("controlled launch: per-tx deposit limit and TVL cap", async function () {
    await deploy({ tvlCap: 1_500_000_000n, maxDeposit: 1_000_000_000n });
    const secret = sdk.randomField();
    const me = await aegis.ownerPubkey(secret);
    const tree = await sdk.MerkleTree.create(aegis);
    const mk = (amt) => realTx({ secret, tree, publicIn: amt, outputs: [{ amount: amt, owner: me, blinding: sdk.randomField() }, { amount: 0n, owner: me, blinding: sdk.randomField() }] });

    const big = await mk(1_000_000_001n);
    await expect(pool.connect(alice).transact(big.proof, big.extData)).to.be.revertedWith("deposit above per-tx limit");

    const a = await mk(1_000_000_000n);
    await pool.connect(alice).transact(a.proof, a.extData);
    const b = await mk(600_000_000n);
    await expect(pool.connect(alice).transact(b.proof, b.extData)).to.be.revertedWith("TVL cap reached");
  });

  it("changing ext data (e.g. the recipient) invalidates the public inputs", async function () {
    const secret = sdk.randomField();
    const me = await aegis.ownerPubkey(secret);
    const tree = await sdk.MerkleTree.create(aegis);
    const tx = await realTx({ secret, tree, publicIn: 1_000_000n, outputs: [{ amount: 1_000_000n, owner: me, blinding: sdk.randomField() }, { amount: 0n, owner: me, blinding: sdk.randomField() }] });
    const tampered = { ...tx.extData, recipient: other.address };
    await pool.connect(alice).transact(tx.proof, tampered); // the mock accepts...
    const pi = await verifier.lastPublicInputs();
    // ...but the ext_data_hash passed to the verifier is no longer the one the proof was made for.
    expect(pi[8]).to.not.equal(ethers.toBeHex(BigInt(tx.witness.ext_data_hash), 32));
  });

  it("governance: only the owner, auditor keys must be on the curve", async function () {
    await expect(pool.connect(other).setLimits(1, 1)).to.be.revertedWithCustomError(pool, "OwnableUnauthorizedAccount");
    await expect(pool.setAuditorKeys({ x: 1, y: 1 }, { x: aml.pub.x, y: aml.pub.y })).to.be.revertedWith("auditor key not on curve");
    await pool.pause();
    await expect(pool.connect(alice).transact(
      { proof: "0x", root: 0, nullifiers: [0, 0], outCommitments: [0, 0], publicIn: 0, publicOut: 0, timestamp: 0, issuer: { x: ethers.ZeroHash, y: ethers.ZeroHash }, taxEph: { x: 0, y: 0 }, taxCt: [0, 0, 0, 0], amlEph: { x: 0, y: 0 }, amlCt: [0, 0, 0, 0, 0, 0, 0, 0] },
      { recipient: ethers.ZeroAddress, relayer: ethers.ZeroAddress, fee: 0, encryptedOutput0: "0x", encryptedOutput1: "0x" },
    )).to.be.revertedWithCustomError(pool, "EnforcedPause");
  });
});
