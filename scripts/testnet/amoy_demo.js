// scripts/testnet/amoy_demo.js — deploy the confidential pool on a TESTNET and run a full round with
// real UltraHonk proofs verified on-chain:
//   deposit 500 → private transfer 250 Mario→Lucia → Lucia withdraws 100 → L2/L3 disclosure decrypted.
//
//   DEPLOYER_PRIVATE_KEY=0x… RPC_URL=https://polygon-amoy-bor-rpc.publicnode.com \
//     npx hardhat run scripts/testnet/amoy_demo.js --network amoy
//
// TESTNET ONLY:
// - the token is MockERC20 ("Mock EURC"), mintable by anyone: no real money;
// - the pool owner is the deployer EOA, not a multisig;
// - the tax/AML keys are single keys, not the t-of-n committee.
// Test secrets (KYC issuer, tax/AML keys, Mario's and Lucia's spending secrets) live in
// $AEGIS_TESTNET_DIR/secrets.json (default ~/.aegis-testnet), never in the repo.
// Public addresses and tx hashes are written to deployments/<network>.json.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { network } from "hardhat";
import { deployHonkVerifier } from "../lib/deploy_verifier.js";

const { ethers, networkName } = await network.getOrCreate();
const root = path.join(import.meta.dirname, "..", "..");
const importEsm = (p) => import(pathToFileURL(path.join(root, p)).href);
const sdk = await importEsm("sdk/aegis.mjs");
const helpers = await importEsm("noir_circuits/test/helpers.mjs");
const { Barretenberg, UltraHonkBackend } = await import("@aztec/bb.js");

const EUR = (n) => BigInt(Math.round(n * 1e6)); // 6 decimals
const TIER_LIMITS = [0n, EUR(1_000), EUR(15_000), EUR(1_000_000)];
const JURISDICTIONS = 0b11n; // IT + DE
const fmt = (v) => `${(Number(v) / 1e6).toFixed(2)} mEURC`;

// ---------------------------------------------------------------- state
const secretsDir = process.env.AEGIS_TESTNET_DIR || path.join(os.homedir(), ".aegis-testnet");
const secretsFile = path.join(secretsDir, "secrets.json");
const deployFile = path.join(root, "deployments", `${networkName}.json`);
const readJson = (f, d) => (fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, "utf8")) : d);
const big = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, BigInt(v)]));
fs.mkdirSync(secretsDir, { recursive: true, mode: 0o700 });
let secrets = readJson(secretsFile, null);
if (!secrets) {
  const r = () => sdk.randomField().toString();
  secrets = { issuer: r(), tax: r(), aml: r(), mario: r(), lucia: r() };
  fs.writeFileSync(secretsFile, JSON.stringify(secrets, null, 2), { mode: 0o600 });
}
secrets = big(secrets);
const dep = readJson(deployFile, { network: networkName, txs: {} });
const save = () => {
  fs.mkdirSync(path.dirname(deployFile), { recursive: true });
  fs.writeFileSync(deployFile, JSON.stringify(dep, null, 2) + "\n");
};

const [deployer] = await ethers.getSigners();
const chainId = (await ethers.provider.getNetwork()).chainId;
dep.chainId = Number(chainId);
console.log(`network ${networkName} (chainId ${chainId}), deployer ${deployer.address}`);
console.log(`balance ${ethers.formatEther(await ethers.provider.getBalance(deployer.address))} POL\n`);

const aegis = await sdk.Aegis.create();
const tax = await aegis.auditorKeypair(secrets.tax);
const aml = await aegis.auditorKeypair(secrets.aml);
const issuer = sdk.Aegis.issuerPublicKey(secrets.issuer);

const hasCode = async (a) => a && (await ethers.provider.getCode(a)) !== "0x";
const waitTx = async (label, txp) => {
  const tx = await txp;
  const r = await tx.wait();
  dep.txs[label] = { hash: tx.hash, gasUsed: r.gasUsed.toString(), block: r.blockNumber };
  save();
  console.log(`  ${label}: ${tx.hash} (gas ${r.gasUsed})`);
  return r;
};

// ---------------------------------------------------------------- deploy (idempotent)
if (!(await hasCode(dep.token))) {
  const t = await (await ethers.getContractFactory("MockERC20")).deploy();
  await t.waitForDeployment();
  dep.token = await t.getAddress();
  save();
}
console.log("Mock EURC (test token):", dep.token);
if (!(await hasCode(dep.spendVerifier))) {
  dep.spendVerifier = await (await deployHonkVerifier(ethers, "SpendVerifier")).getAddress();
  save();
}
console.log("SpendVerifier:", dep.spendVerifier);
if (!(await hasCode(dep.pool))) {
  const p = await (await ethers.getContractFactory("ShieldedPool")).deploy(
    dep.token, dep.spendVerifier, deployer.address, JURISDICTIONS, TIER_LIMITS,
    { x: tax.pub.x, y: tax.pub.y }, { x: aml.pub.x, y: aml.pub.y }, EUR(50_000), EUR(1_000),
  );
  const r = await p.deploymentTransaction().wait();
  dep.pool = await p.getAddress();
  dep.poolDeployBlock = r.blockNumber;
  save();
}
console.log("ShieldedPool:", dep.pool, "\n");
const token = await ethers.getContractAt("MockERC20", dep.token);
const pool = await ethers.getContractAt("ShieldedPool", dep.pool);
if (!(await pool.issuerAllowed(ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [issuer.x, issuer.y]))))) {
  await waitTx("setIssuer", pool.setIssuer(issuer.x, issuer.y, true));
}

// ---------------------------------------------------------------- tree in sync with the chain
const tree = await sdk.MerkleTree.create(aegis);
const logs = await pool.queryFilter(pool.filters.NewCommitment(), dep.poolDeployBlock ?? 0);
logs.sort((a, b) => Number(a.args.index) - Number(b.args.index));
for (const l of logs) tree.insert(BigInt(l.args.commitment));
const nextIndex = () => logs.length + inserted;
let inserted = 0;

// ---------------------------------------------------------------- proving
const program = await helpers.loadCircuit("spend");
const api = await Barretenberg.new({ threads: os.cpus().length });
const backend = new UltraHonkBackend(program.bytecode, api);
const asset = BigInt(dep.token);
const users = {
  mario: { secret: secrets.mario, owner: await aegis.ownerPubkey(secrets.mario), personTag: 1001n },
  lucia: { secret: secrets.lucia, owner: await aegis.ownerPubkey(secrets.lucia), personTag: 1002n },
};
// Rate slots: one per tx per person per day (max 16). Kept per network next to the secrets.
const slotFile = path.join(secretsDir, `slots-${networkName}.json`);
const slots = readJson(slotFile, {});
const nextSlot = (who, now) => {
  const k = `${who}:${now / 86_400n}`;
  slots[k] = (slots[k] ?? -1) + 1;
  fs.writeFileSync(slotFile, JSON.stringify(slots), { mode: 0o600 });
  return slots[k];
};

async function prove(who, { inputs = [], outputs, publicIn = 0n, publicOut = 0n, recipient = ethers.ZeroAddress }) {
  const u = users[who];
  const now = BigInt((await ethers.provider.getBlock("latest")).timestamp);
  const credential = await aegis.issueCredential(secrets.issuer, u.owner,
    { tier: 2, jurisdiction: 0, expiry: now + 86_400n, personTag: u.personTag });
  const extData = { recipient, relayer: ethers.ZeroAddress, fee: 0n, encryptedOutput0: "0x01", encryptedOutput1: "0x02" };
  const { inputs: w } = await helpers.buildSpend(aegis, tree, {
    secret: u.secret, asset, credential, taxKey: tax.pub, amlKey: aml.pub, inputs, outputs, publicIn, publicOut,
    extDataHash: await pool.extDataHash(extData), rateSlot: nextSlot(who, now),
  }, { now, allowed: JURISDICTIONS, issuerKey: secrets.issuer });
  w.tier_limits = TIER_LIMITS.map(String);
  const t0 = Date.now();
  const { witness, returnValue } = await helpers.execute("spend", w);
  const proof = await backend.generateProof(witness, { verifierTarget: "evm" });
  console.log(`  proof generated in ${((Date.now() - t0) / 1000).toFixed(2)} s (${proof.proof.length} bytes)`);
  const [te, tc, ae, ac, rn] = returnValue;
  return {
    w, extData, disclosure: { te, tc, ae, ac },
    p: { proof: ethers.hexlify(proof.proof), root: w.root, nullifiers: w.nullifiers, outCommitments: w.out_commitments,
      publicIn, publicOut, timestamp: now, issuer: { x: issuer.x, y: issuer.y },
      taxEph: { x: te.x, y: te.y }, taxCt: tc, amlEph: { x: ae.x, y: ae.y }, amlCt: ac, rateNullifier: rn },
  };
}
async function submit(label, tx) {
  const r = await waitTx(label, pool.transact(tx.p, tx.extData));
  for (const c of tx.w.out_commitments) { tree.insert(BigInt(c)); inserted++; }
  return r;
}
const note = (amount, owner) => ({ amount, owner, blinding: sdk.randomField() });

// ---------------------------------------------------------------- demo round
console.log("1. Mario deposits 500 (public amount, private owner)");
if ((await token.balanceOf(deployer.address)) < EUR(500)) await waitTx("mint", token.mint(deployer.address, EUR(1_000)));
if ((await token.allowance(deployer.address, dep.pool)) < EUR(500)) await waitTx("approve", token.approve(dep.pool, ethers.MaxUint256));
const m500 = note(EUR(500), users.mario.owner);
const depTx = await prove("mario", { publicIn: EUR(500), outputs: [m500, note(0n, users.mario.owner)] });
const marioIdx = nextIndex();
await submit("deposit", depTx);

console.log("2. Mario pays Lucia 250 privately (no amount, no addresses on-chain)");
const l250 = note(EUR(250), users.lucia.owner);
const xfer = await prove("mario", {
  inputs: [{ amount: m500.amount, blinding: m500.blinding, leafIndex: marioIdx }],
  outputs: [l250, note(EUR(250), users.mario.owner)],
});
const luciaIdx = nextIndex();
await submit("privateTransfer", xfer);

console.log("3. Lucia withdraws 100 to a fresh address");
const payout = ethers.Wallet.createRandom().address;
const wd = await prove("lucia", {
  inputs: [{ amount: l250.amount, blinding: l250.blinding, leafIndex: luciaIdx }],
  outputs: [note(0n, users.lucia.owner), note(EUR(150), users.lucia.owner)],
  publicOut: EUR(100), recipient: payout,
});
await submit("withdrawal", wd);
console.log(`  ${payout} received ${fmt(await token.balanceOf(payout))}`);

console.log("\n4. Graduated disclosure of the private transfer (step 2)");
const pt = (e) => ({ x: BigInt(e.x), y: BigInt(e.y) });
const l2 = await aegis.decrypt(tax.secret, pt(xfer.disclosure.te), xfer.disclosure.tc);
const l3 = await aegis.decrypt(aml.secret, pt(xfer.disclosure.ae), xfer.disclosure.ac);
const name = (o) => (o === users.mario.owner ? "Mario" : o === users.lucia.owner ? "Lucia" : `0x${o.toString(16)}`);
console.log(`  L2 tax key  → payer ${name(l2[0])}, amount ${fmt(l2[1])}, counterparty: not included`);
console.log(`  L3 AML key  → ${name(l3[0])} → ${name(l3[1])}, ${fmt(l3[2])}, change ${fmt(l3[3])}`);
dep.demo = { at: new Date().toISOString(), payout, disclosure: { L2: { payer: name(l2[0]), amount: fmt(l2[1]) },
  L3: { from: name(l3[0]), to: name(l3[1]), amount: fmt(l3[2]) } } };
save();

await api.destroy();
await aegis.destroy();
console.log(`\nSaved to ${path.relative(root, deployFile)}`);
