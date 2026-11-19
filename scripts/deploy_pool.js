// scripts/deploy_pool.js — deploy the confidential pool (ShieldedPool) on an existing stablecoin.
//
// Prerequisites:
//   1. npm run build:circuits          → generates contracts/verifiers/SpendVerifier.sol
//   2. .env with:
//        POOL_TOKEN_ADDRESS     EURC/EURe token on the target chain
//        POOL_OWNER             multisig (Safe) behind a timelock — NEVER an EOA in production
//        KYC_ISSUER_X, KYC_ISSUER_Y  Schnorr-Grumpkin public key of the KYC issuer (GET /pool/issuer)
//        TAX_KEY_X, TAX_KEY_Y   threshold key of the tax-disclosure committee (Grumpkin)
//        AML_KEY_X, AML_KEY_Y   threshold key of the AML-disclosure committee (Grumpkin)
//      optional: ALLOWED_JURISDICTIONS (bitmask, default 1 = IT), TIER_LIMITS (4 values, token units),
//                TVL_CAP, MAX_DEPOSIT_PER_TX (token units, default 50,000 and 1,000 EUR at 6 decimals)
//
//   npx hardhat run scripts/deploy_pool.js --network amoy
import { network } from "hardhat";
import { deployHonkVerifier } from "./lib/deploy_verifier.js";

const { ethers } = await network.getOrCreate();

const need = (k) => {
  const v = process.env[k];
  if (!v) throw new Error(`Missing env ${k}`);
  return v;
};

async function main() {
  const [deployer] = await ethers.getSigners();
  const decimals = 6n;
  const eur = (n) => BigInt(n) * 10n ** decimals;

  const verifier = await deployHonkVerifier(ethers, "SpendVerifier");
  console.log("SpendVerifier:", await verifier.getAddress());

  const tierLimits = process.env.TIER_LIMITS
    ? process.env.TIER_LIMITS.split(",").map((x) => BigInt(x.trim()))
    : [0n, eur(1_000), eur(15_000), eur(1_000_000)];
  const owner = need("POOL_OWNER");
  const Pool = await ethers.getContractFactory("ShieldedPool");
  const pool = await Pool.deploy(
    need("POOL_TOKEN_ADDRESS"),
    await verifier.getAddress(),
    deployer.address, // temporary: ownership is transferred to the multisig below
    BigInt(process.env.ALLOWED_JURISDICTIONS ?? "1"),
    tierLimits,
    { x: need("TAX_KEY_X"), y: need("TAX_KEY_Y") },
    { x: need("AML_KEY_X"), y: need("AML_KEY_Y") },
    BigInt(process.env.TVL_CAP ?? eur(50_000)),
    BigInt(process.env.MAX_DEPOSIT_PER_TX ?? eur(1_000)),
  );
  await pool.waitForDeployment();
  console.log("ShieldedPool:", await pool.getAddress());

  await (await pool.setIssuer(BigInt(need("KYC_ISSUER_X")), BigInt(need("KYC_ISSUER_Y")), true)).wait();
  console.log("KYC issuer registered");

  // Ownable2Step: the multisig must call acceptOwnership().
  await (await pool.transferOwnership(owner)).wait();
  console.log(`Ownership proposed to ${owner}: the multisig must call acceptOwnership()`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
