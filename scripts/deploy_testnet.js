// scripts/deploy_testnet.js — Deploy + verify all AEGIS Protocol contracts on a public testnet
const { ethers, run } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function verify(address, constructorArguments) {
  console.log(`Verifying ${address}...`);
  try {
    await run("verify:verify", { address, constructorArguments });
    console.log("Verified:", address);
  } catch (err) {
    if (err.message.toLowerCase().includes("already verified")) {
      console.log("Already verified:", address);
    } else {
      console.warn("Verification failed:", err.message);
    }
  }
}

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with account:", deployer.address);
  console.log(
    "Account balance:",
    ethers.formatEther(await ethers.provider.getBalance(deployer.address)),
    "ETH"
  );

  // 1. Deploy NoirVerifier in dev mode
  console.log("\n[1/5] Deploying NoirVerifier (dev mode)...");
  const NoirVerifier = await ethers.getContractFactory("NoirVerifier");
  const verifier = await NoirVerifier.deploy(true);
  await verifier.waitForDeployment();
  const verifierAddress = await verifier.getAddress();
  console.log("NoirVerifier deployed to:", verifierAddress);

  // 2. Deploy AegisEUR — temporarily use deployer as vault placeholder
  const vaultPlaceholder = deployer.address;
  console.log("\n[2/5] Deploying AegisEUR...");
  const AegisEUR = await ethers.getContractFactory("AegisEUR");
  const aegisEUR = await AegisEUR.deploy(vaultPlaceholder, deployer.address);
  await aegisEUR.waitForDeployment();
  const aegisEURAddress = await aegisEUR.getAddress();
  console.log("AegisEUR deployed to:", aegisEURAddress);

  // 3. Deploy AegisVault linked to AegisEUR
  console.log("\n[3/5] Deploying AegisVault...");
  const AegisVault = await ethers.getContractFactory("AegisVault");
  const vault = await AegisVault.deploy(aegisEURAddress, [deployer.address], 1);
  await vault.waitForDeployment();
  const vaultAddress = await vault.getAddress();
  console.log("AegisVault deployed to:", vaultAddress);

  // 4. Link AegisEUR to the real vault and verifier
  console.log("\n[4/5] Linking contracts...");
  const setVaultTx = await aegisEUR.setVault(vaultAddress);
  await setVaultTx.wait();
  console.log("AegisEUR.setVault() done:", vaultAddress);

  const setVerifierTx = await aegisEUR.setVerifier(verifierAddress);
  await setVerifierTx.wait();
  console.log("AegisEUR.setVerifier() done:", verifierAddress);

  // 5. Deploy AegisBundleVerifier
  console.log("\n[5/5] Deploying AegisBundleVerifier...");
  const AegisBundleVerifier = await ethers.getContractFactory("AegisBundleVerifier");
  const bundleVerifier = await AegisBundleVerifier.deploy();
  await bundleVerifier.waitForDeployment();
  const bundleVerifierAddress = await bundleVerifier.getAddress();
  console.log("AegisBundleVerifier deployed to:", bundleVerifierAddress);

  // Save addresses
  const addresses = {
    network: (await ethers.provider.getNetwork()).name,
    deployer: deployer.address,
    NoirVerifier: verifierAddress,
    AegisEUR: aegisEURAddress,
    AegisVault: vaultAddress,
    AegisBundleVerifier: bundleVerifierAddress,
    deployedAt: new Date().toISOString(),
  };

  console.log("\n=== Deployment Summary ===");
  console.log(JSON.stringify(addresses, null, 2));

  const outPath = path.join(__dirname, "..", "deployed_addresses.json");
  fs.writeFileSync(outPath, JSON.stringify(addresses, null, 2));
  console.log("\nAddresses saved to deployed_addresses.json");

  // Verify contracts on block explorer
  console.log("\nWaiting 30s before verification (block confirmations)...");
  await new Promise((r) => setTimeout(r, 30000));

  await verify(verifierAddress, [true]);
  await verify(aegisEURAddress, [vaultPlaceholder, deployer.address]);
  await verify(vaultAddress, [aegisEURAddress, [deployer.address], 1]);
  await verify(bundleVerifierAddress, []);

  console.log("\nAll contracts deployed and verified.");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
