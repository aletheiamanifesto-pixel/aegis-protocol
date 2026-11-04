const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("NoirVerifier", function () {
  let NoirVerifier;
  let verifier;
  let owner, alice;

  beforeEach(async function () {
    [owner, alice] = await ethers.getSigners();
    NoirVerifier = await ethers.getContractFactory("NoirVerifier");
    verifier = await NoirVerifier.deploy(true); // deploy in dev mode
  });

  // ─── Deployment ───────────────────────────────────────────────────────────────

  describe("Deployment", function () {
    it("sets owner to deployer", async function () {
      expect(await verifier.owner()).to.equal(owner.address);
    });

    it("dev mode is set correctly at deployment", async function () {
      expect(await verifier.devMode()).to.equal(true);

      const prodVerifier = await NoirVerifier.deploy(false);
      expect(await prodVerifier.devMode()).to.equal(false);
    });
  });

  // ─── Dev mode ─────────────────────────────────────────────────────────────────

  describe("Dev mode — verifyProof", function () {
    it("returns true for any non-empty proof in dev mode", async function () {
      const proof = ethers.toUtf8Bytes("any-proof-data");
      const publicInputs = [ethers.keccak256(ethers.toUtf8Bytes("input"))];
      expect(await verifier.verifyProof.staticCall(proof, publicInputs)).to.equal(true);
    });

    it("returns false for empty proof in dev mode", async function () {
      const emptyProof = new Uint8Array(0);
      const publicInputs = [ethers.keccak256(ethers.toUtf8Bytes("input"))];
      expect(await verifier.verifyProof.staticCall(emptyProof, publicInputs)).to.equal(false);
    });

    it("verifyProofView returns true for non-empty proof in dev mode", async function () {
      const proof = ethers.toUtf8Bytes("any-proof");
      const publicInputs = [ethers.keccak256(ethers.toUtf8Bytes("input"))];
      expect(await verifier.verifyProofView(proof, publicInputs)).to.equal(true);
    });

    it("verifyProofView returns false for empty proof in dev mode", async function () {
      const emptyProof = new Uint8Array(0);
      const publicInputs = [ethers.keccak256(ethers.toUtf8Bytes("input"))];
      expect(await verifier.verifyProofView(emptyProof, publicInputs)).to.equal(false);
    });
  });

  // ─── Non-dev mode: delegates to the real verifier ────────────────────────────

  describe("Non-dev mode — delegates to the bb backend", function () {
    let prodVerifier, backend;

    beforeEach(async function () {
      prodVerifier = await NoirVerifier.deploy(false);
      backend = await (await ethers.getContractFactory("MockHonkVerifier")).deploy();
    });

    it("without a backend it rejects everything", async function () {
      const publicInputs = [ethers.keccak256(ethers.toUtf8Bytes("input"))];
      expect(await prodVerifier.verifyProof.staticCall(ethers.randomBytes(64), publicInputs)).to.equal(false);
    });

    it("the old keccak trick (proof = keccak256(publicInputs)) no longer works", async function () {
      const publicInputs = [ethers.keccak256(ethers.toUtf8Bytes("sender")), ethers.keccak256(ethers.toUtf8Bytes("amount"))];
      const forged = ethers.concat([ethers.keccak256(ethers.concat(publicInputs)), ethers.randomBytes(32)]);
      expect(await prodVerifier.verifyProof.staticCall(forged, publicInputs)).to.equal(false);
    });

    it("with a backend it returns the backend's result", async function () {
      await prodVerifier.setBackend(await backend.getAddress());
      const publicInputs = [ethers.keccak256(ethers.toUtf8Bytes("input"))];
      expect(await prodVerifier.verifyProofView(ethers.randomBytes(64), publicInputs)).to.equal(true);
      await backend.setResult(false);
      expect(await prodVerifier.verifyProofView(ethers.randomBytes(64), publicInputs)).to.equal(false);
    });

    it("only the owner sets the backend", async function () {
      const [, stranger] = await ethers.getSigners();
      await expect(prodVerifier.connect(stranger).setBackend(await backend.getAddress())).to.be.revertedWith("Not owner");
    });
  });

  // ─── State ────────────────────────────────────────────────────────────────────

  describe("State — verifiedProofs mapping", function () {
    it("verifiedProofs is updated after successful verification", async function () {
      const proof = ethers.toUtf8Bytes("valid-proof");
      const publicInputs = [ethers.keccak256(ethers.toUtf8Bytes("input"))];
      const proofHash = ethers.keccak256(
        ethers.concat([proof, ...publicInputs])
      );

      expect(await verifier.isProofVerified(proofHash)).to.equal(false);
      await verifier.verifyProof(proof, publicInputs);
      expect(await verifier.isProofVerified(proofHash)).to.equal(true);
    });

    it("verifiedProofs is NOT updated for failed verification", async function () {
      // In non-dev mode, an empty-public-inputs proof fails
      const prodVerifier = await NoirVerifier.deploy(false);
      const proof = ethers.randomBytes(64);
      const publicInputs = []; // causes failure

      const proofHash = ethers.keccak256(ethers.concat([proof]));
      await prodVerifier.verifyProof(proof, publicInputs);
      expect(await prodVerifier.isProofVerified(proofHash)).to.equal(false);
    });

    it("emits ProofVerified event with correct hash and result", async function () {
      const proof = ethers.toUtf8Bytes("event-test-proof");
      const publicInputs = [ethers.keccak256(ethers.toUtf8Bytes("input"))];
      const proofHash = ethers.keccak256(
        ethers.concat([proof, ...publicInputs])
      );

      await expect(verifier.verifyProof(proof, publicInputs))
        .to.emit(verifier, "ProofVerified")
        .withArgs(proofHash, true);
    });

    it("emits ProofVerified(false) when proof fails", async function () {
      const emptyProof = new Uint8Array(0);
      const publicInputs = [ethers.keccak256(ethers.toUtf8Bytes("input"))];
      const proofHash = ethers.keccak256(
        ethers.concat([emptyProof, ...publicInputs])
      );

      await expect(verifier.verifyProof(emptyProof, publicInputs))
        .to.emit(verifier, "ProofVerified")
        .withArgs(proofHash, false);
    });
  });

  // ─── Admin ────────────────────────────────────────────────────────────────────

  describe("Admin — setDevMode", function () {
    it("owner can toggle dev mode off", async function () {
      await verifier.connect(owner).setDevMode(false);
      expect(await verifier.devMode()).to.equal(false);
    });

    it("owner can toggle dev mode on again", async function () {
      await verifier.connect(owner).setDevMode(false);
      await verifier.connect(owner).setDevMode(true);
      expect(await verifier.devMode()).to.equal(true);
    });

    it("setDevMode emits DevModeToggled event", async function () {
      await expect(verifier.connect(owner).setDevMode(false))
        .to.emit(verifier, "DevModeToggled")
        .withArgs(false);
    });

    it("non-owner cannot call setDevMode", async function () {
      await expect(
        verifier.connect(alice).setDevMode(false)
      ).to.be.revertedWith("Not owner");
    });
  });
});
