import { expect } from "chai";
import { network } from "hardhat";

const { ethers, networkHelpers } = await network.create();

describe("AegisEUR", function () {
  let AegisEUR, NoirVerifier;
  let aegisEUR, noirVerifier;
  let owner, vault, regulator, minter, alice, bob;

  beforeEach(async function () {
    [owner, vault, regulator, minter, alice, bob] = await ethers.getSigners();

    NoirVerifier = await ethers.getContractFactory("NoirVerifier");
    noirVerifier = await NoirVerifier.deploy(true); // dev mode

    AegisEUR = await ethers.getContractFactory("AegisEUR");
    aegisEUR = await AegisEUR.deploy(vault.address, regulator.address);
  });

  // ─── Deployment ───────────────────────────────────────────────────────────────

  describe("Deployment", function () {
    it("has correct name and symbol and decimals", async function () {
      expect(await aegisEUR.name()).to.equal("AEGIS Euro");
      expect(await aegisEUR.symbol()).to.equal("AEGIS-EUR");
      expect(await aegisEUR.decimals()).to.equal(6);
    });

    it("sets deployer as owner", async function () {
      expect(await aegisEUR.owner()).to.equal(owner.address);
    });

    it("sets vault correctly and makes vault a minter", async function () {
      expect(await aegisEUR.vault()).to.equal(vault.address);
      expect(await aegisEUR.minters(vault.address)).to.equal(true);
    });

    it("sets regulator as provided and also makes owner a regulator", async function () {
      expect(await aegisEUR.regulators(regulator.address)).to.equal(true);
      expect(await aegisEUR.regulators(owner.address)).to.equal(true);
    });

    it("starts with zero total supply", async function () {
      expect(await aegisEUR.totalSupply()).to.equal(0n);
    });

    it("reverts when vault is zero address", async function () {
      await expect(
        AegisEUR.deploy(ethers.ZeroAddress, regulator.address)
      ).to.be.revertedWith("Vault zero");
    });

    it("reverts when regulator is zero address", async function () {
      await expect(
        AegisEUR.deploy(vault.address, ethers.ZeroAddress)
      ).to.be.revertedWith("Regulator zero");
    });
  });

  // ─── Minting ──────────────────────────────────────────────────────────────────

  describe("Minting", function () {
    it("vault can mint tokens", async function () {
      await aegisEUR.connect(vault).mint(alice.address, 1000n);
      expect(await aegisEUR.balanceOf(alice.address)).to.equal(1000n);
      expect(await aegisEUR.totalSupply()).to.equal(1000n);
    });

    it("authorised minter can mint tokens", async function () {
      await aegisEUR.connect(owner).addMinter(minter.address);
      await aegisEUR.connect(minter).mint(alice.address, 500n);
      expect(await aegisEUR.balanceOf(alice.address)).to.equal(500n);
    });

    it("non-minter cannot mint", async function () {
      await expect(
        aegisEUR.connect(alice).mint(alice.address, 100n)
      ).to.be.revertedWith("Not minter");
    });

    it("cannot mint to zero address", async function () {
      await expect(
        aegisEUR.connect(vault).mint(ethers.ZeroAddress, 100n)
      ).to.be.revertedWith("Mint to zero");
    });

    it("cannot mint zero amount", async function () {
      await expect(
        aegisEUR.connect(vault).mint(alice.address, 0n)
      ).to.be.revertedWith("Zero amount");
    });

    it("emits Transfer and Mint events on mint", async function () {
      await expect(aegisEUR.connect(vault).mint(alice.address, 1000n))
        .to.emit(aegisEUR, "Transfer")
        .withArgs(ethers.ZeroAddress, alice.address, 1000n)
        .and.to.emit(aegisEUR, "Mint")
        .withArgs(alice.address, 1000n, vault.address);
    });

    it("cannot mint to frozen account", async function () {
      await aegisEUR.connect(regulator).freeze(alice.address);
      await expect(
        aegisEUR.connect(vault).mint(alice.address, 100n)
      ).to.be.revertedWith("Account frozen");
    });
  });

  // ─── Burning ──────────────────────────────────────────────────────────────────

  describe("Burning", function () {
    beforeEach(async function () {
      await aegisEUR.connect(vault).mint(alice.address, 2000n);
      await aegisEUR.connect(vault).mint(vault.address, 2000n); // tokens in escrow at the vault
    });

    it("minter burns its own balance (escrow)", async function () {
      await aegisEUR.connect(vault).burn(vault.address, 500n);
      expect(await aegisEUR.balanceOf(vault.address)).to.equal(1500n);
      expect(await aegisEUR.totalSupply()).to.equal(3500n);
    });

    it("minter CANNOT burn a user's balance", async function () {
      await expect(aegisEUR.connect(vault).burn(alice.address, 500n)).to.be.revertedWith("Can only burn own balance");
    });

    it("non-minter cannot burn", async function () {
      await expect(aegisEUR.connect(alice).burn(alice.address, 100n)).to.be.revertedWith("Not minter");
    });

    it("cannot burn more than balance", async function () {
      await expect(aegisEUR.connect(vault).burn(vault.address, 3000n)).to.be.revertedWith("Insufficient balance");
    });

    it("emits Transfer and Burn events on burn", async function () {
      await expect(aegisEUR.connect(vault).burn(vault.address, 500n))
        .to.emit(aegisEUR, "Transfer")
        .withArgs(vault.address, ethers.ZeroAddress, 500n)
        .and.to.emit(aegisEUR, "Burn")
        .withArgs(vault.address, 500n);
    });
  });


  // ─── Transfers ────────────────────────────────────────────────────────────────

  describe("Transfers", function () {
    beforeEach(async function () {
      await aegisEUR.connect(vault).mint(alice.address, 5000n);
    });

    it("basic transfer updates balances", async function () {
      await aegisEUR.connect(alice).transfer(bob.address, 1000n);
      expect(await aegisEUR.balanceOf(alice.address)).to.equal(4000n);
      expect(await aegisEUR.balanceOf(bob.address)).to.equal(1000n);
    });

    it("emits Transfer event", async function () {
      await expect(aegisEUR.connect(alice).transfer(bob.address, 1000n))
        .to.emit(aegisEUR, "Transfer")
        .withArgs(alice.address, bob.address, 1000n);
    });

    it("reverts when insufficient balance", async function () {
      await expect(
        aegisEUR.connect(alice).transfer(bob.address, 6000n)
      ).to.be.revertedWith("Insufficient balance");
    });

    it("transferFrom works with sufficient allowance", async function () {
      await aegisEUR.connect(alice).approve(bob.address, 1000n);
      await aegisEUR.connect(bob).transferFrom(alice.address, bob.address, 500n);
      expect(await aegisEUR.balanceOf(alice.address)).to.equal(4500n);
      expect(await aegisEUR.balanceOf(bob.address)).to.equal(500n);
      expect(await aegisEUR.allowance(alice.address, bob.address)).to.equal(500n);
    });

    it("transferFrom reverts on insufficient allowance", async function () {
      await aegisEUR.connect(alice).approve(bob.address, 100n);
      await expect(
        aegisEUR.connect(bob).transferFrom(alice.address, bob.address, 500n)
      ).to.be.revertedWith("Insufficient allowance");
    });
  });

  // ─── Frozen accounts ──────────────────────────────────────────────────────────

  describe("Frozen accounts", function () {
    beforeEach(async function () {
      await aegisEUR.connect(vault).mint(alice.address, 5000n);
      await aegisEUR.connect(vault).mint(bob.address, 5000n);
    });

    it("regulator can freeze an account", async function () {
      await aegisEUR.connect(regulator).freeze(alice.address);
      expect(await aegisEUR.frozen(alice.address)).to.equal(true);
    });

    it("freeze emits Frozen event", async function () {
      await expect(aegisEUR.connect(regulator).freeze(alice.address))
        .to.emit(aegisEUR, "Frozen")
        .withArgs(alice.address, regulator.address);
    });

    it("cannot transfer from frozen account", async function () {
      await aegisEUR.connect(regulator).freeze(alice.address);
      await expect(
        aegisEUR.connect(alice).transfer(bob.address, 100n)
      ).to.be.revertedWith("Account frozen");
    });

    it("cannot transfer to frozen account", async function () {
      await aegisEUR.connect(regulator).freeze(bob.address);
      await expect(
        aegisEUR.connect(alice).transfer(bob.address, 100n)
      ).to.be.revertedWith("Account frozen");
    });

    it("non-regulator cannot freeze", async function () {
      await expect(
        aegisEUR.connect(alice).freeze(bob.address)
      ).to.be.revertedWith("Not regulator");
    });

    it("regulator can unfreeze", async function () {
      await aegisEUR.connect(regulator).freeze(alice.address);
      await aegisEUR.connect(regulator).unfreeze(alice.address);
      expect(await aegisEUR.frozen(alice.address)).to.equal(false);
    });

    it("unfreeze emits Unfrozen event", async function () {
      await aegisEUR.connect(regulator).freeze(alice.address);
      await expect(aegisEUR.connect(regulator).unfreeze(alice.address))
        .to.emit(aegisEUR, "Unfrozen")
        .withArgs(alice.address, regulator.address);
    });

    it("after unfreeze, account can transfer again", async function () {
      await aegisEUR.connect(regulator).freeze(alice.address);
      await aegisEUR.connect(regulator).unfreeze(alice.address);
      await aegisEUR.connect(alice).transfer(bob.address, 100n);
      expect(await aegisEUR.balanceOf(bob.address)).to.equal(5100n);
    });
  });

  // ─── transferWithProof ────────────────────────────────────────────────────────

  describe("transferWithProof", function () {
    const THRESHOLD = 1000n * 10n ** 6n; // 1000 AEGIS-EUR

    beforeEach(async function () {
      await aegisEUR.connect(vault).mint(alice.address, THRESHOLD * 10n);
    });

    it("works below threshold without verifier (no ZK check)", async function () {
      const proof = ethers.toUtf8Bytes("some-proof-data");
      const amount = THRESHOLD - 1n;
      await aegisEUR.connect(alice).transferWithProof(bob.address, amount, proof);
      expect(await aegisEUR.balanceOf(bob.address)).to.equal(amount);
    });

    it("works at threshold with dev-mode verifier set", async function () {
      await aegisEUR.connect(owner).setVerifier(await noirVerifier.getAddress());
      const proof = ethers.toUtf8Bytes("valid-proof");
      await aegisEUR.connect(alice).transferWithProof(bob.address, THRESHOLD, proof);
      expect(await aegisEUR.balanceOf(bob.address)).to.equal(THRESHOLD);
    });

    it("emits ProofAttached event", async function () {
      const proof = ethers.toUtf8Bytes("my-proof");
      const proofHash = ethers.keccak256(proof);
      await expect(
        aegisEUR.connect(alice).transferWithProof(bob.address, 100n, proof)
      )
        .to.emit(aegisEUR, "ProofAttached")
        .withArgs(alice.address, bob.address, proofHash);
    });

    it("rejects reused proof hash", async function () {
      const proof = ethers.toUtf8Bytes("reused-proof");
      await aegisEUR.connect(alice).transferWithProof(bob.address, 100n, proof);
      await expect(
        aegisEUR.connect(alice).transferWithProof(bob.address, 100n, proof)
      ).to.be.revertedWith("Proof already used");
    });

    it("rejects invalid ZK proof at or above threshold when verifier set", async function () {
      // Deploy verifier in non-dev mode and set it
      const prodVerifier = await NoirVerifier.deploy(false);
      await aegisEUR.connect(owner).setVerifier(await prodVerifier.getAddress());

      // Empty proof will fail _ultraPlonkVerify (proof.length < 32)
      const badProof = ethers.toUtf8Bytes("short");
      await expect(
        aegisEUR.connect(alice).transferWithProof(bob.address, THRESHOLD, badProof)
      ).to.be.revertedWith("Invalid ZK proof");
    });
  });

  // ─── Balance commitments ──────────────────────────────────────────────────────

  describe("Balance commitments", function () {
    it("user can update their own commitment", async function () {
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("my-balance-commitment"));
      await aegisEUR.connect(alice).updateBalanceCommitment(commitment);
      expect(await aegisEUR.getBalanceCommitment(alice.address)).to.equal(commitment);
    });

    it("emits CommitmentUpdated event", async function () {
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment-value"));
      await expect(aegisEUR.connect(alice).updateBalanceCommitment(commitment))
        .to.emit(aegisEUR, "CommitmentUpdated")
        .withArgs(alice.address, commitment);
    });
  });

  // ─── Role management ──────────────────────────────────────────────────────────

  describe("Role management", function () {
    it("owner can add a minter", async function () {
      await aegisEUR.connect(owner).addMinter(minter.address);
      expect(await aegisEUR.minters(minter.address)).to.equal(true);
    });

    it("addMinter emits MinterAdded", async function () {
      await expect(aegisEUR.connect(owner).addMinter(minter.address))
        .to.emit(aegisEUR, "MinterAdded")
        .withArgs(minter.address);
    });

    it("non-owner cannot add a minter", async function () {
      await expect(
        aegisEUR.connect(alice).addMinter(minter.address)
      ).to.be.revertedWith("Not owner");
    });

    it("owner can remove a minter", async function () {
      await aegisEUR.connect(owner).addMinter(minter.address);
      await aegisEUR.connect(owner).removeMinter(minter.address);
      expect(await aegisEUR.minters(minter.address)).to.equal(false);
    });

    it("removeMinter emits MinterRemoved", async function () {
      await aegisEUR.connect(owner).addMinter(minter.address);
      await expect(aegisEUR.connect(owner).removeMinter(minter.address))
        .to.emit(aegisEUR, "MinterRemoved")
        .withArgs(minter.address);
    });

    it("non-owner cannot remove a minter", async function () {
      await expect(
        aegisEUR.connect(alice).removeMinter(vault.address)
      ).to.be.revertedWith("Not owner");
    });

    it("owner can add a regulator", async function () {
      await aegisEUR.connect(owner).addRegulator(alice.address);
      expect(await aegisEUR.regulators(alice.address)).to.equal(true);
    });

    it("addRegulator emits RegulatorAdded", async function () {
      await expect(aegisEUR.connect(owner).addRegulator(alice.address))
        .to.emit(aegisEUR, "RegulatorAdded")
        .withArgs(alice.address);
    });

    it("non-owner cannot add a regulator", async function () {
      await expect(
        aegisEUR.connect(alice).addRegulator(bob.address)
      ).to.be.revertedWith("Not owner");
    });

    it("setVault updates vault and minter status", async function () {
      const newVault = bob;
      await aegisEUR.connect(owner).setVault(newVault.address);
      expect(await aegisEUR.vault()).to.equal(newVault.address);
      expect(await aegisEUR.minters(newVault.address)).to.equal(true);
      expect(await aegisEUR.minters(vault.address)).to.equal(false);
    });

    it("setVault reverts for zero address", async function () {
      await expect(
        aegisEUR.connect(owner).setVault(ethers.ZeroAddress)
      ).to.be.revertedWith("Vault zero");
    });

    it("non-owner cannot setVault", async function () {
      await expect(
        aegisEUR.connect(alice).setVault(bob.address)
      ).to.be.revertedWith("Not owner");
    });
  });

  // ─── Approve ──────────────────────────────────────────────────────────────────

  describe("Approve", function () {
    it("sets allowance correctly", async function () {
      await aegisEUR.connect(alice).approve(bob.address, 1234n);
      expect(await aegisEUR.allowance(alice.address, bob.address)).to.equal(1234n);
    });

    it("emits Approval event", async function () {
      await expect(aegisEUR.connect(alice).approve(bob.address, 1234n))
        .to.emit(aegisEUR, "Approval")
        .withArgs(alice.address, bob.address, 1234n);
    });
  });
});
