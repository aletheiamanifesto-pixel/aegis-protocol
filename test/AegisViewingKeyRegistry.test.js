const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("AegisViewingKeyRegistry", function () {
  let Registry;
  let registry;
  let owner, alice, bob, carol;

  // Helper: current block timestamp
  async function blockTimestamp() {
    const block = await ethers.provider.getBlock("latest");
    return block.timestamp;
  }

  beforeEach(async function () {
    [owner, alice, bob, carol] = await ethers.getSigners();

    Registry = await ethers.getContractFactory("AegisViewingKeyRegistry");
    registry = await Registry.deploy();
  });

  // ─── Deployment ───────────────────────────────────────────────────────────

  describe("Deployment", function () {
    it("sets the deployer as owner", async function () {
      expect(await registry.owner()).to.equal(owner.address);
    });

    it("starts unpaused", async function () {
      expect(await registry.paused()).to.equal(false);
    });
  });

  // ─── grantAccess ──────────────────────────────────────────────────────────

  describe("grantAccess", function () {
    const txHash = ethers.keccak256(ethers.toUtf8Bytes("test-tx-hash"));
    const scope = "single_tx";
    let expiresAt;

    beforeEach(async function () {
      const ts = await blockTimestamp();
      expiresAt = ts + 30 * 24 * 3600; // 30 days from now
    });

    it("stores the grant correctly", async function () {
      const tx = await registry
        .connect(alice)
        .grantAccess(bob.address, txHash, scope, expiresAt);
      const receipt = await tx.wait();

      // Parse the AccessGranted event to get grantId
      const event = receipt.logs
        .map((log) => {
          try {
            return registry.interface.parseLog(log);
          } catch {
            return null;
          }
        })
        .find((e) => e && e.name === "AccessGranted");

      expect(event).to.not.be.null;
      const grantId = event.args.grantId;

      const grant = await registry.getGrant(grantId);
      expect(grant.owner).to.equal(alice.address);
      expect(grant.grantee).to.equal(bob.address);
      expect(grant.txHash).to.equal(txHash);
      expect(grant.scope).to.equal(scope);
      expect(grant.expiresAt).to.equal(BigInt(expiresAt));
      expect(grant.active).to.equal(true);
    });

    it("emits AccessGranted event with correct args", async function () {
      const ts = await blockTimestamp();
      expiresAt = ts + 30 * 24 * 3600;

      const tx = await registry
        .connect(alice)
        .grantAccess(bob.address, txHash, scope, expiresAt);
      const receipt = await tx.wait();

      const event = receipt.logs
        .map((log) => {
          try {
            return registry.interface.parseLog(log);
          } catch {
            return null;
          }
        })
        .find((e) => e && e.name === "AccessGranted");

      expect(event).to.not.be.null;
      expect(event.args.owner).to.equal(alice.address);
      expect(event.args.grantee).to.equal(bob.address);
      expect(event.args.txHash).to.equal(txHash);
      expect(event.args.scope).to.equal(scope);
      expect(event.args.expiresAt).to.equal(BigInt(expiresAt));
    });

    it("anyone can grant access (msg.sender becomes owner of grant)", async function () {
      // Carol — not the contract owner — can still create a grant for her own wallet
      await expect(
        registry.connect(carol).grantAccess(bob.address, txHash, scope, expiresAt)
      ).to.not.be.reverted;
    });

    it("reverts when grantee is zero address", async function () {
      await expect(
        registry
          .connect(alice)
          .grantAccess(ethers.ZeroAddress, txHash, scope, expiresAt)
      ).to.be.revertedWith("Grantee is zero address");
    });

    it("reverts when scope is empty string", async function () {
      await expect(
        registry.connect(alice).grantAccess(bob.address, txHash, "", expiresAt)
      ).to.be.revertedWith("Scope must not be empty");
    });

    it("reverts when paused", async function () {
      await registry.connect(owner).pause();
      await expect(
        registry.connect(alice).grantAccess(bob.address, txHash, scope, expiresAt)
      ).to.be.revertedWith("Contract is paused");
    });
  });

  // ─── revokeAccess ─────────────────────────────────────────────────────────

  describe("revokeAccess", function () {
    let grantId;
    const txHash = ethers.keccak256(ethers.toUtf8Bytes("revoke-test"));
    const scope = "balance_only";

    beforeEach(async function () {
      const ts = await blockTimestamp();
      const expiresAt = ts + 7 * 24 * 3600;

      const tx = await registry
        .connect(alice)
        .grantAccess(bob.address, txHash, scope, expiresAt);
      const receipt = await tx.wait();
      const event = receipt.logs
        .map((log) => {
          try {
            return registry.interface.parseLog(log);
          } catch {
            return null;
          }
        })
        .find((e) => e && e.name === "AccessGranted");
      grantId = event.args.grantId;
    });

    it("marks grant as inactive", async function () {
      await registry.connect(alice).revokeAccess(grantId);
      const grant = await registry.getGrant(grantId);
      expect(grant.active).to.equal(false);
    });

    it("emits AccessRevoked event", async function () {
      const tx = await registry.connect(alice).revokeAccess(grantId);
      const receipt = await tx.wait();

      const event = receipt.logs
        .map((log) => {
          try {
            return registry.interface.parseLog(log);
          } catch {
            return null;
          }
        })
        .find((e) => e && e.name === "AccessRevoked");

      expect(event).to.not.be.null;
      expect(event.args.grantId).to.equal(grantId);
      expect(event.args.owner).to.equal(alice.address);
    });

    it("reverts when non-owner tries to revoke", async function () {
      await expect(
        registry.connect(bob).revokeAccess(grantId)
      ).to.be.revertedWith("Not grant owner");
    });

    it("reverts on double revoke", async function () {
      await registry.connect(alice).revokeAccess(grantId);
      await expect(
        registry.connect(alice).revokeAccess(grantId)
      ).to.be.revertedWith("Grant already revoked");
    });

    it("reverts when grant not found", async function () {
      const badId = ethers.keccak256(ethers.toUtf8Bytes("nonexistent"));
      await expect(
        registry.connect(alice).revokeAccess(badId)
      ).to.be.revertedWith("Grant not found");
    });

    it("reverts when paused", async function () {
      await registry.connect(owner).pause();
      await expect(
        registry.connect(alice).revokeAccess(grantId)
      ).to.be.revertedWith("Contract is paused");
    });
  });

  // ─── isAccessActive ───────────────────────────────────────────────────────

  describe("isAccessActive", function () {
    const txHash = ethers.keccak256(ethers.toUtf8Bytes("active-test"));
    const scope = "tx_only";

    it("returns true for an active, non-expired grant", async function () {
      const ts = await blockTimestamp();
      const expiresAt = ts + 3600; // 1 hour
      const tx = await registry
        .connect(alice)
        .grantAccess(bob.address, txHash, scope, expiresAt);
      const receipt = await tx.wait();
      const event = receipt.logs
        .map((log) => {
          try {
            return registry.interface.parseLog(log);
          } catch {
            return null;
          }
        })
        .find((e) => e && e.name === "AccessGranted");
      const grantId = event.args.grantId;

      expect(await registry.isAccessActive(grantId)).to.equal(true);
    });

    it("returns false for a revoked grant", async function () {
      const ts = await blockTimestamp();
      const expiresAt = ts + 3600;
      const tx = await registry
        .connect(alice)
        .grantAccess(bob.address, txHash, scope, expiresAt);
      const receipt = await tx.wait();
      const event = receipt.logs
        .map((log) => {
          try {
            return registry.interface.parseLog(log);
          } catch {
            return null;
          }
        })
        .find((e) => e && e.name === "AccessGranted");
      const grantId = event.args.grantId;

      await registry.connect(alice).revokeAccess(grantId);
      expect(await registry.isAccessActive(grantId)).to.equal(false);
    });

    it("returns false for an expired grant (expiresAt in the past)", async function () {
      // Use expiresAt = 1 (far in the past)
      const expiresAt = 1;
      const tx = await registry
        .connect(alice)
        .grantAccess(bob.address, txHash, scope, expiresAt);
      const receipt = await tx.wait();
      const event = receipt.logs
        .map((log) => {
          try {
            return registry.interface.parseLog(log);
          } catch {
            return null;
          }
        })
        .find((e) => e && e.name === "AccessGranted");
      const grantId = event.args.grantId;

      expect(await registry.isAccessActive(grantId)).to.equal(false);
    });

    it("returns true for a grant with expiresAt = 0 (no expiry)", async function () {
      const tx = await registry
        .connect(alice)
        .grantAccess(bob.address, txHash, scope, 0);
      const receipt = await tx.wait();
      const event = receipt.logs
        .map((log) => {
          try {
            return registry.interface.parseLog(log);
          } catch {
            return null;
          }
        })
        .find((e) => e && e.name === "AccessGranted");
      const grantId = event.args.grantId;

      expect(await registry.isAccessActive(grantId)).to.equal(true);
    });

    it("returns false for a non-existent grantId", async function () {
      const badId = ethers.keccak256(ethers.toUtf8Bytes("nope"));
      expect(await registry.isAccessActive(badId)).to.equal(false);
    });
  });

  // ─── getGrant ─────────────────────────────────────────────────────────────

  describe("getGrant", function () {
    it("returns correct grant data", async function () {
      const txHash = ethers.keccak256(ethers.toUtf8Bytes("get-grant-test"));
      const scope = "full_access";
      const ts = await blockTimestamp();
      const expiresAt = ts + 60;

      const tx = await registry
        .connect(alice)
        .grantAccess(bob.address, txHash, scope, expiresAt);
      const receipt = await tx.wait();
      const event = receipt.logs
        .map((log) => {
          try {
            return registry.interface.parseLog(log);
          } catch {
            return null;
          }
        })
        .find((e) => e && e.name === "AccessGranted");
      const grantId = event.args.grantId;

      const grant = await registry.getGrant(grantId);
      expect(grant.owner).to.equal(alice.address);
      expect(grant.grantee).to.equal(bob.address);
      expect(grant.txHash).to.equal(txHash);
      expect(grant.scope).to.equal(scope);
      expect(grant.expiresAt).to.equal(BigInt(expiresAt));
      expect(grant.active).to.equal(true);
      expect(grant.grantedAt).to.be.greaterThan(0n);
    });

    it("reverts for a non-existent grantId", async function () {
      const badId = ethers.keccak256(ethers.toUtf8Bytes("missing"));
      await expect(registry.getGrant(badId)).to.be.revertedWith("Grant not found");
    });
  });

  // ─── pause / unpause ──────────────────────────────────────────────────────

  describe("pause / unpause", function () {
    it("contract owner can pause", async function () {
      await registry.connect(owner).pause();
      expect(await registry.paused()).to.equal(true);
    });

    it("emits Paused event", async function () {
      const tx = await registry.connect(owner).pause();
      const receipt = await tx.wait();
      const event = receipt.logs
        .map((log) => {
          try {
            return registry.interface.parseLog(log);
          } catch {
            return null;
          }
        })
        .find((e) => e && e.name === "Paused");
      expect(event).to.not.be.null;
      expect(event.args.by).to.equal(owner.address);
    });

    it("contract owner can unpause", async function () {
      await registry.connect(owner).pause();
      await registry.connect(owner).unpause();
      expect(await registry.paused()).to.equal(false);
    });

    it("emits Unpaused event", async function () {
      await registry.connect(owner).pause();
      const tx = await registry.connect(owner).unpause();
      const receipt = await tx.wait();
      const event = receipt.logs
        .map((log) => {
          try {
            return registry.interface.parseLog(log);
          } catch {
            return null;
          }
        })
        .find((e) => e && e.name === "Unpaused");
      expect(event).to.not.be.null;
    });

    it("non-owner cannot pause", async function () {
      await expect(registry.connect(alice).pause()).to.be.revertedWith(
        "Not contract owner"
      );
    });

    it("non-owner cannot unpause", async function () {
      await registry.connect(owner).pause();
      await expect(registry.connect(alice).unpause()).to.be.revertedWith(
        "Not contract owner"
      );
    });

    it("grantAccess blocked when paused, works after unpause", async function () {
      const txHash = ethers.keccak256(ethers.toUtf8Bytes("pause-flow"));
      const ts = await blockTimestamp();
      const expiresAt = ts + 3600;

      await registry.connect(owner).pause();
      await expect(
        registry.connect(alice).grantAccess(bob.address, txHash, "single_tx", expiresAt)
      ).to.be.revertedWith("Contract is paused");

      await registry.connect(owner).unpause();
      await expect(
        registry.connect(alice).grantAccess(bob.address, txHash, "single_tx", expiresAt)
      ).to.not.be.reverted;
    });
  });
});
