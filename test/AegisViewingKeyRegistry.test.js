const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("AegisViewingKeyRegistry", function () {
  let Registry;
  let registry;
  let owner, alice, bob, carol;

  beforeEach(async function () {
    [owner, alice, bob, carol] = await ethers.getSigners();

    Registry = await ethers.getContractFactory("AegisViewingKeyRegistry");
    registry = await Registry.deploy();
  });

  // ─── Deployment ─────────────────────────────────────────────────────────────

  describe("Deployment", function () {
    it("sets deployer as owner", async function () {
      expect(await registry.owner()).to.equal(owner.address);
    });

    it("starts unpaused", async function () {
      expect(await registry.paused()).to.equal(false);
    });
  });

  // ─── grantAccess ────────────────────────────────────────────────────────────

  describe("grantAccess", function () {
    const txHash = ethers.randomBytes(32);
    const scope = "single_tx";

    it("allows any account to grant access as the caller (owner of wallet)", async function () {
      const expiresAt =
        (await ethers.provider.getBlock("latest")).timestamp + 86400 * 30;

      await expect(
        registry.connect(alice).grantAccess(bob.address, txHash, scope, expiresAt)
      ).to.emit(registry, "AccessGranted");
    });

    it("emits AccessGranted with correct fields", async function () {
      const expiresAt =
        (await ethers.provider.getBlock("latest")).timestamp + 86400 * 30;

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
      expect(event.args.scope).to.equal(scope);
      expect(event.args.expiresAt).to.equal(BigInt(expiresAt));
    });

    it("stores the grant correctly", async function () {
      const expiresAt =
        (await ethers.provider.getBlock("latest")).timestamp + 86400 * 30;

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
      const [
        gOwner,
        gGrantee,
        gTxHash,
        gScope,
        gGrantedAt,
        gExpiresAt,
        gActive,
      ] = await registry.getGrant(grantId);

      expect(gOwner).to.equal(alice.address);
      expect(gGrantee).to.equal(bob.address);
      expect(ethers.hexlify(gTxHash)).to.equal(ethers.hexlify(txHash));
      expect(gScope).to.equal(scope);
      expect(gExpiresAt).to.equal(BigInt(expiresAt));
      expect(gActive).to.equal(true);
    });

    it("reverts if grantee is the zero address", async function () {
      const expiresAt =
        (await ethers.provider.getBlock("latest")).timestamp + 86400 * 30;

      await expect(
        registry.connect(alice).grantAccess(ethers.ZeroAddress, txHash, scope, expiresAt)
      ).to.be.revertedWith("AegisVKR: grantee is zero address");
    });

    it("reverts if scope is empty", async function () {
      const expiresAt =
        (await ethers.provider.getBlock("latest")).timestamp + 86400 * 30;

      await expect(
        registry.connect(alice).grantAccess(bob.address, txHash, "", expiresAt)
      ).to.be.revertedWith("AegisVKR: scope is empty");
    });

    it("reverts if expiresAt is in the past", async function () {
      const expiresAt =
        (await ethers.provider.getBlock("latest")).timestamp - 1;

      await expect(
        registry.connect(alice).grantAccess(bob.address, txHash, scope, expiresAt)
      ).to.be.revertedWith("AegisVKR: expiry is in the past");
    });

    it("accepts expiresAt = 0 (no expiry)", async function () {
      await expect(
        registry.connect(alice).grantAccess(bob.address, txHash, scope, 0)
      ).to.emit(registry, "AccessGranted");
    });

    it("reverts when paused", async function () {
      await registry.connect(owner).pause();
      const expiresAt =
        (await ethers.provider.getBlock("latest")).timestamp + 86400 * 30;

      await expect(
        registry.connect(alice).grantAccess(bob.address, txHash, scope, expiresAt)
      ).to.be.revertedWith("AegisVKR: paused");
    });
  });

  // ─── revokeAccess ───────────────────────────────────────────────────────────

  describe("revokeAccess", function () {
    let grantId;
    const txHash = ethers.randomBytes(32);
    const scope = "balance_only";

    beforeEach(async function () {
      const expiresAt =
        (await ethers.provider.getBlock("latest")).timestamp + 86400 * 30;
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

    it("allows the grant owner to revoke", async function () {
      await expect(
        registry.connect(alice).revokeAccess(grantId)
      ).to.emit(registry, "AccessRevoked");
    });

    it("emits AccessRevoked with correct fields", async function () {
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

    it("marks the grant as inactive after revocation", async function () {
      await registry.connect(alice).revokeAccess(grantId);
      const [, , , , , , active] = await registry.getGrant(grantId);
      expect(active).to.equal(false);
    });

    it("reverts if caller is not the grant owner", async function () {
      await expect(
        registry.connect(carol).revokeAccess(grantId)
      ).to.be.revertedWith("AegisVKR: not grant owner");
    });

    it("reverts if grant does not exist", async function () {
      const nonexistent = ethers.keccak256(ethers.toUtf8Bytes("fake-grant"));
      await expect(
        registry.connect(alice).revokeAccess(nonexistent)
      ).to.be.revertedWith("AegisVKR: grant does not exist");
    });

    it("reverts if already revoked", async function () {
      await registry.connect(alice).revokeAccess(grantId);
      await expect(
        registry.connect(alice).revokeAccess(grantId)
      ).to.be.revertedWith("AegisVKR: already revoked");
    });

    it("reverts when paused", async function () {
      await registry.connect(owner).pause();
      await expect(
        registry.connect(alice).revokeAccess(grantId)
      ).to.be.revertedWith("AegisVKR: paused");
    });
  });

  // ─── isAccessActive ─────────────────────────────────────────────────────────

  describe("isAccessActive", function () {
    const txHash = ethers.randomBytes(32);

    it("returns true for an active, non-expired grant", async function () {
      const expiresAt =
        (await ethers.provider.getBlock("latest")).timestamp + 86400 * 30;
      const tx = await registry
        .connect(alice)
        .grantAccess(bob.address, txHash, "single_tx", expiresAt);
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

      expect(await registry.isAccessActive(event.args.grantId)).to.equal(true);
    });

    it("returns false after revocation", async function () {
      const expiresAt =
        (await ethers.provider.getBlock("latest")).timestamp + 86400 * 30;
      const tx = await registry
        .connect(alice)
        .grantAccess(bob.address, txHash, "single_tx", expiresAt);
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

      await registry.connect(alice).revokeAccess(event.args.grantId);
      expect(await registry.isAccessActive(event.args.grantId)).to.equal(false);
    });

    it("returns false for an expired grant (via time warp)", async function () {
      // Grant expires 10 seconds after the latest block (the grant tx itself is mined at +1s)
      const blockTimestamp = (await ethers.provider.getBlock("latest")).timestamp;
      const expiresAt = blockTimestamp + 10;

      const tx = await registry
        .connect(alice)
        .grantAccess(bob.address, txHash, "single_tx", expiresAt);
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

      // Advance the block time past the expiry
      await ethers.provider.send("evm_increaseTime", [20]);
      await ethers.provider.send("evm_mine");

      expect(await registry.isAccessActive(grantId)).to.equal(false);
    });

    it("returns false for a nonexistent grant", async function () {
      const fake = ethers.keccak256(ethers.toUtf8Bytes("fake"));
      expect(await registry.isAccessActive(fake)).to.equal(false);
    });

    it("returns true for a grant with expiresAt = 0 (no expiry)", async function () {
      const tx = await registry
        .connect(alice)
        .grantAccess(bob.address, txHash, "single_tx", 0);
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

      expect(await registry.isAccessActive(event.args.grantId)).to.equal(true);
    });
  });

  // ─── getGrant ───────────────────────────────────────────────────────────────

  describe("getGrant", function () {
    it("reverts for a nonexistent grantId", async function () {
      const fake = ethers.keccak256(ethers.toUtf8Bytes("nonexistent"));
      await expect(registry.getGrant(fake)).to.be.revertedWith(
        "AegisVKR: grant does not exist"
      );
    });

    it("returns correct data for an existing grant", async function () {
      const txHash = ethers.randomBytes(32);
      const expiresAt =
        (await ethers.provider.getBlock("latest")).timestamp + 86400 * 7;

      const tx = await registry
        .connect(alice)
        .grantAccess(bob.address, txHash, "balance_only", expiresAt);
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

      const [
        gOwner,
        gGrantee,
        ,
        gScope,
        gGrantedAt,
        gExpiresAt,
        gActive,
      ] = await registry.getGrant(event.args.grantId);

      expect(gOwner).to.equal(alice.address);
      expect(gGrantee).to.equal(bob.address);
      expect(gScope).to.equal("balance_only");
      expect(gGrantedAt).to.be.gt(0n);
      expect(gExpiresAt).to.equal(BigInt(expiresAt));
      expect(gActive).to.equal(true);
    });
  });

  // ─── Pause / Unpause ────────────────────────────────────────────────────────

  describe("Pause / Unpause", function () {
    it("owner can pause and unpause", async function () {
      await expect(registry.connect(owner).pause()).to.emit(registry, "Paused");
      expect(await registry.paused()).to.equal(true);

      await expect(registry.connect(owner).unpause()).to.emit(registry, "Unpaused");
      expect(await registry.paused()).to.equal(false);
    });

    it("non-owner cannot pause", async function () {
      await expect(
        registry.connect(alice).pause()
      ).to.be.revertedWith("AegisVKR: not owner");
    });

    it("non-owner cannot unpause", async function () {
      await registry.connect(owner).pause();
      await expect(
        registry.connect(alice).unpause()
      ).to.be.revertedWith("AegisVKR: not owner");
    });

    it("actions are blocked while paused", async function () {
      await registry.connect(owner).pause();
      const txHash = ethers.randomBytes(32);
      const expiresAt =
        (await ethers.provider.getBlock("latest")).timestamp + 86400;

      await expect(
        registry
          .connect(alice)
          .grantAccess(bob.address, txHash, "single_tx", expiresAt)
      ).to.be.revertedWith("AegisVKR: paused");
    });

    it("actions resume after unpause", async function () {
      await registry.connect(owner).pause();
      await registry.connect(owner).unpause();

      const txHash = ethers.randomBytes(32);
      const expiresAt =
        (await ethers.provider.getBlock("latest")).timestamp + 86400;

      await expect(
        registry
          .connect(alice)
          .grantAccess(bob.address, txHash, "single_tx", expiresAt)
      ).to.emit(registry, "AccessGranted");
    });
  });
});
