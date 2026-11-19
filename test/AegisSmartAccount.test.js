const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

// ─── Minimal mocks deployed inline ───────────────────────────────────────────

// Deploy a minimal ERC-20 mock (MockEURC) that supports transfer/transferFrom/approve
const MOCK_EURC_ABI = [
  "function mint(address to, uint256 amount) external",
  "function transfer(address to, uint256 amount) external returns (bool)",
  "function transferFrom(address from, address to, uint256 amount) external returns (bool)",
  "function approve(address spender, uint256 amount) external returns (bool)",
  "function balanceOf(address account) external view returns (uint256)",
];

// We will use AegisEUR as the EURC token since it's a compatible ERC-20 and already compiled.
// AegisSmartAccount only calls transfer/transferFrom/balanceOf on the EURC address.

describe("AegisSmartAccount", function () {
  let AegisSmartAccount, AegisEUR;
  let account, eurc;
  let owner, regulator, guardian, alice, bob, entryPointSigner;

  // Minimal mock EntryPoint — AegisSmartAccount only calls entryPoint.call{value:}
  // and checks msg.sender == entryPoint in some modifiers.
  // We will use a real signer address as entryPoint.

  beforeEach(async function () {
    [owner, regulator, guardian, alice, bob, entryPointSigner] =
      await ethers.getSigners();

    // Deploy AegisEUR as our EURC token (owner=deployer, vault=alice for minting convenience)
    AegisEUR = await ethers.getContractFactory("AegisEUR");
    eurc = await AegisEUR.deploy(alice.address, regulator.address);

    AegisSmartAccount = await ethers.getContractFactory("AegisSmartAccount");
    account = await AegisSmartAccount.deploy(
      owner.address,
      entryPointSigner.address, // entryPoint
      await eurc.getAddress(),
      regulator.address
    );
  });

  // ─── Deployment ──────────────────────────────────────────────────────────────

  describe("Deployment", function () {
    it("sets owner correctly", async function () {
      expect(await account.owner()).to.equal(owner.address);
    });

    it("sets entryPoint correctly", async function () {
      expect(await account.entryPoint()).to.equal(entryPointSigner.address);
    });

    it("sets eurc correctly", async function () {
      expect(await account.eurc()).to.equal(await eurc.getAddress());
    });

    it("sets regulator correctly", async function () {
      expect(await account.regulator()).to.equal(regulator.address);
    });

    it("starts unfrozen", async function () {
      expect(await account.frozen()).to.equal(false);
    });

    it("starts with recoveryThreshold = 1", async function () {
      expect(await account.recoveryThreshold()).to.equal(1n);
    });

    it("reverts when owner is zero address", async function () {
      await expect(
        AegisSmartAccount.deploy(
          ethers.ZeroAddress,
          entryPointSigner.address,
          await eurc.getAddress(),
          regulator.address
        )
      ).to.be.revertedWith("Owner zero");
    });

    it("reverts when entryPoint is zero address", async function () {
      await expect(
        AegisSmartAccount.deploy(
          owner.address,
          ethers.ZeroAddress,
          await eurc.getAddress(),
          regulator.address
        )
      ).to.be.revertedWith("EntryPoint zero");
    });

    it("reverts when eurc is zero address", async function () {
      await expect(
        AegisSmartAccount.deploy(
          owner.address,
          entryPointSigner.address,
          ethers.ZeroAddress,
          regulator.address
        )
      ).to.be.revertedWith("EURC zero");
    });
  });

  // ─── EURC transfer ────────────────────────────────────────────────────────────

  describe("transferEURC", function () {
    const THRESHOLD = 1000n * 10n ** 6n;

    beforeEach(async function () {
      // Mint to owner via alice (vault), owner approves the account, then deposits
      await eurc.connect(alice).mint(owner.address, THRESHOLD * 10n);
      await eurc.connect(owner).approve(await account.getAddress(), THRESHOLD * 10n);
      await account.connect(owner).depositEURC(THRESHOLD * 10n);
    });

    it("owner can transfer EURC below threshold without proof hash", async function () {
      const amount = THRESHOLD - 1n;
      await account.connect(owner).transferEURC(bob.address, amount, ethers.ZeroHash);
      expect(await eurc.balanceOf(bob.address)).to.equal(amount);
    });

    it("emits EURCTransferred event", async function () {
      const amount = 100n;
      await expect(
        account.connect(owner).transferEURC(bob.address, amount, ethers.ZeroHash)
      )
        .to.emit(account, "EURCTransferred")
        .withArgs(bob.address, amount, ethers.ZeroHash);
    });

    it("owner can transfer at or above threshold with a non-zero proof hash", async function () {
      const proofHash = ethers.keccak256(ethers.toUtf8Bytes("my-zk-proof"));
      await account.connect(owner).transferEURC(bob.address, THRESHOLD, proofHash);
      expect(await eurc.balanceOf(bob.address)).to.equal(THRESHOLD);
    });

    it("reverts above threshold when proof hash is zero", async function () {
      await expect(
        account.connect(owner).transferEURC(bob.address, THRESHOLD, ethers.ZeroHash)
      ).to.be.revertedWith("ZK proof required for large transfers");
    });

    it("reverts on reused proof hash", async function () {
      const proofHash = ethers.keccak256(ethers.toUtf8Bytes("reuse-proof"));
      await account.connect(owner).transferEURC(bob.address, THRESHOLD, proofHash);
      await expect(
        account.connect(owner).transferEURC(bob.address, THRESHOLD, proofHash)
      ).to.be.revertedWith("Proof already used");
    });

    it("reverts when recipient is zero address", async function () {
      await expect(
        account.connect(owner).transferEURC(ethers.ZeroAddress, 100n, ethers.ZeroHash)
      ).to.be.revertedWith("Zero recipient");
    });

    it("reverts when amount is zero", async function () {
      await expect(
        account.connect(owner).transferEURC(bob.address, 0n, ethers.ZeroHash)
      ).to.be.revertedWith("Zero amount");
    });

    it("non-owner cannot transfer EURC", async function () {
      await expect(
        account.connect(alice).transferEURC(bob.address, 100n, ethers.ZeroHash)
      ).to.be.revertedWith("Not owner");
    });
  });

  // ─── depositEURC ─────────────────────────────────────────────────────────────

  describe("depositEURC", function () {
    it("deposits EURC into the account and emits EURCDeposited", async function () {
      await eurc.connect(alice).mint(alice.address, 1000n);
      await eurc.connect(alice).approve(await account.getAddress(), 1000n);
      await expect(account.connect(alice).depositEURC(1000n))
        .to.emit(account, "EURCDeposited")
        .withArgs(alice.address, 1000n);
      expect(await eurc.balanceOf(await account.getAddress())).to.equal(1000n);
    });
  });

  // ─── execute ──────────────────────────────────────────────────────────────────

  describe("execute", function () {
    it("owner can execute a call", async function () {
      // Send ETH to the account first
      await owner.sendTransaction({ to: await account.getAddress(), value: ethers.parseEther("1") });

      const balanceBefore = await ethers.provider.getBalance(bob.address);
      await account.connect(owner).execute(bob.address, ethers.parseEther("0.1"), "0x");
      const balanceAfter = await ethers.provider.getBalance(bob.address);
      expect(balanceAfter - balanceBefore).to.equal(ethers.parseEther("0.1"));
    });

    it("emits Executed event", async function () {
      await owner.sendTransaction({ to: await account.getAddress(), value: ethers.parseEther("0.5") });
      await expect(
        account.connect(owner).execute(bob.address, ethers.parseEther("0.1"), "0x")
      )
        .to.emit(account, "Executed")
        .withArgs(bob.address, ethers.parseEther("0.1"), "0x");
    });

    it("non-owner cannot execute", async function () {
      await expect(
        account.connect(alice).execute(bob.address, 0n, "0x")
      ).to.be.revertedWith("Not owner");
    });
  });

  // ─── executeBatch ────────────────────────────────────────────────────────────

  describe("executeBatch", function () {
    it("owner can execute a batch of calls", async function () {
      await owner.sendTransaction({ to: await account.getAddress(), value: ethers.parseEther("1") });
      await account.connect(owner).executeBatch(
        [bob.address, alice.address],
        [ethers.parseEther("0.1"), ethers.parseEther("0.2")],
        ["0x", "0x"]
      );
      // Just check it doesn't revert
    });

    it("emits BatchExecuted event", async function () {
      await owner.sendTransaction({ to: await account.getAddress(), value: ethers.parseEther("1") });
      await expect(
        account.connect(owner).executeBatch(
          [bob.address],
          [ethers.parseEther("0.05")],
          ["0x"]
        )
      )
        .to.emit(account, "BatchExecuted")
        .withArgs(1n);
    });

    it("reverts when array lengths mismatch", async function () {
      await expect(
        account.connect(owner).executeBatch(
          [bob.address, alice.address],
          [ethers.parseEther("0.1")], // length mismatch
          ["0x", "0x"]
        )
      ).to.be.revertedWith("Array length mismatch");
    });
  });

  // ─── Freeze / Unfreeze ────────────────────────────────────────────────────────

  describe("Freeze / Unfreeze", function () {
    it("regulator can freeze the account", async function () {
      await account.connect(regulator).freeze();
      expect(await account.frozen()).to.equal(true);
    });

    it("freeze emits Frozen event", async function () {
      await expect(account.connect(regulator).freeze())
        .to.emit(account, "Frozen")
        .withArgs(regulator.address);
    });

    it("regulator can unfreeze the account", async function () {
      await account.connect(regulator).freeze();
      await account.connect(regulator).unfreeze();
      expect(await account.frozen()).to.equal(false);
    });

    it("unfreeze emits Unfrozen event", async function () {
      await account.connect(regulator).freeze();
      await expect(account.connect(regulator).unfreeze())
        .to.emit(account, "Unfrozen")
        .withArgs(regulator.address);
    });

    it("non-regulator cannot freeze", async function () {
      await expect(account.connect(alice).freeze()).to.be.revertedWith("Not regulator");
    });

    it("cannot execute when frozen", async function () {
      await account.connect(regulator).freeze();
      await expect(
        account.connect(owner).execute(bob.address, 0n, "0x")
      ).to.be.revertedWith("Account frozen");
    });
  });

  // ─── Guardian management ─────────────────────────────────────────────────────

  describe("Guardian management", function () {
    it("owner can add a guardian", async function () {
      await account.connect(owner).addGuardian(guardian.address);
      expect(await account.guardians(guardian.address)).to.equal(true);
      expect(await account.guardianCount()).to.equal(1n);
    });

    it("addGuardian emits GuardianAdded event", async function () {
      await expect(account.connect(owner).addGuardian(guardian.address))
        .to.emit(account, "GuardianAdded")
        .withArgs(guardian.address);
    });

    it("owner can remove a guardian", async function () {
      await account.connect(owner).addGuardian(guardian.address);
      // Add a second guardian so threshold is met after removal
      await account.connect(owner).addGuardian(alice.address);
      await account.connect(owner).removeGuardian(alice.address);
      expect(await account.guardians(alice.address)).to.equal(false);
    });

    it("removeGuardian emits GuardianRemoved event", async function () {
      await account.connect(owner).addGuardian(guardian.address);
      await account.connect(owner).addGuardian(alice.address);
      await expect(account.connect(owner).removeGuardian(alice.address))
        .to.emit(account, "GuardianRemoved")
        .withArgs(alice.address);
    });

    it("non-owner cannot add guardian", async function () {
      await expect(
        account.connect(alice).addGuardian(guardian.address)
      ).to.be.revertedWith("Not owner");
    });

    it("reverts when removing non-guardian", async function () {
      await expect(
        account.connect(owner).removeGuardian(alice.address)
      ).to.be.revertedWith("Not a guardian");
    });
  });

  // ─── Recovery ─────────────────────────────────────────────────────────────────

  describe("Recovery", function () {
    beforeEach(async function () {
      await account.connect(owner).addGuardian(guardian.address);
    });

    it("guardian can initiate recovery", async function () {
      await expect(
        account.connect(guardian).initiateRecovery(alice.address, 3600)
      )
        .to.emit(account, "RecoveryInitiated");
    });

    it("threshold reached → executable only after the delay", async function () {
      await account.connect(guardian).initiateRecovery(alice.address, 3600);
      await expect(account.connect(guardian).approveRecovery()).to.emit(account, "RecoveryReady");
      await expect(account.executeRecovery()).to.be.revertedWith("Delay not elapsed");
      await time.increase(2 * 24 * 3600);
      await expect(account.executeRecovery()).to.emit(account, "RecoveryExecuted").withArgs(alice.address);
      expect(await account.owner()).to.equal(alice.address);
    });

    it("recovery can be repeated (votes reset each round)", async function () {
      await account.connect(guardian).initiateRecovery(alice.address, 3600);
      await account.connect(guardian).approveRecovery();
      await time.increase(2 * 24 * 3600);
      await account.executeRecovery();
      // second recovery: the same guardian can vote again
      await account.connect(guardian).initiateRecovery(owner.address, 3600);
      await account.connect(guardian).approveRecovery();
      await time.increase(2 * 24 * 3600);
      await account.executeRecovery();
      expect(await account.owner()).to.equal(owner.address);
    });

    it("a guardian cannot reset an open recovery (griefing)", async function () {
      await account.connect(guardian).initiateRecovery(alice.address, 3600);
      await expect(account.connect(guardian).initiateRecovery(guardian.address, 3600)).to.be.revertedWith(
        "Recovery in progress"
      );
    });

    it("the owner can cancel a malicious recovery during the delay", async function () {
      await account.connect(guardian).initiateRecovery(alice.address, 3600);
      await account.connect(guardian).approveRecovery();
      await account.connect(owner).cancelRecovery();
      await time.increase(2 * 24 * 3600);
      await expect(account.executeRecovery()).to.be.revertedWith("Recovery not ready");
      expect(await account.owner()).to.equal(owner.address);
    });
  });

  // ─── receive ETH ─────────────────────────────────────────────────────────────

  describe("receive ETH", function () {
    it("accepts ETH transfers", async function () {
      const amount = ethers.parseEther("0.5");
      await owner.sendTransaction({ to: await account.getAddress(), value: amount });
      expect(
        await ethers.provider.getBalance(await account.getAddress())
      ).to.equal(amount);
    });
  });
});
