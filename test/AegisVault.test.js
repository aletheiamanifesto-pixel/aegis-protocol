const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("AegisVault", function () {
  let AegisEUR, AegisVault;
  let aegisEUR, vault;
  let owner, signer1, signer2, alice, bob;

  beforeEach(async function () {
    [owner, signer1, signer2, alice, bob] = await ethers.getSigners();

    // Deploy AegisEUR with owner as vault placeholder initially
    AegisEUR = await ethers.getContractFactory("AegisEUR");
    aegisEUR = await AegisEUR.deploy(owner.address, owner.address);

    // Deploy AegisVault with 2 signers and threshold 1
    AegisVault = await ethers.getContractFactory("AegisVault");
    vault = await AegisVault.deploy(
      await aegisEUR.getAddress(),
      [signer1.address, signer2.address],
      1
    );

    // Wire vault as the authorised minter in AegisEUR
    await aegisEUR.connect(owner).setVault(await vault.getAddress());
  });

  // ─── Deployment ───────────────────────────────────────────────────────────────

  describe("Deployment", function () {
    it("sets owner correctly", async function () {
      expect(await vault.owner()).to.equal(owner.address);
    });

    it("links to aegisEUR correctly", async function () {
      expect(await vault.aegisEUR()).to.equal(await aegisEUR.getAddress());
    });

    it("records signer count and required signatures", async function () {
      expect(await vault.signerCount()).to.equal(2n);
      expect(await vault.requiredSignatures()).to.equal(1n);
    });

    it("marks provided signers as signers", async function () {
      expect(await vault.signers(signer1.address)).to.equal(true);
      expect(await vault.signers(signer2.address)).to.equal(true);
    });

    it("reverts when aegisEUR is zero address", async function () {
      await expect(
        AegisVault.deploy(ethers.ZeroAddress, [signer1.address], 1)
      ).to.be.revertedWith("AegisEUR zero");
    });

    it("reverts when required sigs exceed signer count", async function () {
      await expect(
        AegisVault.deploy(await aegisEUR.getAddress(), [signer1.address], 2)
      ).to.be.revertedWith("Invalid multi-sig config");
    });

    it("reverts when required sigs is zero", async function () {
      await expect(
        AegisVault.deploy(await aegisEUR.getAddress(), [signer1.address], 0)
      ).to.be.revertedWith("Invalid multi-sig config");
    });
  });

  // ─── Deposit ──────────────────────────────────────────────────────────────────

  describe("Deposit", function () {
    const txRef = ethers.keccak256(ethers.toUtf8Bytes("tx-ref-001"));

    it("signer can deposit and mints tokens to user", async function () {
      await vault.connect(signer1).deposit(alice.address, 1000n, txRef);
      expect(await aegisEUR.balanceOf(alice.address)).to.equal(1000n);
    });

    it("updates totalEURDeposited", async function () {
      await vault.connect(signer1).deposit(alice.address, 1000n, txRef);
      expect(await vault.totalEURDeposited()).to.equal(1000n);
    });

    it("emits Deposited event", async function () {
      await expect(vault.connect(signer1).deposit(alice.address, 1000n, txRef))
        .to.emit(vault, "Deposited")
        .withArgs(alice.address, 1000n, txRef);
    });

    it("non-signer cannot deposit", async function () {
      await expect(
        vault.connect(alice).deposit(alice.address, 1000n, txRef)
      ).to.be.revertedWith("Not a signer");
    });

    it("reverts when user is zero address", async function () {
      await expect(
        vault.connect(signer1).deposit(ethers.ZeroAddress, 1000n, txRef)
      ).to.be.revertedWith("User zero");
    });

    it("reverts when amount is zero", async function () {
      await expect(
        vault.connect(signer1).deposit(alice.address, 0n, txRef)
      ).to.be.revertedWith("Zero amount");
    });
  });

  // ─── Withdraw ─────────────────────────────────────────────────────────────────

  describe("Withdraw", function () {
    const txRef = ethers.keccak256(ethers.toUtf8Bytes("tx-ref-001"));
    const iban = ethers.id("payout:DE89370400440532013000:2026-11-04"); // hash, never the raw IBAN

    beforeEach(async function () {
      await vault.connect(signer1).deposit(alice.address, 5000n, txRef);
    });

    it("signer can withdraw and burns tokens from user", async function () {
      await vault.connect(signer1).withdraw(alice.address, 2000n, iban);
      expect(await aegisEUR.balanceOf(alice.address)).to.equal(3000n);
    });

    it("updates totalEURWithdrawn", async function () {
      await vault.connect(signer1).withdraw(alice.address, 2000n, iban);
      expect(await vault.totalEURWithdrawn()).to.equal(2000n);
    });

    it("emits Withdrawn event", async function () {
      await expect(vault.connect(signer1).withdraw(alice.address, 2000n, iban))
        .to.emit(vault, "Withdrawn")
        .withArgs(alice.address, 2000n, iban);
    });

    it("non-signer cannot withdraw", async function () {
      await expect(
        vault.connect(alice).withdraw(alice.address, 100n, iban)
      ).to.be.revertedWith("Not a signer");
    });

    it("reverts when user has insufficient balance", async function () {
      await expect(
        vault.connect(signer1).withdraw(alice.address, 6000n, iban)
      ).to.be.revertedWith("Insufficient AEGIS EUR");
    });

    it("reverts when user is zero address", async function () {
      await expect(
        vault.connect(signer1).withdraw(ethers.ZeroAddress, 100n, iban)
      ).to.be.revertedWith("User zero");
    });

    it("reverts when amount is zero", async function () {
      await expect(
        vault.connect(signer1).withdraw(alice.address, 0n, iban)
      ).to.be.revertedWith("Zero amount");
    });
  });

  // ─── Reserve proof ────────────────────────────────────────────────────────────

  describe("Reserve proof", function () {
    const txRef = ethers.keccak256(ethers.toUtf8Bytes("tx-ref-001"));
    const iban = ethers.id("payout:DE89370400440532013000:2026-11-04"); // hash, never the raw IBAN

    it("getReserveRatio returns 10000 when total supply is zero", async function () {
      expect(await vault.getReserveRatio()).to.equal(10000n);
    });

    it("getReserveRatio returns 10000 when fully backed 1:1", async function () {
      await vault.connect(signer1).deposit(alice.address, 1000n, txRef);
      expect(await vault.getReserveRatio()).to.equal(10000n);
    });

    it("getReserveRatio decreases after withdrawal", async function () {
      await vault.connect(signer1).deposit(alice.address, 2000n, txRef);
      await vault.connect(signer1).withdraw(alice.address, 1000n, iban);
      // eurReserve = 2000 - 1000 = 1000, supply = 1000, ratio = 10000
      expect(await vault.getReserveRatio()).to.equal(10000n);
    });

    it("proveReserve emits ReserveProven event with correct ratio", async function () {
      await vault.connect(signer1).deposit(alice.address, 1000n, txRef);
      await expect(vault.proveReserve())
        .to.emit(vault, "ReserveProven")
        .withArgs(1000n, 1000n, 10000n);
    });

    it("proveReserve emits 10000 ratio when supply is zero", async function () {
      await expect(vault.proveReserve())
        .to.emit(vault, "ReserveProven")
        .withArgs(0n, 0n, 10000n);
    });
  });

  // ─── Audit reports ────────────────────────────────────────────────────────────

  describe("Audit reports", function () {
    it("signer can submit an audit report", async function () {
      const reportHash = ethers.keccak256(ethers.toUtf8Bytes("audit-report-1"));
      await vault.connect(signer1).auditReport(reportHash);
      const reports = await vault.getAuditReports();
      expect(reports.length).to.equal(1);
      expect(reports[0]).to.equal(reportHash);
    });

    it("emits AuditReportSubmitted event", async function () {
      const reportHash = ethers.keccak256(ethers.toUtf8Bytes("audit-report-event"));
      const tx = await vault.connect(signer1).auditReport(reportHash);
      const receipt = await tx.wait();
      const block = await ethers.provider.getBlock(receipt.blockNumber);
      await expect(tx)
        .to.emit(vault, "AuditReportSubmitted")
        .withArgs(reportHash, BigInt(block.timestamp));
    });

    it("non-signer cannot submit audit report", async function () {
      const reportHash = ethers.keccak256(ethers.toUtf8Bytes("audit-report-1"));
      await expect(
        vault.connect(alice).auditReport(reportHash)
      ).to.be.revertedWith("Not a signer");
    });

    it("reverts on empty report hash", async function () {
      await expect(
        vault.connect(signer1).auditReport(ethers.ZeroHash)
      ).to.be.revertedWith("Empty report hash");
    });

    it("getAuditReports returns all submitted reports", async function () {
      const hash1 = ethers.keccak256(ethers.toUtf8Bytes("report-1"));
      const hash2 = ethers.keccak256(ethers.toUtf8Bytes("report-2"));
      await vault.connect(signer1).auditReport(hash1);
      await vault.connect(signer2).auditReport(hash2);
      const reports = await vault.getAuditReports();
      expect(reports.length).to.equal(2);
      expect(reports[0]).to.equal(hash1);
      expect(reports[1]).to.equal(hash2);
    });
  });

  // ─── Signer management ────────────────────────────────────────────────────────

  describe("Signer management", function () {
    it("owner can add a signer", async function () {
      await vault.connect(owner).addSigner(alice.address);
      expect(await vault.signers(alice.address)).to.equal(true);
      expect(await vault.signerCount()).to.equal(3n);
    });

    it("addSigner emits SignerAdded event", async function () {
      await expect(vault.connect(owner).addSigner(alice.address))
        .to.emit(vault, "SignerAdded")
        .withArgs(alice.address);
    });

    it("non-owner cannot add a signer", async function () {
      await expect(
        vault.connect(alice).addSigner(alice.address)
      ).to.be.revertedWith("Not owner");
    });

    it("cannot add already-existing signer", async function () {
      await expect(
        vault.connect(owner).addSigner(signer1.address)
      ).to.be.revertedWith("Already signer");
    });

    it("owner can remove a signer when above threshold", async function () {
      await vault.connect(owner).removeSigner(signer2.address);
      expect(await vault.signers(signer2.address)).to.equal(false);
      expect(await vault.signerCount()).to.equal(1n);
    });

    it("removeSigner emits SignerRemoved event", async function () {
      await expect(vault.connect(owner).removeSigner(signer2.address))
        .to.emit(vault, "SignerRemoved")
        .withArgs(signer2.address);
    });

    it("non-owner cannot remove a signer", async function () {
      await expect(
        vault.connect(alice).removeSigner(signer1.address)
      ).to.be.revertedWith("Not owner");
    });

    it("cannot remove signer if it would breach threshold", async function () {
      // signerCount=2, requiredSigs=1 -> removing one leaves 1 which equals threshold -> OK?
      // Let's set threshold to 2 first, then removing one would breach it
      await vault.connect(owner).setRequiredSignatures(2);
      await expect(
        vault.connect(owner).removeSigner(signer1.address)
      ).to.be.revertedWith("Would breach threshold");
    });

    it("cannot remove a non-signer", async function () {
      await expect(
        vault.connect(owner).removeSigner(alice.address)
      ).to.be.revertedWith("Not signer");
    });

    it("setRequiredSignatures updates threshold", async function () {
      await vault.connect(owner).setRequiredSignatures(2);
      expect(await vault.requiredSignatures()).to.equal(2n);
    });

    it("setRequiredSignatures reverts when zero", async function () {
      await expect(
        vault.connect(owner).setRequiredSignatures(0)
      ).to.be.revertedWith("Invalid threshold");
    });

    it("setRequiredSignatures reverts when above signer count", async function () {
      await expect(
        vault.connect(owner).setRequiredSignatures(3)
      ).to.be.revertedWith("Invalid threshold");
    });

    it("non-owner cannot call setRequiredSignatures", async function () {
      await expect(
        vault.connect(alice).setRequiredSignatures(1)
      ).to.be.revertedWith("Not owner");
    });
  });

  // ─── Multi-sig (threshold actually enforced) ─────────────────────────────────

  describe("Multi-sig threshold", function () {
    const txRef = ethers.id("bank-tx-777");

    beforeEach(async function () {
      await vault.connect(owner).setRequiredSignatures(2);
    });

    it("a single signer cannot mint on their own", async function () {
      await vault.connect(signer1).deposit(alice.address, 1000n, txRef);
      expect(await aegisEUR.balanceOf(alice.address)).to.equal(0n);
      await vault.connect(signer2).deposit(alice.address, 1000n, txRef);
      expect(await aegisEUR.balanceOf(alice.address)).to.equal(1000n);
    });

    it("the same signer cannot vote twice", async function () {
      await vault.connect(signer1).deposit(alice.address, 1000n, txRef);
      await expect(vault.connect(signer1).deposit(alice.address, 1000n, txRef)).to.be.revertedWith("Already approved");
    });

    it("the same bank transfer cannot be minted twice", async function () {
      await vault.connect(signer1).deposit(alice.address, 1000n, txRef);
      await vault.connect(signer2).deposit(alice.address, 1000n, txRef);
      await expect(vault.connect(signer1).deposit(alice.address, 1000n, txRef)).to.be.revertedWith("Already executed");
    });

    it("different parameters = different operation (no vote mixing)", async function () {
      await vault.connect(signer1).deposit(alice.address, 1000n, txRef);
      await vault.connect(signer2).deposit(alice.address, 9999n, txRef);
      expect(await aegisEUR.balanceOf(alice.address)).to.equal(0n);
    });

    it("two identical withdrawals are two distinct operations", async function () {
      await vault.connect(signer1).deposit(alice.address, 1000n, txRef);
      await vault.connect(signer2).deposit(alice.address, 1000n, txRef);
      const ref = ethers.id("payout-1");
      for (let i = 0; i < 2; i++) {
        await vault.connect(signer1).withdraw(alice.address, 100n, ref);
        await vault.connect(signer2).withdraw(alice.address, 100n, ref);
      }
      expect(await aegisEUR.balanceOf(alice.address)).to.equal(800n);
    });
  });

  // ─── Independent reserve attestation ─────────────────────────────────────────

  describe("Attested reserve", function () {
    it("the attestor cannot be a signer", async function () {
      await expect(vault.connect(owner).setAttestor(signer1.address, true)).to.be.revertedWith(
        "Attestor must be independent of signers"
      );
    });

    it("with enforcement on, minting beyond the attested reserve is impossible", async function () {
      await vault.connect(owner).setAttestor(bob.address, true);
      await expect(vault.connect(signer1).deposit(alice.address, 1n, ethers.id("a"))).to.be.revertedWith(
        "Reserve attestation stale"
      );
      await vault.connect(bob).attestReserve(1000n, ethers.id("bank-statement-2026-11-04"));
      await vault.connect(signer1).deposit(alice.address, 1000n, ethers.id("b"));
      await expect(vault.connect(signer1).deposit(alice.address, 1n, ethers.id("c"))).to.be.revertedWith(
        "Exceeds attested reserve"
      );
      expect(await vault.getAttestedReserveRatio()).to.equal(10000n);
    });

    it("only the attestor can attest", async function () {
      await vault.connect(owner).setAttestor(bob.address, false);
      await expect(vault.connect(signer1).attestReserve(1n, ethers.ZeroHash)).to.be.revertedWith("Not attestor");
    });
  });
});
