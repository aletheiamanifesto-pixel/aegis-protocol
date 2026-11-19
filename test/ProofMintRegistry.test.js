import { expect } from "chai";
import { network } from "hardhat";

const { ethers, networkHelpers } = await network.create();

describe("ProofMintRegistry", function () {
  let registry;
  let owner, brand, auditor, other;

  beforeEach(async function () {
    [owner, brand, auditor, other] = await ethers.getSigners();
    const ProofMintRegistry = await ethers.getContractFactory("ProofMintRegistry");
    registry = await ProofMintRegistry.deploy(owner.address);

    await registry.grantRole(await registry.BRAND_ROLE(), brand.address);
    await registry.grantRole(await registry.AUDITOR_ROLE(), auditor.address);
  });

  it("creates a passport and tracks product history", async function () {
    const hash = ethers.keccak256(ethers.toUtf8Bytes("dpp-v1"));
    await expect(registry.connect(brand).createPassport("SKU-001", hash, "cid-v1"))
      .to.emit(registry, "PassportCreated");

    const passport = await registry.passports(1);
    expect(passport.productId).to.equal("SKU-001");
    expect(passport.version).to.equal(1n);
    expect(passport.active).to.equal(true);

    const historyId = await registry.productHistory("SKU-001", 0);
    expect(historyId).to.equal(1n);
  });

  it("updates passport version and verification state", async function () {
    const v1 = ethers.keccak256(ethers.toUtf8Bytes("dpp-v1"));
    const v2 = ethers.keccak256(ethers.toUtf8Bytes("dpp-v2"));

    await registry.connect(brand).createPassport("SKU-001", v1, "cid-v1");
    await expect(registry.connect(brand).updatePassport(1, v2, "cid-v2"))
      .to.emit(registry, "PassportUpdated");

    const passport = await registry.passports(1);
    expect(passport.version).to.equal(2n);
    expect(passport.ipfsCid).to.equal("cid-v2");

    expect(await registry.verifyPassport(1, v2)).to.equal(true);
    expect(await registry.verifyPassport(1, v1)).to.equal(false);

    const historyV2 = await registry.productHistory("SKU-001", 1);
    expect(historyV2).to.equal(1n);
  });

  it("allows brand and auditor to revoke", async function () {
    const hash = ethers.keccak256(ethers.toUtf8Bytes("dpp-v1"));
    await registry.connect(brand).createPassport("SKU-001", hash, "cid-v1");

    await expect(registry.connect(auditor).revokePassport(1))
      .to.emit(registry, "PassportRevoked");

    expect(await registry.verifyPassport(1, hash)).to.equal(false);
  });

  it("prevents non-brand create and non-owner update", async function () {
    const hash = ethers.keccak256(ethers.toUtf8Bytes("dpp-v1"));
    await expect(
      registry.connect(other).createPassport("SKU-001", hash, "cid-v1")
    ).to.revert(ethers);

    await registry.connect(brand).createPassport("SKU-001", hash, "cid-v1");
    await expect(
      registry.connect(other).updatePassport(1, hash, "cid-v2")
    ).to.revert(ethers);
  });
});
