import { expect } from "chai";
import { network } from "hardhat";

const { ethers, networkHelpers } = await network.create();

// ─── Merkle helpers ───────────────────────────────────────────────────────────
// The contract uses canonical (sorted) ordering: smaller node goes left before hashing.

function canonicalHash(a, b) {
  // Sort lexicographically so smaller value is on the left
  if (a <= b) {
    return ethers.keccak256(ethers.concat([a, b]));
  } else {
    return ethers.keccak256(ethers.concat([b, a]));
  }
}

/**
 * Build a Merkle root from an array of bytes32 leaf hashes.
 * Returns { root, proofs } where proofs[i] is the sibling path for leaf i.
 * Supports any number of leaves; odd layers duplicate the last node.
 */
function buildMerkleTree(leaves) {
  if (leaves.length === 0) throw new Error("No leaves");
  if (leaves.length === 1) {
    return { root: leaves[0], proofs: [[]] };
  }

  const layers = [leaves.slice()];
  while (layers[layers.length - 1].length > 1) {
    const prev = layers[layers.length - 1];
    const next = [];
    for (let i = 0; i < prev.length; i += 2) {
      const left = prev[i];
      const right = i + 1 < prev.length ? prev[i + 1] : prev[i];
      next.push(canonicalHash(left, right));
    }
    layers.push(next);
  }

  const root = layers[layers.length - 1][0];

  // Build proofs for each leaf
  const proofs = leaves.map((_, idx) => {
    const path = [];
    let index = idx;
    for (let l = 0; l < layers.length - 1; l++) {
      const layer = layers[l];
      const siblingIdx = index % 2 === 0 ? index + 1 : index - 1;
      if (siblingIdx < layer.length) {
        path.push(layer[siblingIdx]);
      } else {
        path.push(layer[index]); // duplicate last node
      }
      index = Math.floor(index / 2);
    }
    return path;
  });

  return { root, proofs };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("AegisBundleVerifier", function () {
  let AegisBundleVerifier, bundleVerifier;
  let owner, submitter, alice;

  beforeEach(async function () {
    [owner, submitter, alice] = await ethers.getSigners();
    AegisBundleVerifier = await ethers.getContractFactory("AegisBundleVerifier");
    bundleVerifier = await AegisBundleVerifier.deploy();
    // Since the access-control hardening, only authorized submitters can submit bundles.
    await bundleVerifier.connect(owner).addSubmitter(submitter.address);
  });

  // Helper: create deterministic ids
  function bundleId(seed) {
    return ethers.keccak256(ethers.toUtf8Bytes(`bundle-${seed}`));
  }
  function txLeaf(seed) {
    return ethers.keccak256(ethers.toUtf8Bytes(`tx-${seed}`));
  }

  // ─── Submit bundle ──────────────────────────────────────────────────────────

  describe("submitBundle", function () {
    it("stores bundle fields correctly", async function () {
      const id = bundleId("A");
      const leaf = txLeaf("1");
      const merkleRoot = leaf; // single-leaf root
      const txCount = 1n;
      const totalAmount = 500n;

      const tx = await bundleVerifier.connect(submitter).submitBundle(id, merkleRoot, txCount, totalAmount);
      const receipt = await tx.wait();
      const block = await ethers.provider.getBlock(receipt.blockNumber);

      const stored = await bundleVerifier.bundles(id);
      expect(stored.merkleRoot).to.equal(merkleRoot);
      expect(stored.txCount).to.equal(txCount);
      expect(stored.totalAmount).to.equal(totalAmount);
      expect(stored.timestamp).to.equal(BigInt(block.timestamp));
      expect(stored.submitter).to.equal(submitter.address);
    });

    it("emits BundleSubmitted event", async function () {
      const id = bundleId("B");
      const root = txLeaf("2");
      await expect(
        bundleVerifier.connect(submitter).submitBundle(id, root, 1n, 100n)
      )
        .to.emit(bundleVerifier, "BundleSubmitted")
        .withArgs(id, root, 1n, 100n, submitter.address);
    });

    it("marks merkle root as processed", async function () {
      const id = bundleId("C");
      const root = txLeaf("3");
      await bundleVerifier.connect(submitter).submitBundle(id, root, 1n, 100n);
      expect(await bundleVerifier.processedRoots(root)).to.equal(true);
    });

    it("rejects duplicate bundleId", async function () {
      const id = bundleId("D");
      const root1 = txLeaf("4");
      const root2 = txLeaf("5");
      await bundleVerifier.connect(submitter).submitBundle(id, root1, 1n, 100n);
      await expect(
        bundleVerifier.connect(submitter).submitBundle(id, root2, 1n, 200n)
      ).to.be.revertedWithCustomError(bundleVerifier, "BundleAlreadyExists");
    });

    it("rejects duplicate merkle root", async function () {
      const id1 = bundleId("E1");
      const id2 = bundleId("E2");
      const root = txLeaf("6");
      await bundleVerifier.connect(submitter).submitBundle(id1, root, 1n, 100n);
      await expect(
        bundleVerifier.connect(submitter).submitBundle(id2, root, 1n, 100n)
      ).to.be.revertedWithCustomError(bundleVerifier, "MerkleRootAlreadyProcessed");
    });
  });

  // ─── Verify transaction ─────────────────────────────────────────────────────

  describe("verifyTransaction", function () {
    it("single leaf: leaf itself is root, empty proof verifies true", async function () {
      const id = bundleId("single");
      const leaf = txLeaf("only");
      // For single leaf, root = leaf, proof = []
      await bundleVerifier.connect(submitter).submitBundle(id, leaf, 1n, 100n);
      expect(
        await bundleVerifier.verifyTransaction(id, leaf, [], [])
      ).to.equal(true);
    });

    it("two-leaf bundle: correct Merkle proof verifies true", async function () {
      const leaves = [txLeaf("a"), txLeaf("b")];
      const { root, proofs } = buildMerkleTree(leaves);

      const id = bundleId("two-leaf");
      await bundleVerifier.connect(submitter).submitBundle(id, root, 2n, 200n);

      // Verify leaf 0
      const proof0 = proofs[0];
      const positions0 = proof0.map(() => false); // positions ignored by contract
      expect(
        await bundleVerifier.verifyTransaction(id, leaves[0], proof0, positions0)
      ).to.equal(true);

      // Verify leaf 1
      const proof1 = proofs[1];
      const positions1 = proof1.map(() => false);
      expect(
        await bundleVerifier.verifyTransaction(id, leaves[1], proof1, positions1)
      ).to.equal(true);
    });

    it("four-leaf bundle: all leaves verify correctly", async function () {
      const leaves = [txLeaf("1"), txLeaf("2"), txLeaf("3"), txLeaf("4")];
      const { root, proofs } = buildMerkleTree(leaves);

      const id = bundleId("four-leaf");
      await bundleVerifier.connect(submitter).submitBundle(id, root, 4n, 400n);

      for (let i = 0; i < leaves.length; i++) {
        const positions = proofs[i].map(() => false);
        expect(
          await bundleVerifier.verifyTransaction(id, leaves[i], proofs[i], positions)
        ).to.equal(true, `leaf ${i} should verify`);
      }
    });

    it("incorrect proof returns false", async function () {
      const leaves = [txLeaf("x"), txLeaf("y")];
      const { root, proofs } = buildMerkleTree(leaves);

      const id = bundleId("wrong-proof");
      await bundleVerifier.connect(submitter).submitBundle(id, root, 2n, 200n);

      const badProof = [ethers.keccak256(ethers.toUtf8Bytes("wrong-sibling"))];
      expect(
        await bundleVerifier.verifyTransaction(id, leaves[0], badProof, [false])
      ).to.equal(false);
    });

    it("wrong leaf returns false", async function () {
      const leaves = [txLeaf("p"), txLeaf("q")];
      const { root, proofs } = buildMerkleTree(leaves);

      const id = bundleId("wrong-leaf");
      await bundleVerifier.connect(submitter).submitBundle(id, root, 2n, 200n);

      const wrongLeaf = txLeaf("not-in-bundle");
      const positions = proofs[0].map(() => false);
      expect(
        await bundleVerifier.verifyTransaction(id, wrongLeaf, proofs[0], positions)
      ).to.equal(false);
    });

    it("reverts for non-existent bundle", async function () {
      const nonExistentId = bundleId("ghost");
      await expect(
        bundleVerifier.verifyTransaction(nonExistentId, txLeaf("x"), [], [])
      ).to.be.revertedWithCustomError(bundleVerifier, "BundleNotFound");
    });

    it("reverts when proof and positions arrays have different lengths", async function () {
      const id = bundleId("mismatch");
      const leaf = txLeaf("m");
      await bundleVerifier.connect(submitter).submitBundle(id, leaf, 1n, 100n);

      const proof = [ethers.keccak256(ethers.toUtf8Bytes("extra"))];
      const positions = []; // mismatch: proof.length=1, positions.length=0
      await expect(
        bundleVerifier.verifyTransaction(id, leaf, proof, positions)
      ).to.be.revertedWithCustomError(bundleVerifier, "InvalidProofLength");
    });
  });

  // ─── Canonical ordering ─────────────────────────────────────────────────────

  describe("Canonical ordering", function () {
    it("proofPositions values are irrelevant — canonical sorting always applied", async function () {
      const leaves = [txLeaf("left"), txLeaf("right")];
      const { root, proofs } = buildMerkleTree(leaves);

      const id = bundleId("canonical");
      await bundleVerifier.connect(submitter).submitBundle(id, root, 2n, 200n);

      // Verify leaf[0] with proofPositions = [true] (contract ignores it)
      expect(
        await bundleVerifier.verifyTransaction(id, leaves[0], proofs[0], [true])
      ).to.equal(true);

      // Verify leaf[1] with proofPositions = [false] (contract ignores it)
      expect(
        await bundleVerifier.verifyTransaction(id, leaves[1], proofs[1], [false])
      ).to.equal(true);
    });
  });
});
