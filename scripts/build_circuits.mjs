// scripts/build_circuits.mjs — compile the Noir circuits and generate the Solidity verifiers.
//
//   npm run build:circuits
//
// Output:
//   noir_circuits/target/<circuit>.json      ACIR bytecode + ABI (used by the SDK/frontend to prove)
//   noir_circuits/target/<circuit>.vk        verification key
//   contracts/verifiers/<Name>Verifier.sol   UltraHonk verifier (keccak transcript, ZK) for the EVM
//
// Needs internet access the first time (bb.js downloads Aztec's public CRS).
import { compile, createFileManager } from '@noir-lang/noir_wasm';
import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const circuitsDir = path.join(root, 'noir_circuits');
const targetDir = path.join(circuitsDir, 'target');
const verifiersDir = path.join(root, 'contracts', 'verifiers');
const CIRCUITS = { spend: 'Spend', compliance_proof: 'Compliance', balance_proof: 'Balance' };

fs.mkdirSync(targetDir, { recursive: true });
fs.mkdirSync(verifiersDir, { recursive: true });
const api = await Barretenberg.new({ threads: 4 });
try {
  for (const [dir, name] of Object.entries(CIRCUITS)) {
    const { program } = await compile(createFileManager(path.join(circuitsDir, dir)));
    fs.writeFileSync(path.join(targetDir, `${dir}.json`), JSON.stringify(program));
    const backend = new UltraHonkBackend(program.bytecode, api);
    const vk = await backend.getVerificationKey({ verifierTarget: 'evm' });
    fs.writeFileSync(path.join(targetDir, `${dir}.vk`), vk);
    let sol = await backend.getSolidityVerifier(vk, { verifierTarget: 'evm' });
    // Every verifier in its own namespace (the generated contract is always called HonkVerifier).
    sol = sol.replace(/\bHonkVerifier\b/g, `${name}Verifier`);
    fs.writeFileSync(path.join(verifiersDir, `${name}Verifier.sol`), sol);
    console.log(`✓ ${dir} → contracts/verifiers/${name}Verifier.sol`);
  }
} finally {
  await api.destroy();
}
