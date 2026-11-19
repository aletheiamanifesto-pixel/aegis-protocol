// Deploy a bb-generated UltraHonk verifier: first its external libraries
// (RelationsLib, ZKTranscriptLib), then the linked contract.
export async function deployHonkVerifier(ethers, name) {
  const file = `contracts/verifiers/${name}.sol`;
  const libraries = {};
  for (const lib of ["RelationsLib", "ZKTranscriptLib"]) {
    const l = await (await ethers.getContractFactory(`${file}:${lib}`)).deploy();
    await l.waitForDeployment();
    libraries[lib] = await l.getAddress();
  }
  const v = await (await ethers.getContractFactory(`${file}:${name}`, { libraries })).deploy();
  await v.waitForDeployment();
  return v;
}
