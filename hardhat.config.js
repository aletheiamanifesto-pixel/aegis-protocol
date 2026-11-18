require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

// Offline builds: set SOLCJS_PATH to a local soljson.js (npm package "solc")
// to skip downloading the compiler from binaries.soliditylang.org.
if (process.env.SOLCJS_PATH) {
  const { subtask } = require("hardhat/config");
  const { TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD } = require("hardhat/builtin-tasks/task-names");
  subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD, async (args, hre, runSuper) => {
    if (args.solcVersion !== "0.8.26") return runSuper();
    return {
      compilerPath: process.env.SOLCJS_PATH,
      isSolcJs: true,
      version: args.solcVersion,
      longVersion: args.solcVersion,
    };
  });
}

const RPC_URL = process.env.RPC_URL || "https://rpc-amoy.polygon.technology";
const DEPLOYER_PRIVATE_KEY = process.env.DEPLOYER_PRIVATE_KEY
  ? [process.env.DEPLOYER_PRIVATE_KEY]
  : [];

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.26",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    amoy: {
      url: RPC_URL,
      chainId: 80002,
      accounts: DEPLOYER_PRIVATE_KEY,
    },
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL || "https://rpc.sepolia.org",
      chainId: 11155111,
      accounts: DEPLOYER_PRIVATE_KEY,
    },
    localhost: {
      url: "http://127.0.0.1:8545",
      chainId: 31337,
    },
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },
};
