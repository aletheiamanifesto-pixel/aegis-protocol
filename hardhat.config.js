require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

const RPC_URL = process.env.RPC_URL || "https://rpc-amoy.polygon.technology";
const DEPLOYER_PRIVATE_KEY = process.env.DEPLOYER_PRIVATE_KEY
  ? [process.env.DEPLOYER_PRIVATE_KEY]
  : [];

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.20",
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
