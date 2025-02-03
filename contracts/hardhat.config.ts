import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
require("dotenv").config();
import "hardhat-contract-sizer";
import "@nomicfoundation/hardhat-ignition-ethers";
import 'solidity-coverage';
import "hardhat-gas-reporter";
import "hardhat-contract-sizer";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.28",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
        details: {
          yul: true
        }
      },
      metadata: {
        bytecodeHash: "none"
      },
      viaIR: false,
    },
  },
  contractSizer: {
    runOnCompile: true,
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  },
  defaultNetwork: "hardhat",
  networks: {
    localhost: {
      url: "http://127.0.0.1:8545",
      accounts: ["0xdf57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e"]
    },
    // goerli: {
    //   url: "https://eth-goerli.public.blastapi.io",
    //   accounts: [process.env.PKEY as string],
    // },
    // polygon: {
    //   url: process.env.POLYGON_RPC_URL || "https://polygon.llamarpc.com",
    //   accounts: [process.env.PKEY as string],
    // },
    // mumbai: {
    //   url: process.env.MUMBAI_RPC_URL || "https://polygon-mumbai-bor.publicnode.com",
    //   accounts: [process.env.PKEY as string],
    // },
    // sepolia: {
    //   url: process.env.SEPOLIA_RPC_URL || "https://eth-sepolia.public.blastapi.io",
    //   accounts: [process.env.PKEY as string],
    //   gasPrice: 6 * 10 ** 9, 
    // },
    // optimismSepolia: {
    //   url: process.env.OPTIMISM_SEPOLIA_RPC_URL || "https://sepolia.optimism.io",
    //   accounts: [process.env.PKEY as string],
    //   gasPrice: 5 * 10 ** 9, // Optimism uses a different gas mechanism, set to 0 for automatic handling
    // },
    // optimism: {
    //   url: process.env.OPTIMISM_RPC_URL || "https://mainnet.optimism.io",
    //   accounts: [process.env.PKEY as string],
    // }
  },
  etherscan: {
    apiKey: {
      sepolia: process.env.ETHERSCAN_API_KEY as string,
      ethereum: process.env.ETHERSCAN_API_KEY as string,
      optimism: process.env.OPTIMISMSCAN_API_KEY as string
    }
  }
};

export default config;