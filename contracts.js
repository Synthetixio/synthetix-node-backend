const { JsonRpcProvider, Contract } = require('ethers');
const Whitelist = require('@synthetixio/synthetix-node-namespace/deployments/11155420/Whitelist');
const Namespace = require('@synthetixio/synthetix-node-namespace/deployments/11155420/Namespace');

class EthereumContractError extends Error {
  constructor(message, originalError) {
    super(message);
    this.name = 'EthereumContractError';
    this.originalError = originalError;
  }
}

const getContract = (address, abi) => {
  try {
    const provider = new JsonRpcProvider('https://sepolia.optimism.io');
    return new Contract(address, abi, provider);
  } catch (err) {
    throw new EthereumContractError('Failed to get contract', err);
  }
};

const getNamespaceContract = () => getContract(Namespace.address, Namespace.abi);
const getWhitelistContract = () => getContract(Whitelist.address, Whitelist.abi);

module.exports = {
  getNamespaceContract,
  getWhitelistContract,
};
