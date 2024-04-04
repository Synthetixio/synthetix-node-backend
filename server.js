const express = require('express');
const { ethers, JsonRpcProvider, Contract } = require('ethers');
const { address, abi } = require('@vderunov/whitelist-contract/deployments/11155420/Whitelist');
const crypto = require('crypto');
const { promises: fs } = require('fs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const app = express();
require('dotenv').config();
const { createProxyMiddleware } = require('http-proxy-middleware');

const PORT = process.env.PORT || 3005;

const IPFS_HOST = process.env.IPFS_HOST || '127.0.0.1';
const IPFS_PORT = process.env.IPFS_PORT || '5001';
const IPFS_URL = `http://${IPFS_HOST}:${IPFS_PORT}/`;

app.use(cors());
app.use(express.json());

class HttpError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
  }
}

class EthereumContractError extends Error {
  constructor(message, originalError) {
    super(message);
    this.name = 'EthereumContractError';
    this.originalError = originalError;
  }
}

const getEthereumContract = () => {
  try {
    const provider = new JsonRpcProvider('https://sepolia.optimism.io');
    return new Contract(address, abi, provider);
  } catch (err) {
    throw new EthereumContractError('Failed to get Ethereum contract', err);
  }
};

const validateWalletAddress = (req, res, next) => {
  if (!req.body.walletAddress) {
    return next(new HttpError('Missing wallet address', 400));
  }
  if (!ethers.isAddress(req.body.walletAddress)) {
    return next(new HttpError('Invalid wallet address', 400));
  }
  next();
};

const transformWalletAddress = (req, res, next) => {
  req.body.walletAddress = req.body.walletAddress.toLowerCase();
  next();
};

const createNonce = async (req, res, next) => {
  try {
    const hash = crypto.createHash('sha1');
    hash.update(`${req.body.walletAddress}:${process.env.SECRET}`);
    res.status(200).send({ nonce: hash.digest('hex') });
  } catch (err) {
    next(err);
  }
};

app.post('/signup', validateWalletAddress, transformWalletAddress, createNonce);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

const validateVerificationParameters = (req, res, next) => {
  if (!req.body.nonce) {
    return next(new HttpError('Nonce not provided', 400));
  }
  if (!req.body.signedMessage) {
    return next(new HttpError('Signed message not provided', 400));
  }
  next();
};

const getAddressFromMessage = (nonce, signedMessage, next) => {
  try {
    return ethers.verifyMessage(nonce, signedMessage);
  } catch {
    return next(new HttpError('Failed to verify message', 400));
  }
};

const generateNonce = (address) => {
  const checkHash = crypto.createHash('sha1');
  checkHash.update(`${address.toLowerCase()}:${process.env.SECRET}`);
  return checkHash.digest('hex');
};

const verifyMessage = async (req, res, next) => {
  const address = getAddressFromMessage(req.body.nonce, req.body.signedMessage, next);
  const newNonce = generateNonce(address);

  if (req.body.nonce !== newNonce) {
    return next(new HttpError('Nonce mismatch', 400));
  }
  res.locals.address = address;
  next();
};

const createJwtToken = async (walletAddress) => {
  return new Promise((resolve, reject) => {
    jwt.sign({ walletAddress }, process.env.JWT_SECRET_KEY, { expiresIn: '1d' }, (err, token) => {
      if (err) reject(err);
      resolve(token);
    });
  });
};

app.post('/verify', validateVerificationParameters, verifyMessage, async (req, res, next) => {
  try {
    res.status(200).send({ token: await createJwtToken(res.locals.address) });
  } catch (err) {
    next(err);
  }
});

app.use('/api/v0/cat', createProxyMiddleware({ target: IPFS_URL }));

const verifyToken = (req) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1];
  if (token == null) throw new Error('Token is missing');

  return new Promise((resolve, reject) => {
    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
      if (err) reject(err);
      resolve(decoded);
    });
  });
};

const authenticateToken = async (req, res, next) => {
  try {
    const decoded = await verifyToken(req);
    const contract = await getEthereumContract();
    if (!(await contract.isGranted(decoded.walletAddress))) {
      return res.sendStatus(401);
    }
    next();
  } catch (err) {
    if (err.message === 'Token is missing') return res.sendStatus(401);
    if (err instanceof jwt.JsonWebTokenError) return res.sendStatus(403);
    if (err instanceof EthereumContractError) return res.status(500).send(err.message);
    return res.status(500).send(err);
  }
};

app.get('/protected', authenticateToken, (req, res) => {
  res.send('Hello! You are viewing protected content.');
});

app.use('/api/v0/add', authenticateToken, createProxyMiddleware({ target: IPFS_URL }));

app.use((err, req, res, next) => {
  const status = err.code || 500;
  const message = err.message || 'Something went wrong';
  res.status(status).send(message);
});
