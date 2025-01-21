const express = require('express');
const cp = require('node:child_process');
const { ethers, JsonRpcProvider, Contract } = require('ethers');
const { address, abi } = require('@vderunov/whitelist-contract/deployments/11155420/Whitelist');
const crypto = require('node:crypto');
const cors = require('cors');
const { Namespace: NamespaceAddress } = require('./namespace/11155420/deployments.json');
const NamespaceAbi = require('./namespace/11155420/Namespace.json');
const Multicall3 = require('./Multicall3/11155420/Multicall3');
const Gun = require('gun');
const jwt = require('jsonwebtoken');
const app = express();
require('dotenv').config();
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');

const PORT = process.env.PORT || 3005;

const IPFS_HOST = process.env.IPFS_HOST || '127.0.0.1';
const IPFS_PORT = process.env.IPFS_PORT || '5001';
const IPFS_URL = `http://${IPFS_HOST}:${IPFS_PORT}/`;
const GRAPH_API_ENDPOINT =
  'https://api.studio.thegraph.com/query/71164/vd-practice-v1/version/latest';

const state = {
  peers: [],
  uptime: 0,
  numObjects: 0,
  repoSize: 0,
  totalIn: 0,
  totalOut: 0,
  dailyIn: 0,
  hourlyIn: 0,
  dailyOut: 0,
  hourlyOut: 0,
};

app.use(cors());
app.use(express.json());

app.get('/api', (_req, res) => {
  res.status(200).json(state);
});

async function updateStats() {
  try {
    const { RepoSize: repoSize, NumObjects: numObjects } = await (
      await fetch(`${IPFS_URL}api/v0/repo/stat`, { method: 'POST' })
    ).json();
    Object.assign(state, { repoSize, numObjects });
  } catch (e) {
    console.error(e);
  }

  try {
    const { TotalIn: totalIn, TotalOut: totalOut } = await (
      await fetch(`${IPFS_URL}api/v0/stats/bw`, { method: 'POST' })
    ).json();
    Object.assign(state, { totalIn, totalOut });
  } catch (e) {
    console.error(e);
  }

  const [pid] = await new Promise((resolve) =>
    cp.exec('pgrep -f "ipfs daemon"', (err, stdout, stderr) => {
      if (err) {
        console.error(err);
        return resolve(null);
      }
      if (stderr) {
        console.error(new Error(stderr));
        return resolve(null);
      }
      return resolve(
        stdout
          .split('\n')
          .map((s) => s.trim())
          .filter(Boolean)
      );
    })
  );
  if (!pid) {
    return;
  }

  const uptime = await new Promise((resolve) =>
    cp.exec(`ps -p ${pid} -o lstart=`, (err, stdout, stderr) => {
      if (err) {
        console.error(err);
        return resolve(null);
      }
      if (stderr) {
        console.error(new Error(stderr));
        return resolve(null);
      }
      const startDate = new Date(stdout);
      const uptimeInSeconds = Math.floor((Date.now() - startDate.getTime()) / 1000);
      return resolve(uptimeInSeconds);
    })
  );
  if (!uptime) {
    return;
  }
  Object.assign(state, { uptime });

  const uptimeHours = uptime / (60 * 60);
  const uptimeDays = uptimeHours / 24;
  const dailyIn = state.totalIn / uptimeDays;
  const hourlyIn = state.totalIn / uptimeHours;
  const dailyOut = state.totalOut / uptimeDays;
  const hourlyOut = state.totalOut / uptimeHours;
  Object.assign(state, { dailyIn, hourlyIn, dailyOut, hourlyOut });
}

async function updatePeers() {
  const peers = await new Promise((resolve) =>
    cp.exec("ipfs-cluster-ctl --enc=json peers ls | jq '[inputs]'", (err, stdout, stderr) => {
      if (err) {
        console.error(err);
        return resolve([]);
      }
      if (stderr) {
        console.error(new Error(stderr));
        return resolve([]);
      }
      try {
        const result = JSON.parse(stdout);
        return resolve(
          result
            .map(({ id, version }) => ({ id, version }))
            .sort((a, b) => a.id.localeCompare(b.id))
        );
      } catch (_e) {
        return resolve([]);
      }
    })
  );
  Object.assign(state, { peers });
}

setInterval(updatePeers, 60_000);
setInterval(updateStats, 60_000);

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

const getMulticall3Contract = () => {
  try {
    const provider = new JsonRpcProvider('https://sepolia.optimism.io');
    return new Contract(Multicall3.address, Multicall3.abi, provider);
  } catch (err) {
    throw new EthereumContractError('Failed to get Multicall3 contract', err);
  }
};

const getNamespaceContract = () => {
  try {
    const provider = new JsonRpcProvider('https://sepolia.optimism.io');
    return new Contract(NamespaceAddress, NamespaceAbi, provider);
  } catch (err) {
    throw new EthereumContractError('Failed to get Namespace contract', err);
  }
};

const getWhitelistContract = () => {
  try {
    const provider = new JsonRpcProvider('https://sepolia.optimism.io');
    return new Contract(address, abi, provider);
  } catch (err) {
    throw new EthereumContractError('Failed to get Whitelist contract', err);
  }
};

const validateWalletAddress = (req, _res, next) => {
  if (!req.body.walletAddress) {
    return next(new HttpError('Missing wallet address', 400));
  }
  if (!ethers.isAddress(req.body.walletAddress)) {
    return next(new HttpError('Invalid wallet address', 400));
  }
  next();
};

const transformWalletAddress = (req, _res, next) => {
  req.body.walletAddress = req.body.walletAddress.toLowerCase();
  next();
};

const generateNonce = (address) => {
  const checkHash = crypto.createHash('sha1');
  checkHash.update(`${address.toLowerCase()}:${process.env.SECRET}`);
  return checkHash.digest('hex');
};

const createNonce = async (req, res, next) => {
  try {
    res.status(200).send({ nonce: generateNonce(req.body.walletAddress) });
  } catch (err) {
    next(err);
  }
};

app.post('/signup', validateWalletAddress, transformWalletAddress, createNonce);

const server = app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  Promise.all([updateStats(), updatePeers()]);
});
const gun = Gun({ web: server });

const validateVerificationParameters = (req, _res, next) => {
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
    jwt.sign({ walletAddress }, process.env.JWT_SECRET_KEY, {}, (err, token) => {
      if (err) reject(err);
      resolve(token);
    });
  });
};

const saveTokenToGun = (walletAddress, token) => {
  return new Promise((resolve, reject) => {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    gun
      .get('tokens')
      .get(walletAddress.toLowerCase())
      .put(tokenHash, (ack) => {
        if (ack.err) {
          reject(new HttpError('Failed to save token to Gun'));
        } else {
          resolve();
        }
      });
  });
};

app.post('/verify', validateVerificationParameters, verifyMessage, async (_req, res, next) => {
  try {
    const token = await createJwtToken(res.locals.address);
    await saveTokenToGun(res.locals.address, token);
    res.status(200).send({ token });
  } catch (err) {
    next(err);
  }
});

app.use(
  '/api/v0/cat',
  createProxyMiddleware({
    target: `${IPFS_URL}/api/v0/cat`,
    pathRewrite: {
      '^/': '',
    },
  })
);

const verifyToken = (req) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1];
  if (token == null) throw new HttpError('Unauthorized', 401);

  return new Promise((resolve, reject) => {
    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
      if (err) reject(new HttpError('Forbidden', 403));
      resolve(decoded);
    });
  });
};

const validateTokenWithGun = (walletAddress, token) => {
  return new Promise((resolve, reject) => {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    gun
      .get('tokens')
      .get(walletAddress.toLowerCase())
      .once((tokenData) => {
        if (!tokenData || tokenData !== tokenHash) {
          reject(new HttpError('Unauthorized', 401));
        } else {
          resolve();
        }
      });
  });
};

const authenticateToken = async (req, _res, next) => {
  try {
    const decoded = await verifyToken(req);
    const contract = await getWhitelistContract();
    if (!(await contract.isGranted(decoded.walletAddress))) {
      throw new HttpError('Unauthorized', 401);
    }
    const token = req.headers.authorization.split(' ')[1];
    await validateTokenWithGun(decoded.walletAddress, token);
    req.user = decoded;
    next();
  } catch (err) {
    next(err);
  }
};

const validateNamespaceOwnership = async (namespace, walletAddress) => {
  if (!namespace) {
    throw new HttpError('Missing namespace parameter', 400);
  }
  const contract = await getNamespaceContract();
  const tokenId = await contract.namespaceToTokenId(namespace);

  if (tokenId === BigInt(0)) {
    throw new HttpError('Namespace not found', 404);
  }
  if ((await contract.ownerOf(tokenId)).toLowerCase() !== walletAddress.toLowerCase()) {
    throw new HttpError('Not namespace owner', 403);
  }
};

const verifyKeyGenNamespace = async (req, _res, next) => {
  try {
    await validateNamespaceOwnership(req.query.arg, req.user.walletAddress);
    next();
  } catch (err) {
    next(err);
  }
};

const verifyNamePublishNamespace = async (req, _res, next) => {
  try {
    await validateNamespaceOwnership(req.query.key, req.user.walletAddress);
    next();
  } catch (err) {
    next(err);
  }
};

app.get('/protected', authenticateToken, (_req, res) => {
  res.send('Hello! You are viewing protected content.');
});

app.use(
  '/api/v0/add',
  authenticateToken,
  createProxyMiddleware({ target: `${IPFS_URL}/api/v0/add` })
);

app.use(
  '/api/v0/key/gen',
  authenticateToken,
  verifyKeyGenNamespace,
  createProxyMiddleware({
    target: `${IPFS_URL}/api/v0/key/gen`,
    pathRewrite: {
      '^/': '',
    },
  })
);

const removeDeploymentFromGun = (walletAddress, name) => {
  return new Promise((resolve, reject) => {
    gun
      .get('deployments')
      .get(walletAddress.toLowerCase())
      .get(name)
      .put(null, (ack) => {
        if (ack.err) {
          reject(new HttpError(`Failed to remove deployment from Gun: ${ack.err}`));
        } else {
          resolve();
        }
      });
  });
};

app.use(
  '/api/v0/key/rm',
  authenticateToken,
  verifyKeyGenNamespace,
  createProxyMiddleware({
    target: `${IPFS_URL}/api/v0/key/rm`,
    pathRewrite: {
      '^/': '',
    },
    selfHandleResponse: true,
    on: {
      proxyRes: responseInterceptor(async (responseBuffer, _proxyRes, req, res) => {
        res.removeHeader('trailer');
        const response = responseBuffer.toString('utf8');
        try {
          if (JSON.parse(response).Message) {
            throw new Error(response);
          }
          await removeDeploymentFromGun(req.user.walletAddress, JSON.parse(response).Keys[0]?.Name);
        } catch (err) {
          console.error('Error removing from Gun:', err);
        }
        return responseBuffer;
      }),
    },
  })
);

const saveDeploymentsToGun = (walletAddress, key, value) => {
  return new Promise((resolve, reject) => {
    gun
      .get('deployments')
      .get(walletAddress.toLowerCase())
      .get(key)
      .put(value, (ack) => {
        if (ack.err) {
          reject(new HttpError(`Failed to save deployment to Gun: ${ack.err}`));
        } else {
          resolve();
        }
      });
  });
};

app.use(
  '/api/v0/name/publish',
  authenticateToken,
  verifyNamePublishNamespace,
  createProxyMiddleware({
    target: `${IPFS_URL}/api/v0/name/publish`,
    pathRewrite: {
      '^/': '',
    },
    selfHandleResponse: true,
    on: {
      proxyRes: responseInterceptor(async (responseBuffer, _proxyRes, req, res) => {
        res.removeHeader('trailer');
        const response = responseBuffer.toString('utf8');
        try {
          await saveDeploymentsToGun(
            req.user.walletAddress,
            req.query.key,
            JSON.parse(response).Name
          );
        } catch (err) {
          console.error('Error saving to Gun:', err.message);
        }
        return responseBuffer;
      }),
    },
  })
);

const authenticateAdmin = async (req, _res, next) => {
  try {
    const decoded = await verifyToken(req);
    const contract = await getWhitelistContract();
    if (!(await contract.isAdmin(decoded.walletAddress))) {
      throw new HttpError('Unauthorized', 401);
    }
    const token = req.headers.authorization.split(' ')[1];
    await validateTokenWithGun(decoded.walletAddress, token);
    next();
  } catch (err) {
    next(err);
  }
};

const fetchApprovedWallets = async () => {
  const response = await fetch(GRAPH_API_ENDPOINT, {
    method: 'POST',
    body: JSON.stringify({
      query: `
    {
      wallets(where: { granted: true }) {
        id
      }
    }
  `,
    }),
    headers: { 'Content-Type': 'application/json' },
  });
  if (!response.ok) {
    throw new HttpError('Error querying approved wallets with TheGraph Studio API', 500);
  }
  return response.json();
};

app.get('/approved-wallets', authenticateAdmin, async (_req, res, next) => {
  try {
    res.status(200).send(await fetchApprovedWallets());
  } catch (err) {
    next(err);
  }
});

const fetchSubmittedWallets = async () => {
  const response = await fetch(GRAPH_API_ENDPOINT, {
    method: 'POST',
    body: JSON.stringify({
      query: `
    {
      wallets(where: { pending: true }) {
        id
      }
    }
  `,
    }),
    headers: { 'Content-Type': 'application/json' },
  });
  if (!response.ok) {
    throw new HttpError('Error querying submitted wallets with TheGraph Studio API', 500);
  }
  return response.json();
};

app.get('/submitted-wallets', authenticateAdmin, async (_req, res, next) => {
  try {
    res.status(200).send(await fetchSubmittedWallets());
  } catch (err) {
    next(err);
  }
});

app.post('/refresh-token', validateWalletAddress, authenticateToken, async (req, res, next) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    await validateTokenWithGun(req.body.walletAddress, token);
    const newToken = await createJwtToken(req.body.walletAddress);
    await saveTokenToGun(req.body.walletAddress, newToken);
    res.status(200).send({ token: newToken });
  } catch (err) {
    next(err);
  }
});

const getDeploymentsByWalletAddressFromGun = (walletAddress) => {
  return new Promise((resolve) => {
    gun
      .get('deployments')
      .get(walletAddress.toLowerCase())
      .once((data) => {
        if (data) {
          const { _, ...deploymentData } = data;
          resolve(
            Object.entries(deploymentData).map(([name, value]) => ({
              name,
              value,
            }))
          );
        } else {
          resolve([]);
        }
      });
  });
};

app.get('/deployments', authenticateToken, async (req, res, next) => {
  try {
    res.status(200).json(await getDeploymentsByWalletAddressFromGun(req.user.walletAddress));
  } catch (err) {
    next(err);
  }
});

const getNamespaces = async (walletAddress) => {
  const NamespaceContract = getNamespaceContract();
  const Multicall3Contract = getMulticall3Contract();

  const NamespaceInterface = new ethers.Interface(NamespaceAbi);

  const ownerBalance = await NamespaceContract.balanceOf(walletAddress);
  if (ownerBalance === BigInt(0)) {
    return [];
  }

  const ownerTokensArray = Array.from({ length: Number(ownerBalance) }, (_, index) => index);
  const BATCH_SIZE = 500;
  const tokenChunks = [];
  for (let i = 0; i < ownerTokensArray.length; i += BATCH_SIZE) {
    tokenChunks.push(ownerTokensArray.slice(i, i + BATCH_SIZE));
  }

  let tokenIds = [];
  for (const chunk of tokenChunks) {
    const calls = chunk.map((index) => ({
      target: NamespaceAddress,
      allowFailure: true,
      callData: NamespaceInterface.encodeFunctionData('tokenOfOwnerByIndex', [
        walletAddress,
        index,
      ]),
    }));

    const multicallResults = await Multicall3Contract.aggregate3.staticCall(calls);

    const results = multicallResults.map(({ success, returnData }, i) => {
      if (!success) {
        console.error(`Failed to retrieve token ID for index: ${chunk[i]}`);
        return null;
      }
      return NamespaceInterface.decodeFunctionResult('tokenOfOwnerByIndex', returnData)[0];
    });

    tokenIds = tokenIds.concat(results);
  }

  const tokenChunksForNamespaces = [];
  for (let i = 0; i < tokenIds.length; i += BATCH_SIZE) {
    tokenChunksForNamespaces.push(tokenIds.slice(i, i + BATCH_SIZE));
  }

  let namespaces = [];
  for (const chunk of tokenChunksForNamespaces) {
    const calls = chunk.map((tokenId) => ({
      target: NamespaceAddress,
      allowFailure: true,
      callData: NamespaceInterface.encodeFunctionData('tokenIdToNamespace', [tokenId]),
    }));

    const multicallResults = await Multicall3Contract.aggregate3.staticCall(calls);

    const results = multicallResults.map(({ success, returnData }, i) => {
      if (!success) {
        console.error(`Failed to fetch namespace for token ID ${chunk[i]}`);
        return null;
      }
      return NamespaceInterface.decodeFunctionResult('tokenIdToNamespace', returnData)[0];
    });

    namespaces = namespaces.concat(results);
  }
  return namespaces;
};

app.get('/namespaces', authenticateToken, async (req, res, next) => {
  try {
    res.status(200).json({ namespaces: await getNamespaces(req.user.walletAddress) });
  } catch (err) {
    next(err);
  }
});

app.get('/unpublished-namespaces', authenticateToken, async (req, res, next) => {
  try {
    const namespaces = await getNamespaces(req.user.walletAddress);
    const deployments = await getDeploymentsByWalletAddressFromGun(req.user.walletAddress);
    const deployedNamesSet = new Set(deployments.map(({ name }) => name));
    res.status(200).json({ namespaces: namespaces.filter((n) => !deployedNamesSet.has(n)) });
  } catch (err) {
    next(err);
  }
});

app.use((err, _req, res, _next) => {
  const status = err.code || 500;
  const message = err.message || 'Something went wrong';
  res.status(status).send(message);
});
