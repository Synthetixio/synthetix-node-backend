const express = require('express');
const { ethers, JsonRpcProvider, Contract } = require('ethers');
const crypto = require('node:crypto');
const cors = require('cors');
const puppeteer = require('puppeteer');
const Whitelist = require('@synthetixio/synthetix-node-namespace/deployments/11155420/Whitelist');
const Namespace = require('@synthetixio/synthetix-node-namespace/deployments/11155420/Namespace');
//const Multicall3 = require('./Multicall3/11155420/Multicall3');
const Gun = require('gun');
const jwt = require('jsonwebtoken');
const app = express();
require('dotenv').config();
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');
const basicAuth = require('basic-auth');

const {
  //
  PORT,
  UPSTREAM_IPFS_URL,
  UPSTREAM_IPFS_CLUSTER_URL,
  GRAPH_API_ENDPOINT,
} = require('./env');

app.use(cors());
app.use(express.json());

app.get('/api/stats', (_req, res) => {
  res.status(200).json(require('./state'));
});

setInterval(require('./updatePeers'), 60_000);
setInterval(require('./updateStats'), 60_000);
setInterval(require('./peersTracking'), 10_000);

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

const generateHash = (data) =>
  crypto.createHash('sha256').update(`${data}:${process.env.SECRET}`).digest('hex');

const encrypt = async (data) => await Gun.SEA.encrypt(data, process.env.SECRET);
const decrypt = async (data) => await Gun.SEA.decrypt(data, process.env.SECRET);

const getContract = (address, abi) => {
  try {
    const provider = new JsonRpcProvider('https://sepolia.optimism.io');
    return new Contract(address, abi, provider);
  } catch (err) {
    throw new EthereumContractError('Failed to get contract', err);
  }
};
//const getMulticall3Contract = () => getContract(Multicall3.address, Multicall3.abi);
const getNamespaceContract = () => getContract(Namespace.address, Namespace.abi);
const getWhitelistContract = () => getContract(Whitelist.address, Whitelist.abi);

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

app.post('/api/signup', validateWalletAddress, transformWalletAddress, createNonce);

const server = app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  require('./updatePeers')();
  require('./updateStats')();
  require('./peersTracking')();
});
const gun = Gun({ web: server, file: process.env.GUNDB_STORAGE_PATH });

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

const saveTokenToGun = (walletAddress, encryptedToken) => {
  return new Promise((resolve, reject) => {
    gun
      .get(generateHash(walletAddress.toLowerCase()))
      .get('tokens')
      .put(encryptedToken, (ack) => {
        if (ack.err) {
          reject(new HttpError('Failed to save token to Gun'));
        } else {
          resolve();
        }
      });
  });
};

app.post('/api/verify', validateVerificationParameters, verifyMessage, async (_req, res, next) => {
  try {
    const token = await createJwtToken(res.locals.address);
    const encryptedToken = await encrypt(generateHash(token));
    await saveTokenToGun(res.locals.address, encryptedToken);
    res.status(200).send({ token });
  } catch (err) {
    next(err);
  }
});

app.use(
  '/api/v0/cat',
  createProxyMiddleware({
    target: `${UPSTREAM_IPFS_URL}/api/v0/cat`,
    pathRewrite: {
      '^/': '',
    },
  })
);

const verifyToken = (req) => {
  let token = null;

  // Case 1: Handle token from Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  }

  // Case 2: Fallback to Basic Auth
  if (!token) {
    const auth = basicAuth(req);
    if (auth?.name === 'token' && auth?.pass) {
      token = auth.pass;
    }
  }

  // If no token is found, throw an unauthorized error
  if (!token) {
    throw new HttpError('Unauthorized', 401);
  }

  // Verify the JWT token
  return new Promise((resolve, reject) => {
    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
      if (err) {
        return reject(new HttpError('Forbidden', 403));
      }
      resolve(decoded);
    });
  });
};

const validateTokenWithGun = (walletAddress, token) => {
  return new Promise((resolve, reject) => {
    gun
      .get(generateHash(walletAddress.toLowerCase()))
      .get('tokens')
      .once(async (tokenData) => {
        if (!tokenData || (await decrypt(tokenData)) !== generateHash(token)) {
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
    throw new HttpError('Missing namespace', 400);
  }
  const contract = await getNamespaceContract();
  const tokenId = await contract.namespaceToTokenId(namespace);

  if (tokenId === BigInt(0)) {
    throw new HttpError('Namespace not found', 404);
  }
  if ((await contract.ownerOf(tokenId)).toLowerCase() !== walletAddress.toLowerCase()) {
    throw new HttpError('Not a namespace owner', 403);
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

const validateNamespace = (namespace, next) => {
  const errors = [];

  if (!namespace) {
    errors.push('Namespace cannot be empty.');
  }

  if (namespace && (namespace.length < 3 || namespace.length > 30)) {
    errors.push('Namespace must be between 3 and 30 characters long.');
  }

  if (namespace && !/^[a-z0-9-_]+$/.test(namespace)) {
    errors.push(
      'Namespace must be DNS-compatible: lowercase letters, numbers, dashes (-), or underscores (_).'
    );
  }

  if (namespace && /^-|-$/.test(namespace)) {
    errors.push('Namespace cannot start or end with a dash (-).');
  }

  if (namespace && /^_|_$/.test(namespace)) {
    errors.push('Namespace cannot start or end with an underscore (_).');
  }

  if (errors.length > 0) {
    return next(new HttpError(errors.join(' '), 400));
  }

  next();
};

const verifyNamePublishNamespace = async (req, _res, next) => {
  try {
    await validateNamespaceOwnership(req.query.key, req.user.walletAddress);
    next();
  } catch (err) {
    next(err);
  }
};

app.get('/api/protected', authenticateToken, (_req, res) => {
  res.send('Hello! You are viewing protected content.');
});

const saveGeneratedKey = ({ walletAddress, key, id }) => {
  return new Promise((resolve, reject) => {
    gun
      .get(generateHash(walletAddress.toLowerCase()))
      .get('generated-keys')
      .get(key)
      .put({ key, id, published: false }, (ack) => {
        if (ack.err) {
          reject(new HttpError(`Failed to save ipns keys to Gun: ${ack.err}`));
        } else {
          resolve();
        }
      });
  });
};

app.use(
  '/api/v0/key/gen',
  authenticateToken,
  (req, _res, next) => validateNamespace(req.query.arg, next),
  verifyKeyGenNamespace,
  createProxyMiddleware({
    target: `${UPSTREAM_IPFS_URL}/api/v0/key/gen`,
    pathRewrite: {
      '^/': '',
    },
    selfHandleResponse: true,
    on: {
      proxyReq: function onProxyReq(proxyReq) {
        proxyReq.removeHeader('authorization');
      },
      proxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
        try {
          res.removeHeader('trailer');
          if (proxyRes.statusCode < 400) {
            await saveGeneratedKey({
              walletAddress: req.user.walletAddress,
              key: req.query.arg,
              id: JSON.parse(responseBuffer.toString('utf8')).Id,
            });
          }
        } catch (err) {
          console.error('Error saving to Gun:', err.message);
        }
        return responseBuffer;
      }),
    },
  })
);

const deleteGeneratedKey = ({ walletAddress, key }) => {
  return new Promise((resolve, reject) => {
    gun
      .get(generateHash(walletAddress.toLowerCase()))
      .get('generated-keys')
      .get(key)
      .put(null, (ack) => {
        if (ack.err) {
          reject(new HttpError(`Failed to delete key: ${ack.err}`));
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
    target: `${UPSTREAM_IPFS_URL}/api/v0/key/rm`,
    pathRewrite: {
      '^/': '',
    },
    selfHandleResponse: true,
    on: {
      proxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
        try {
          res.removeHeader('trailer');
          if (proxyRes.statusCode < 400) {
            await Promise.all(
              JSON.parse(responseBuffer.toString('utf8')).Keys.map((k) =>
                deleteGeneratedKey({
                  walletAddress: req.user.walletAddress,
                  key: k.Name,
                })
              )
            );
          }
        } catch (err) {
          console.error('Error processing proxy response:', err);
        }
        return responseBuffer;
      }),
    },
  })
);

const updateGeneratedKey = ({ walletAddress, key, updates }) => {
  return new Promise((resolve, reject) => {
    gun
      .get(generateHash(walletAddress.toLowerCase()))
      .get('generated-keys')
      .get(key)
      .put(updates, (ack) => {
        if (ack.err) {
          reject(new HttpError(`Failed to update key: ${ack.err}`));
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
    target: `${UPSTREAM_IPFS_URL}/api/v0/name/publish`,
    pathRewrite: {
      '^/': '',
    },
    selfHandleResponse: true,
    on: {
      proxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
        try {
          res.removeHeader('trailer');
          if (proxyRes.statusCode < 400) {
            await updateGeneratedKey({
              walletAddress: req.user.walletAddress,
              key: req.query.key,
              updates: {
                ipfs: JSON.parse(responseBuffer.toString('utf8')).Value,
                published: true,
              },
            });
          }
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

app.get('/api/approved-wallets', authenticateAdmin, async (_req, res, next) => {
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

app.get('/api/submitted-wallets', authenticateAdmin, async (_req, res, next) => {
  try {
    res.status(200).send(await fetchSubmittedWallets());
  } catch (err) {
    next(err);
  }
});

app.post('/api/refresh-token', validateWalletAddress, authenticateToken, async (req, res, next) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    await validateTokenWithGun(req.body.walletAddress, token);
    const newToken = await createJwtToken(req.body.walletAddress);
    const encryptedNewToken = await encrypt(generateHash(newToken));
    await saveTokenToGun(req.body.walletAddress, encryptedNewToken);
    res.status(200).send({ token: newToken });
  } catch (err) {
    next(err);
  }
});

//const getNamespacesFromContract = async (walletAddress) => {
//  const NamespaceContract = getNamespaceContract();
//  const Multicall3Contract = getMulticall3Contract();
//
//  const NamespaceInterface = new ethers.Interface(Namespace.abi);
//
//  const ownerBalance = await NamespaceContract.balanceOf(walletAddress);
//  if (ownerBalance === BigInt(0)) {
//    return new Set();
//  }
//
//  const ownerTokensArray = Array.from({ length: Number(ownerBalance) }, (_, index) => index);
//  const BATCH_SIZE = 500;
//  const tokenChunks = [];
//  for (let i = 0; i < ownerTokensArray.length; i += BATCH_SIZE) {
//    tokenChunks.push(ownerTokensArray.slice(i, i + BATCH_SIZE));
//  }
//
//  let tokenIds = [];
//  for (const chunk of tokenChunks) {
//    const calls = chunk.map((index) => ({
//      target: Namespace.address,
//      allowFailure: true,
//      callData: NamespaceInterface.encodeFunctionData('tokenOfOwnerByIndex', [
//        walletAddress,
//        index,
//      ]),
//    }));
//
//    const multicallResults = await Multicall3Contract.aggregate3.staticCall(calls);
//
//    const results = multicallResults.map(({ success, returnData }, i) => {
//      if (!success) {
//        console.error(`Failed to retrieve token ID for index: ${chunk[i]}`);
//        return null;
//      }
//      return NamespaceInterface.decodeFunctionResult('tokenOfOwnerByIndex', returnData)[0];
//    });
//
//    tokenIds = tokenIds.concat(results);
//  }
//
//  const tokenChunksForNamespaces = [];
//  for (let i = 0; i < tokenIds.length; i += BATCH_SIZE) {
//    tokenChunksForNamespaces.push(tokenIds.slice(i, i + BATCH_SIZE));
//  }
//
//  const namespaces = new Set();
//  for (const chunk of tokenChunksForNamespaces) {
//    const calls = chunk.map((tokenId) => ({
//      target: Namespace.address,
//      allowFailure: true,
//      callData: NamespaceInterface.encodeFunctionData('tokenIdToNamespace', [tokenId]),
//    }));
//
//    const multicallResults = await Multicall3Contract.aggregate3.staticCall(calls);
//
//    const results = multicallResults.map(({ success, returnData }, i) => {
//      if (!success) {
//        console.error(`Failed to fetch namespace for token ID ${chunk[i]}`);
//        return null;
//      }
//      return NamespaceInterface.decodeFunctionResult('tokenIdToNamespace', returnData)[0];
//    });
//
//    for (const namespace of results) {
//      if (namespace) namespaces.add(namespace);
//    }
//  }
//  return namespaces;
//};

app.post(
  '/api/unique-namespace',
  authenticateToken,
  (req, _res, next) => validateNamespace(req.body.namespace, next),
  async (req, res, next) => {
    try {
      const NamespaceContract = getNamespaceContract();

      const tokenId = await NamespaceContract.namespaceToTokenId(req.body.namespace);
      if (!tokenId) {
        res.status(200).json({ unique: true });
        return;
      }
      const owner = await NamespaceContract.ownerOf(tokenId);
      if (owner.toLowerCase() === req.user.walletAddress.toLowerCase()) {
        res.status(200).json({ unique: true });
        return;
      }
      if (owner.toLowerCase() !== req.user.walletAddress.toLowerCase()) {
        res.status(200).json({ unique: false });
        return;
      }
    } catch (err) {
      next(err);
    }
  }
);

const checkGeneratedKey = async ({ walletAddress, key }) => {
  return gun.get(generateHash(walletAddress.toLowerCase())).get('generated-keys').get(key);
};

app.post('/api/unique-generated-key', authenticateToken, async (req, res, next) => {
  try {
    const unique = await checkGeneratedKey({
      walletAddress: req.user.walletAddress,
      key: req.body.key,
    });

    res.status(200).json({ unique: !unique });
  } catch (err) {
    next(err);
  }
});

const removeMetaData = (o) => {
  const { _, ...withoutMeta } = o;
  return withoutMeta;
};

const getGeneratedKey = async (walletAddress) => {
  const data = await gun.get(generateHash(walletAddress.toLowerCase())).get('generated-keys');

  if (!data) {
    return [];
  }

  return Promise.all(
    Object.values(removeMetaData(data))
      .filter((ref) => ref)
      .map(async (ref) => {
        return removeMetaData(await gun.get(ref));
      })
  );
};

app.get('/api/generated-keys', authenticateToken, async (req, res, next) => {
  try {
    res.status(200).json({ keys: await getGeneratedKey(req.user.walletAddress) });
  } catch (err) {
    next(err);
  }
});

const verifyCidNamespace = async (req, _res, next) => {
  try {
    if (!req.query.key) {
      throw new HttpError('Missing key', 400);
    }
    await validateNamespaceOwnership(req.query.key, req.user.walletAddress);
    next();
  } catch (err) {
    next(err);
  }
};

app.get('/api/cids', authenticateToken, verifyCidNamespace, async (req, res, next) => {
  try {
    res.status(200).json({
      cids: await getCidsFromGeneratedKey({
        walletAddress: req.user.walletAddress,
        key: req.query.key,
      }),
    });
  } catch (err) {
    next(err);
  }
});

const verifyRemoveCidNamespace = async (req, _res, next) => {
  try {
    if (!req.body.key) {
      throw new HttpError('Missing key', 400);
    }
    await validateNamespaceOwnership(req.body.key, req.user.walletAddress);
    next();
  } catch (err) {
    next(err);
  }
};

app.post('/api/remove-cid', authenticateToken, verifyRemoveCidNamespace, async (req, res, next) => {
  try {
    const { cid, key } = req.body;

    if (!cid) {
      return next(new HttpError('CID missed.', 400));
    }

    const response = await fetch(`${UPSTREAM_IPFS_CLUSTER_URL}/api/v0/pin/rm?arg=${cid}`, {
      method: 'POST',
    });
    if (!response.ok) {
      throw new HttpError(`Failed to remove CID ${cid} from IPFS`);
    }

    await deleteCidFromGeneratedKey({
      walletAddress: req.user.walletAddress,
      key,
      cid,
    });

    res.status(200).json({ success: true, cid });
  } catch (err) {
    next(err);
  }
});

const addCidToGeneratedKey = ({ walletAddress, key, cid }) => {
  return new Promise((resolve) => {
    gun
      .get(generateHash(walletAddress.toLowerCase()))
      .get('generated-keys')
      .get(key)
      .get('cids')
      .get(cid)
      .put({ cid }, resolve);
  });
};

const getCidsFromGeneratedKey = ({ walletAddress, key }) => {
  return new Promise((resolve) => {
    gun
      .get(generateHash(walletAddress.toLowerCase()))
      .get('generated-keys')
      .get(key)
      .get('cids')
      .once((node) => {
        if (!node) {
          return resolve([]);
        }

        const cids = Object.entries(removeMetaData(node))
          .filter(([_, value]) => value !== null)
          .map(([key]) => key);

        resolve(cids);
      });
  });
};

const deleteCidFromGeneratedKey = ({ walletAddress, key, cid }) => {
  return new Promise((resolve) => {
    gun
      .get(generateHash(walletAddress.toLowerCase()))
      .get('generated-keys')
      .get(key)
      .get('cids')
      .get(cid)
      .put(null, resolve);
  });
};

app.use(
  '/api/v0/dag/import',
  authenticateToken,
  createProxyMiddleware({
    target: `${UPSTREAM_IPFS_URL}/api/v0/dag/import`,
    pathRewrite: {
      '^/': '',
    },
    selfHandleResponse: true,
    on: {
      proxyRes: responseInterceptor(async (responseBuffer, _proxyRes, req, res) => {
        try {
          res.removeHeader('trailer');
          if (_proxyRes.statusCode < 400) {
            const cid = JSON.parse(responseBuffer.toString('utf8')).Root?.Cid['/'];
            if (cid) {
              await fetch(`${UPSTREAM_IPFS_CLUSTER_URL}/api/v0/pin/add?arg=${cid}`, {
                method: 'POST',
              });
              await addCidToGeneratedKey({
                walletAddress: req.user.walletAddress,
                key: req.query.key,
                cid,
              });
            }
          }
        } catch (e) {
          console.error(e);
        }
        return responseBuffer;
      }),
    },
  })
);

app.use(
  '/api/v0/dag/get',
  authenticateToken,
  createProxyMiddleware({
    target: `${UPSTREAM_IPFS_URL}/api/v0/dag/get`,
    pathRewrite: {
      '^/': '',
    },
  })
);

app.get('/api/screenshot', authenticateToken, async (req, res, next) => {
  const { url } = req.query;

  if (!url) {
    return next(new HttpError('URL parameter is required', 400));
  }

  const urlPattern = /^(https?:\/\/[a-zA-Z0-9.-]+(:\d+)?\/ipns\/[a-zA-Z0-9\/_-]+)$/;
  if (!urlPattern.test(url)) {
    return next(new HttpError('Invalid url', 400));
  }

  let browser;
  try {
    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });
    const page = await browser.newPage();
    await page.setViewport({ width: 800, height: 600 });
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 120000 });
    const screenshotBase64 = await page.screenshot({
      encoding: 'base64',
    });
    await browser.close();

    res.json({ image: `data:image/png;base64,${screenshotBase64}` });
  } catch {
    next(new HttpError('Failed to generate screenshot', 500));
  } finally {
    if (browser) {
      await browser.close();
    }
  }
});

app.use((err, _req, res, _next) => {
  const status = err.code || 500;
  const message = err.message || 'Something went wrong';
  res.status(status).send(message);
});
