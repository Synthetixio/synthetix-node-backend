const express = require('express');
const { ethers } = require('ethers');
const crypto = require('node:crypto');
const cors = require('cors');
const { getNamespaceContract, getWhitelistContract } = require('./contracts');
const { getGun, decrypt } = require('./gundb');
//const Multicall3 = require('./Multicall3/11155420/Multicall3');
const HttpError = require('./HttpError');
const validateNamespace = require('./validateNamespace');
const jwt = require('jsonwebtoken');
const { initGun } = require('./gundb');
const app = express();
require('dotenv').config();
const { createProxyMiddleware } = require('http-proxy-middleware');
const basicAuth = require('basic-auth');

const {
  //
  PORT,
  UPSTREAM_IPFS_URL,
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

//const getMulticall3Contract = () => getContract(Multicall3.address, Multicall3.abi);

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
initGun(server);

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

app.post('/api/verify', validateVerificationParameters, verifyMessage, require('./routeApiVerify'));

app.post(
  '/api/verify-api-token',
  validateVerificationParameters,
  verifyMessage,
  require('./routeApiVerifyApiToken')
);

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
    getGun()
      .get(require('./generateHash')(walletAddress.toLowerCase()))
      .get('tokens')
      .once(async (tokenData) => {
        if (!tokenData || (await decrypt(tokenData)) !== require('./generateHash')(token)) {
          reject(new HttpError('Unauthorized', 401));
        } else {
          resolve();
        }
      });
  });
};

const validateApiTokenWithGun = (walletAddress, token) => {
  return new Promise((resolve, reject) => {
    getGun()
      .get(require('./generateHash')(walletAddress.toLowerCase()))
      .get('api-tokens')
      .once(async (tokenData) => {
        if (!tokenData || (await decrypt(tokenData)) !== require('./generateHash')(token)) {
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
    if (req.query.api) {
      await validateApiTokenWithGun(decoded.walletAddress, token);
    } else {
      await validateTokenWithGun(decoded.walletAddress, token);
    }
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

app.post('/api/generate-api-nonce', authenticateToken, createNonce);

app.get('/api/check-api-token', authenticateToken, require('./routeApiCheckApiToken'));

app.use(
  '/api/v0/key/gen',
  authenticateToken,
  (req, _res, next) => validateNamespace(req.query.arg, next),
  verifyKeyGenNamespace,
  require('./routeApiV0KeyGen')
);

app.use('/api/v0/key/rm', authenticateToken, verifyKeyGenNamespace, require('./routeApiV0KeyRm'));

app.use(
  '/api/v0/name/publish',
  authenticateToken,
  verifyNamePublishNamespace,
  require('./routeApiV0NamePublish')
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

app.post('/api/regenerate-api-token', authenticateToken, require('./routeApiRegenerateApiToken'));

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
  require('./routeApiUniqueNamespace')
);

app.post('/api/unique-generated-key', authenticateToken, require('./routeApiUniqueGeneratedKey'));

const getGeneratedKey = async (walletAddress) => {
  const data = await getGun()
    .get(require('./generateHash')(walletAddress.toLowerCase()))
    .get('generated-keys');

  if (!data) {
    return [];
  }

  return Promise.all(
    Object.values(require('./removeMetaData')(data))
      .filter((ref) => ref)
      .map(async (ref) => {
        return require('./removeMetaData')(await getGun().get(ref));
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

app.get('/api/cids', authenticateToken, verifyCidNamespace, require('./routeApiCids'));

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

app.post(
  '/api/remove-cid',
  authenticateToken,
  verifyRemoveCidNamespace,
  require('./routeApiRemoveCid')
);

app.use(
  '/api/v0/dag/import',
  authenticateToken,
  createProxyMiddleware({
    target: `${UPSTREAM_IPFS_URL}/api/v0/dag/import`,
    pathRewrite: {
      '^/': '',
    },
  })
);

app.use('/api/v0/pin/add', authenticateToken, require('./routeApiV0PinAdd'));

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

app.get('/api/screenshot', authenticateToken, require('./routeApiScreenshot'));

app.use((err, _req, res, _next) => {
  const status = err.code || 500;
  const message = err.message || 'Something went wrong';
  res.status(status).send(message);
});
