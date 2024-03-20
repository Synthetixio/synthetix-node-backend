const express = require('express');
const ethers = require('ethers');
const crypto = require('crypto');
const path = require('path');
const { promises: fs } = require('fs');
const proxy = require('express-http-proxy');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const app = express();
require('dotenv').config();

const PORT = process.env.PORT || 3005;
const DATA_DIR = path.join(__dirname, 'data');

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

const walletAddressStored = async (filePath) => {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
};

const generateRandomHexString = async () => {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(32, (err, buf) => {
      if (err) return reject(err);
      resolve(buf.toString('hex'));
    });
  });
};

const storeWalletAddress = async (fileName, fileContent) => {
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.writeFile(path.join(DATA_DIR, fileName), fileContent);
};

app.post('/signup', validateWalletAddress, transformWalletAddress, async (req, res, next) => {
  try {
    if (await walletAddressStored(path.join(DATA_DIR, `${req.body.walletAddress}.unverified`))) {
      res.status(200).send({
        nonce: await fs.readFile(
          path.join(DATA_DIR, `${req.body.walletAddress}.unverified`),
          'utf8'
        ),
      });
      return;
    }

    const nonce = await generateRandomHexString();
    await storeWalletAddress(`${req.body.walletAddress}.unverified`, nonce);
    res.status(200).send({ nonce });
  } catch (err) {
    next(err);
  }
});

const setIpfsConfig = async (config, value) => {
  try {
    const response = await fetch(`${IPFS_URL}api/v0/config?arg=${config}&arg=${value}&json=true`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });

    if (!response.ok) throw new Error('Failed to set config');

    const data = await response.json();
    console.log(`IPFS config set: ${data.Key} to ${data.Value}`);
  } catch (err) {
    console.error(`Error setting ${config}:`, err.message);
  }
};

Promise.all([
  setIpfsConfig('API.HTTPHeaders.Access-Control-Allow-Origin', '["*"]'),
  setIpfsConfig('API.HTTPHeaders.Access-Control-Allow-Methods', '["PUT", "POST", "GET"]'),
])
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  })
  .catch((error) => console.log(error.message));

const validateVerificationParameters = (req, res, next) => {
  if (!req.body.nonce) {
    return next(new HttpError('Nonce not provided', 400));
  }
  if (!req.body.signedMessage) {
    return next(new HttpError('Signed message not provided', 400));
  }
  next();
};

const verifyMessage = async (req, res, next) => {
  let address;
  let storedNonce;
  try {
    address = ethers.verifyMessage(req.body.nonce, req.body.signedMessage);
  } catch {
    return next(new HttpError('Failed to verify message', 400));
  }
  try {
    storedNonce = await fs.readFile(path.join(DATA_DIR, `${address}.unverified`), 'utf8');
  } catch (err) {
    return next(err);
  }
  if (storedNonce !== req.body.nonce) {
    return next(new HttpError('Nonce mismatch', 400));
  }
  res.locals.address = address;
  next();
};

const manageWalletAddressStorage = async (req, res, next) => {
  if (!(await walletAddressStored(path.join(DATA_DIR, `${res.locals.address}.verified`)))) {
    await storeWalletAddress(`${res.locals.address}.verified`, req.body.nonce);
  }
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

app.post(
  '/verify',
  validateVerificationParameters,
  verifyMessage,
  manageWalletAddressStorage,
  async (req, res, next) => {
    try {
      res.status(200).send({ token: await createJwtToken(res.locals.address) });
    } catch (err) {
      next(err);
    }
  }
);

app.use(
  '/api/v0/cat',
  proxy(IPFS_URL, {
    proxyReqPathResolver: (req) => req.originalUrl,
    userResDecorator: (proxyRes, proxyResData, userReq, userRes) => {
      const imageBuffer = Buffer.from(proxyResData, 'binary');
      const base64Image = imageBuffer.toString('base64');
      userRes.set('TE', 'trailers');
      userRes.set('Transfer-Encoding', 'chunked');
      return `data:${proxyRes.headers['content-type']};base64,${base64Image}`;
    },
  })
);

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1];
  if (token == null) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET_KEY, (err) => {
    if (err) return res.sendStatus(403);
    next();
  });
};

app.use(authenticateToken);
app.get('/protected', (req, res) => {
  res.send('Hello! You are viewing protected content.');
});

app.use((err, req, res, next) => {
  const status = err.code || 500;
  const message = err.message || 'Something went wrong';
  res.status(status).send(message);
});
