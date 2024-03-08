const express = require('express');
const ethers = require('ethers');
const crypto = require('crypto');
const path = require('path');
const { promises: fs } = require('fs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const app = express();

const PORT = process.env.PORT || 3005;
const DATA_DIR = path.join(__dirname, 'data');
const SECRET_KEY = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

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
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
    await fs.writeFile(path.join(DATA_DIR, fileName), fileContent);
  } catch (error) {
    console.error(`Failed to save data to file: ${error}`);
    throw error;
  }
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

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

const validateVerificationParameters = (req, res, next) => {
  if (!req.body.nonce || !req.body.signedMessage) {
    return next(new HttpError('Invalid request', 400));
  }
  next();
};

const sendAuthToken = async (walletAddress, res) => {
  jwt.sign({ walletAddress }, SECRET_KEY, { expiresIn: '1d' }, (err, token) => {
    if (err) throw err;
    res.status(200).send({ token });
  });
};

app.post('/verify', validateVerificationParameters, async (req, res, next) => {
  try {
    const address = ethers.verifyMessage(req.body.nonce, req.body.signedMessage);
    if (await walletAddressStored(path.join(DATA_DIR, `${address}.verified`))) {
      return await sendAuthToken(address, res);
    }
    await storeWalletAddress(`${address}.verified`, req.body.nonce);
    await sendAuthToken(address, res);
  } catch (err) {
    if (err.code === 'INVALID_ARGUMENT') {
      return next(new HttpError('Incorrect input data', 400));
    }
    return next(err);
  }
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1];
  if (token == null) return res.sendStatus(401);
  jwt.verify(token, SECRET_KEY, (err) => {
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
