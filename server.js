const express = require('express');
const ethers = require('ethers');
const crypto = require('crypto');
const path = require('path');
const { promises: fs } = require('fs');
const cors = require('cors');
const app = express();

const PORT = process.env.PORT || 3005;
const DATA_DIR = path.join(__dirname, 'data');

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

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

const validateVerificationParameters = (req, res, next) => {
  if (!req.body.nonce || !req.body.signedMessage) {
    return next(new HttpError('Invalid request', 400));
  }
  next();
};

const verifyMessage = async (req, res, next) => {
  try {
    const address = ethers.verifyMessage(req.body.nonce, req.body.signedMessage);
    const storedNonce = await fs.readFile(path.join(DATA_DIR, `${address}.unverified`), 'utf8');
    if (storedNonce !== req.body.nonce) throw new Error();
    res.locals.address = address;
    next();
  } catch {
    next(new HttpError('Incorrect input data', 400));
  }
};

const manageWalletAddressStorage = async (req, res, next) => {
  if (!(await walletAddressStored(path.join(DATA_DIR, `${res.locals.address}.verified`)))) {
    await storeWalletAddress(`${res.locals.address}.verified`, req.body.nonce);
  }
  next();
};

app.post(
  '/verify',
  validateVerificationParameters,
  verifyMessage,
  manageWalletAddressStorage,
  async (req, res, next) => {
    try {
      res.status(200).send({ signature: 'Verification successful' });
    } catch (err) {
      next(err);
    }
  }
);

app.use((err, req, res, next) => {
  const status = err.code || 500;
  const message = err.message || 'Something went wrong';
  res.status(status).send(message);
});
