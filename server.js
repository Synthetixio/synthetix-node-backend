const express = require('express');
const ethers = require('ethers');
const crypto = require('crypto');
const path = require('path');
const { promises: fs } = require('fs');
const app = express();

const PORT = process.env.PORT || 3005;
const DATA_DIR = path.join(__dirname, 'data');

app.use(express.json());

const validateWalletAddress = (req, res, next) => {
  if (!req.body.walletAddress) {
    return next({ code: 400, message: 'Missing wallet address' });
  }
  if (!ethers.isAddress(req.body.walletAddress)) {
    return next({ code: 400, message: 'Invalid wallet address' });
  }
  next();
};

const transformWalletAddress = (req, res, next) => {
  req.body.walletAddress = `${req.body.walletAddress.toLowerCase()}.unverified`;
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
    if (await walletAddressStored(path.join(DATA_DIR, req.body.walletAddress))) {
      res.status(200).send({
        signature: await fs.readFile(path.join(DATA_DIR, req.body.walletAddress), 'utf8'),
      });
      return;
    }

    const randomBytes = await generateRandomHexString();
    await storeWalletAddress(req.body.walletAddress, randomBytes);

    res.status(200).send({ signature: randomBytes });
  } catch (err) {
    next(err);
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

app.use((err, req, res, next) => {
  const status = err.code || 500;
  const message = err.message || 'Something went wrong';
  res.status(status).send(message);
});
