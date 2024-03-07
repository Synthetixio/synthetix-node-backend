const express = require('express');
const ethers = require('ethers');
const crypto = require('crypto');
const path = require('path');
const { promises: fs } = require('fs');
const app = express();

const PORT = process.env.PORT || 3005;
const DATA_DIR = path.join(__dirname, 'data');

app.use(express.json());

const validateWalletAddress = (req, res) => {
  if (!req.body.walletAddress) {
    res.status(400).send({ message: 'Missing wallet address' });
    return false;
  }
  if (!ethers.isAddress(req.body.walletAddress)) {
    res.status(400).send({ message: 'Invalid wallet address' });
    return false;
  }
  return true;
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
  return new Promise((resolve) => {
    crypto.randomBytes(32, (err, buf) => {
      if (err) throw err;
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

app.post('/signup', async (req, res) => {
  if (!validateWalletAddress(req, res)) return;

  const filePath = path.join(DATA_DIR, req.body.walletAddress.toLowerCase());
  try {
    if (await walletAddressStored(filePath)) {
      res.status(200).send({ signature: await fs.readFile(filePath, 'utf8') });
      return;
    }

    const randomBytes = await generateRandomHexString();
    await storeWalletAddress(req.body.walletAddress.toLowerCase(), randomBytes);

    res.status(200).send({ signature: randomBytes });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
