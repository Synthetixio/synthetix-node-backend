const jwt = require('jsonwebtoken');
const { getGun, encrypt } = require('./gundb');
const HttpError = require('./HttpError');

const createJwtToken = async (walletAddress) => {
  return new Promise((resolve, reject) => {
    jwt.sign({ walletAddress }, process.env.JWT_SECRET_KEY, { expiresIn: '1d' }, (err, token) => {
      if (err) reject(err);
      resolve(token);
    });
  });
};

const saveTokenToGun = (walletAddress, encryptedToken) => {
  return new Promise((resolve, reject) => {
    getGun()
      .get(require('./generateHash')(walletAddress.toLowerCase()))
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

module.exports = async (_req, res, next) => {
  try {
    const token = await createJwtToken(res.locals.address);
    const encryptedToken = await encrypt(require('./generateHash')(token));
    await saveTokenToGun(res.locals.address, encryptedToken);
    res.status(200).send({ token });
  } catch (err) {
    next(err);
  }
};
