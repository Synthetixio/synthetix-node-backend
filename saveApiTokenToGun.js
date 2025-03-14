const HttpError = require('./HttpError');

const saveApiTokenToGun = (walletAddress, encryptedToken) => {
  return new Promise((resolve, reject) => {
    require('./gundb')
      .getGun()
      .get(require('./generateHash')(walletAddress.toLowerCase()))
      .get('api-tokens')
      .put(encryptedToken, (ack) => {
        if (ack.err) {
          reject(new HttpError('Failed to save api token to Gun'));
        } else {
          resolve();
        }
      });
  });
};

module.exports = saveApiTokenToGun;
