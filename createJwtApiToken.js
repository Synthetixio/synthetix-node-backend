const jwt = require('jsonwebtoken');

const createJwtApiToken = async (walletAddress) => {
  return new Promise((resolve, reject) => {
    jwt.sign({ walletAddress }, process.env.JWT_SECRET_KEY, {}, (err, token) => {
      if (err) reject(err);
      resolve(token);
    });
  });
};

module.exports = createJwtApiToken;
