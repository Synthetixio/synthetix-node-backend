const checkApiTokenWithGun = (walletAddress) => {
  return new Promise((resolve) => {
    require('./gundb')
      .getGun()
      .get(require('./generateHash')(walletAddress.toLowerCase()))
      .get('api-tokens')
      .once((tokenData) => {
        resolve(!!tokenData);
      });
  });
};

module.exports = async (req, res, next) => {
  try {
    res.status(200).json({ apiTokenGenerated: await checkApiTokenWithGun(req.user.walletAddress) });
  } catch (err) {
    next(err);
  }
};
