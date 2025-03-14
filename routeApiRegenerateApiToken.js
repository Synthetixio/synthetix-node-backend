const { encrypt } = require('./gundb');

module.exports = async (req, res, next) => {
  try {
    const newApiToken = await require('./createJwtApiToken')(req.user.walletAddress);
    const encryptedNewApiToken = await encrypt(require('./generateHash')(newApiToken));
    await require('./saveApiTokenToGun')(req.user.walletAddress, encryptedNewApiToken);
    res.status(200).send({ apiToken: newApiToken });
  } catch (err) {
    next(err);
  }
};
