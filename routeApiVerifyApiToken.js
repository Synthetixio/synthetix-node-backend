const { encrypt } = require('./gundb');

module.exports = async (_req, res, next) => {
  try {
    const apiToken = await require('./createJwtApiToken')(res.locals.address);
    const encryptedApiToken = await encrypt(require('./generateHash')(apiToken));
    await require('./saveApiTokenToGun')(res.locals.address, encryptedApiToken);
    res.status(200).send({ apiToken });
  } catch (err) {
    next(err);
  }
};
