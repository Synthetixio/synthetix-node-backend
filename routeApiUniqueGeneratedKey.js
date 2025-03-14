const checkGeneratedKey = async ({ walletAddress, key }) => {
  return require('./gundb')
    .getGun()
    .get(require('./generateHash')(walletAddress.toLowerCase()))
    .get('generated-keys')
    .get(key);
};

module.exports = async (req, res, next) => {
  try {
    const unique = await checkGeneratedKey({
      walletAddress: req.user.walletAddress,
      key: req.body.key,
    });

    res.status(200).json({ unique: !unique });
  } catch (err) {
    next(err);
  }
};
