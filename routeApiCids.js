const getCidsFromGeneratedKey = ({ walletAddress, key }) => {
  return new Promise((resolve) => {
    require('./gundb')
      .getGun()
      .get(require('./generateHash')(walletAddress.toLowerCase()))
      .get('generated-keys')
      .get(key)
      .get('cids')
      .once((node) => {
        if (!node) {
          return resolve([]);
        }

        const cids = Object.entries(require('removeMetaData')(node))
          .filter(([_, value]) => value !== null)
          .map(([key]) => key);

        resolve(cids);
      });
  });
};

module.exports = async (req, res, next) => {
  try {
    res.status(200).json({
      cids: await getCidsFromGeneratedKey({
        walletAddress: req.user.walletAddress,
        key: req.query.key,
      }),
    });
  } catch (err) {
    next(err);
  }
};
