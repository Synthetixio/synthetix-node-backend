module.exports = async (req, res, next) => {
  try {
    const NamespaceContract = require('./contracts').getNamespaceContract();

    const tokenId = await NamespaceContract.namespaceToTokenId(req.body.namespace);
    if (!tokenId) {
      res.status(200).json({ unique: true });
      return;
    }
    const owner = await NamespaceContract.ownerOf(tokenId);
    if (owner.toLowerCase() === req.user.walletAddress.toLowerCase()) {
      res.status(200).json({ unique: true });
      return;
    }
    if (owner.toLowerCase() !== req.user.walletAddress.toLowerCase()) {
      res.status(200).json({ unique: false });
      return;
    }
  } catch (err) {
    next(err);
  }
};
