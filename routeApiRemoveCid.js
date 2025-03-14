const HttpError = require('./HttpError');

const deleteCidFromGeneratedKey = ({ walletAddress, key, cid }) => {
  return new Promise((resolve) => {
    require('./gundb')
      .getGun()
      .get(require('./generateHash')(walletAddress.toLowerCase()))
      .get('generated-keys')
      .get(key)
      .get('cids')
      .get(cid)
      .put(null, resolve);
  });
};

module.exports = async (req, res, next) => {
  try {
    const { cid, key } = req.body;

    if (!cid) {
      return next(new HttpError('CID missed.', 400));
    }

    const response = await fetch(
      `${require('./env').UPSTREAM_IPFS_CLUSTER_URL}/api/v0/pin/rm?arg=${cid}`,
      {
        method: 'POST',
      }
    );
    if (!response.ok) {
      throw new HttpError(`Failed to remove CID ${cid} from IPFS`);
    }

    await deleteCidFromGeneratedKey({
      walletAddress: req.user.walletAddress,
      key,
      cid,
    });

    res.status(200).json({ success: true, cid });
  } catch (err) {
    next(err);
  }
};
