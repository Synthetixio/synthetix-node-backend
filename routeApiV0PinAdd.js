const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');

const addCidToGeneratedKey = ({ walletAddress, key, cid }) => {
  return new Promise((resolve) => {
    require('./gundb')
      .getGun()
      .get(require('./generateHash')(walletAddress.toLowerCase()))
      .get('generated-keys')
      .get(key)
      .get('cids')
      .get(cid)
      .put({ cid }, resolve);
  });
};

module.exports = createProxyMiddleware({
  target: `${require('./env').UPSTREAM_IPFS_CLUSTER_URL}/api/v0/pin/add`,
  pathRewrite: {
    '^/': '',
  },
  selfHandleResponse: true,
  on: {
    proxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
      try {
        res.removeHeader('trailer');
        if (proxyRes.statusCode < 400) {
          if (req.query.arg && req.query.customKey) {
            await addCidToGeneratedKey({
              walletAddress: req.user.walletAddress,
              key: req.query.customKey,
              cid: req.query.arg,
            });
          }
        }
      } catch (e) {
        console.error(e);
      }
      return responseBuffer;
    }),
  },
});
