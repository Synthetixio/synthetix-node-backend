const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');
const HttpError = require('./HttpError');

const updateGeneratedKey = ({ walletAddress, key, updates }) => {
  return new Promise((resolve, reject) => {
    require('./gundb')
      .getGun()
      .get(require('./generateHash')(walletAddress.toLowerCase()))
      .get('generated-keys')
      .get(key)
      .put(updates, (ack) => {
        if (ack.err) {
          reject(new HttpError(`Failed to update key: ${ack.err}`));
        } else {
          resolve();
        }
      });
  });
};

module.exports = createProxyMiddleware({
  target: `${require('./env').UPSTREAM_IPFS_URL}/api/v0/name/publish`,
  pathRewrite: {
    '^/': '',
  },
  selfHandleResponse: true,
  on: {
    proxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
      try {
        res.removeHeader('trailer');
        if (proxyRes.statusCode < 400) {
          await updateGeneratedKey({
            walletAddress: req.user.walletAddress,
            key: req.query.key,
            updates: {
              ipfs: JSON.parse(responseBuffer.toString('utf8')).Value,
              published: true,
            },
          });
        }
      } catch (err) {
        console.error('Error saving to Gun:', err.message);
      }
      return responseBuffer;
    }),
  },
});
