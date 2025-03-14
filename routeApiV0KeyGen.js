const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');
const HttpError = require('./HttpError');

const saveGeneratedKey = ({ walletAddress, key, id }) => {
  return new Promise((resolve, reject) => {
    require('./gundb')
      .getGun()
      .get(require('./generateHash')(walletAddress.toLowerCase()))
      .get('generated-keys')
      .get(key)
      .put({ key, id, published: false }, (ack) => {
        if (ack.err) {
          reject(new HttpError(`Failed to save ipns keys to Gun: ${ack.err}`));
        } else {
          resolve();
        }
      });
  });
};

module.exports = createProxyMiddleware({
  target: `${require('./env').UPSTREAM_IPFS_URL}/api/v0/key/gen`,
  pathRewrite: {
    '^/': '',
  },
  selfHandleResponse: true,
  on: {
    proxyReq: function onProxyReq(proxyReq) {
      proxyReq.removeHeader('authorization');
    },
    proxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
      try {
        res.removeHeader('trailer');
        if (proxyRes.statusCode < 400) {
          await saveGeneratedKey({
            walletAddress: req.user.walletAddress,
            key: req.query.arg,
            id: JSON.parse(responseBuffer.toString('utf8')).Id,
          });
        }
      } catch (err) {
        console.error('Error saving to Gun:', err.message);
      }
      return responseBuffer;
    }),
  },
});
