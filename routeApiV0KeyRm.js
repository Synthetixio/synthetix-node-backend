const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');
const HttpError = require('./HttpError');

const deleteGeneratedKey = ({ walletAddress, key }) => {
  return new Promise((resolve, reject) => {
    require('./gundb')
      .getGun()
      .get(require('./generateHash')(walletAddress.toLowerCase()))
      .get('generated-keys')
      .get(key)
      .put(null, (ack) => {
        if (ack.err) {
          reject(new HttpError(`Failed to delete key: ${ack.err}`));
        } else {
          resolve();
        }
      });
  });
};

module.exports = createProxyMiddleware({
  target: `${require('./env').UPSTREAM_IPFS_URL}/api/v0/key/rm`,
  pathRewrite: {
    '^/': '',
  },
  selfHandleResponse: true,
  on: {
    proxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
      try {
        res.removeHeader('trailer');
        if (proxyRes.statusCode < 400) {
          await Promise.all(
            JSON.parse(responseBuffer.toString('utf8')).Keys.map((k) =>
              deleteGeneratedKey({
                walletAddress: req.user.walletAddress,
                key: k.Name,
              })
            )
          );
        }
      } catch (err) {
        console.error('Error processing proxy response:', err);
      }
      return responseBuffer;
    }),
  },
});
