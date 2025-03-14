const crypto = require('node:crypto');

module.exports = (data) =>
  crypto.createHash('sha256').update(`${data}:${process.env.SECRET}`).digest('hex');
