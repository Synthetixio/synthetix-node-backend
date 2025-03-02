const ip = require('ip');
const geoip = require('geoip-country');

function resolvePeers(data) {
  const duplicates = new Set();
  return data.flatMap(({ id, version, ipfs }) =>
    ipfs.addresses
      .map((address) => {
        const match = address.match(/\/ip4\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
        return match?.[1];
      })
      .filter((address) => address && ip.isPublic(address))
      .filter((address) => {
        if (duplicates.has(address)) {
          return false;
        }
        duplicates.add(address);
        return address;
      })
      .map((address) => {
        const geo = geoip.lookup(address);
        return {
          peerId: id,
          ipfsId: ipfs?.id,
          version,
          address,
          country: geo?.country,
        };
      })
  );
}

module.exports = resolvePeers;
