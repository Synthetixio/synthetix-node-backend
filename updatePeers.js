const cp = require('node:child_process');

function updatePeers() {
  cp.exec(
    "ipfs-cluster-ctl --enc=json peers ls | jq '{id, version, ipfs}' | jq '[inputs]'",
    (err, stdout, stderr) => {
      if (err) {
        return console.error(err);
      }
      if (stderr) {
        return console.error(new Error(stderr));
      }
      try {
        const data = JSON.parse(stdout);
        const peers = require('./resolvePeers')(data);
        return Object.assign(require('./state'), { peers });
      } catch (e) {
        return console.error(e);
      }
    }
  );
}

module.exports = updatePeers;
