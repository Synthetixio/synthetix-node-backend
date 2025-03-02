const cp = require('node:child_process');

async function updateStats() {
  try {
    const { RepoSize: repoSize, NumObjects: numObjects } = await (
      await fetch(`${require('./env').UPSTREAM_IPFS_URL}/api/v0/repo/stat`, { method: 'POST' })
    ).json();
    Object.assign(require('./state'), { repoSize, numObjects });
  } catch (e) {
    console.error(e);
  }

  try {
    const { TotalIn: totalIn, TotalOut: totalOut } = await (
      await fetch(`${require('./env').UPSTREAM_IPFS_URL}/api/v0/stats/bw`, { method: 'POST' })
    ).json();
    Object.assign(require('./state'), { totalIn, totalOut });
  } catch (e) {
    console.error(e);
  }

  const [pid] = await new Promise((resolve) =>
    cp.exec('pgrep -f "ipfs daemon"', (err, stdout, stderr) => {
      if (err) {
        console.error(err);
        return resolve(null);
      }
      if (stderr) {
        console.error(new Error(stderr));
        return resolve(null);
      }
      return resolve(
        stdout
          .split('\n')
          .map((s) => s.trim())
          .filter(Boolean)
      );
    })
  );
  if (!pid) {
    return;
  }

  const uptime = await new Promise((resolve) =>
    cp.exec(`ps -p ${pid} -o lstart=`, (err, stdout, stderr) => {
      if (err) {
        console.error(err);
        return resolve(null);
      }
      if (stderr) {
        console.error(new Error(stderr));
        return resolve(null);
      }
      const startDate = new Date(stdout);
      const uptimeInSeconds = Math.floor((Date.now() - startDate.getTime()) / 1000);
      return resolve(uptimeInSeconds);
    })
  );
  if (!uptime) {
    return;
  }
  Object.assign(require('./state'), { uptime });

  const uptimeHours = uptime / (60 * 60);
  const uptimeDays = uptimeHours / 24;
  const dailyIn = require('./state').totalIn / uptimeDays;
  const hourlyIn = require('./state').totalIn / uptimeHours;
  const dailyOut = require('./state').totalOut / uptimeDays;
  const hourlyOut = require('./state').totalOut / uptimeHours;
  Object.assign(require('./state'), { dailyIn, hourlyIn, dailyOut, hourlyOut });
}

module.exports = updateStats;
