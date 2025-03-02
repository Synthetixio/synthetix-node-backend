const cp = require('node:child_process');
const fs = require('node:fs');

function peersTracking() {
  cp.exec(
    "ipfs-cluster-ctl --enc=json peers ls | jq '{id}' | jq '[inputs]'",
    async (err, stdout, stderr) => {
      if (err) {
        return console.error(err);
      }
      if (stderr) {
        return console.error(new Error(stderr));
      }
      try {
        const data = JSON.parse(stdout);
        const now = new Date();
        const year = now.getFullYear();
        const month = now.getMonth() + 1;
        const day = now.getDate();
        const hour = now.getHours();

        // TODO: switch to GunDB
        await fs.promises.mkdir(`./data/${year}/${month}/${day}/${hour}`, { recursive: true });
        const [yearlyTotal, monthlyTotal, dailyTotal, hourlyTotal] = await Promise.all([
          fs.promises.readFile(`./data/${year}/total`, 'utf8').catch(() => '0'),
          fs.promises.readFile(`./data/${year}/${month}/total`, 'utf8').catch(() => '0'),
          fs.promises.readFile(`./data/${year}/${month}/${day}/total`, 'utf8').catch(() => '0'),
          fs.promises
            .readFile(`./data/${year}/${month}/${day}/${hour}/total`, 'utf8')
            .catch(() => '0'),
        ]);
        const newYearlyTotal = Number.parseInt(yearlyTotal) + 1;
        const newMonthlyTotal = Number.parseInt(monthlyTotal) + 1;
        const newDailyTotal = Number.parseInt(dailyTotal) + 1;
        const newHourlyTotal = Number.parseInt(hourlyTotal) + 1;

        await Promise.all([
          fs.promises.writeFile(`./data/${year}/total`, `${newYearlyTotal}`).catch(() => null),
          fs.promises
            .writeFile(`./data/${year}/${month}/total`, `${newMonthlyTotal}`)
            .catch(() => null),
          fs.promises
            .writeFile(`./data/${year}/${month}/${day}/total`, `${newDailyTotal}`)
            .catch(() => null),
          fs.promises
            .writeFile(`./data/${year}/${month}/${day}/${hour}/total`, `${newHourlyTotal}`)
            .catch(() => null),
        ]);
        for (const { id } of data) {
          const [yearly, monthly, daily, hourly] = await Promise.all([
            fs.promises.readFile(`./data/${year}/${id}`, 'utf8').catch(() => '0'),
            fs.promises.readFile(`./data/${year}/${month}/${id}`, 'utf8').catch(() => '0'),
            fs.promises.readFile(`./data/${year}/${month}/${day}/${id}`, 'utf8').catch(() => '0'),
            fs.promises
              .readFile(`./data/${year}/${month}/${day}/${hour}/${id}`, 'utf8')
              .catch(() => '0'),
          ]);
          const newYearly = Number.parseInt(yearly) + 1;
          const newMonthly = Number.parseInt(monthly) + 1;
          const newDaily = Number.parseInt(daily) + 1;
          const newHourly = Number.parseInt(hourly) + 1;

          await Promise.all([
            fs.promises.writeFile(`./data/${year}/${id}`, `${newYearly}`).catch(() => null),
            fs.promises
              .writeFile(`./data/${year}/${month}/${id}`, `${newMonthly}`)
              .catch(() => null),
            fs.promises
              .writeFile(`./data/${year}/${month}/${day}/${id}`, `${newDaily}`)
              .catch(() => null),
            fs.promises
              .writeFile(`./data/${year}/${month}/${day}/${hour}/${id}`, `${newHourly}`)
              .catch(() => null),
          ]);
          const state = require('./state');
          state.peerUptime[id] = {
            yearly: newYearly / newYearlyTotal,
            monthly: newMonthly / newMonthlyTotal,
            daily: newDaily / newDailyTotal,
            hourly: newHourly / newHourlyTotal,
          };
        }
      } catch (e) {
        return console.error(e);
      }
    }
  );
}

module.exports = peersTracking;
