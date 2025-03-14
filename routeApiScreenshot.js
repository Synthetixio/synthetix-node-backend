const HttpError = require('./HttpError');
const puppeteer = require('puppeteer');

module.exports = async (req, res, next) => {
  const { url } = req.query;

  if (!url) {
    return next(new HttpError('URL parameter is required', 400));
  }

  const urlPattern = /^(https?:\/\/[a-zA-Z0-9.-]+(:\d+)?\/ipns\/[a-zA-Z0-9\/_-]+)$/;
  if (!urlPattern.test(url)) {
    return next(new HttpError('Invalid url', 400));
  }

  let browser;
  try {
    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });
    const page = await browser.newPage();
    await page.setViewport({ width: 800, height: 600 });
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 120000 });
    const screenshotBase64 = await page.screenshot({
      encoding: 'base64',
    });
    await browser.close();

    res.json({ image: `data:image/png;base64,${screenshotBase64}` });
  } catch {
    next(new HttpError('Failed to generate screenshot', 500));
  } finally {
    if (browser) {
      await browser.close();
    }
  }
};
