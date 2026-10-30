// Захват страницы воспроизведения сеанса в видео (Playwright, Chromium).
// node record.js PAGE.html OUTDIR WIDTH HEIGHT  -> печатает путь к записанному .webm
const { chromium } = require('playwright');

(async () => {
  const [, , html, outdir, w, h] = process.argv;
  const size = { width: Number(w), height: Number(h) };
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: size, recordVideo: { dir: outdir, size } });
  const page = await context.newPage();
  await page.goto('file://' + html);
  await page.waitForFunction(() => window.__done === true, null, { timeout: 900000, polling: 250 });
  const video = page.video();
  await context.close();
  console.log(await video.path());
  await browser.close();
})();
