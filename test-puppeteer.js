const puppeteer = require('puppeteer-core');
const path = require('path');

async function test() {
  const browser = await puppeteer.launch({
    executablePath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 800 });
  await page.goto('https://abacusheroes.com', { waitUntil: 'networkidle2', timeout: 30000 });

  const shotPath = path.join(__dirname, 'abacus_home_test.png');
  await page.screenshot({ path: shotPath });
  console.log('Screenshot saved to:', shotPath);

  await browser.close();
}

test().catch(err => console.error(err));
