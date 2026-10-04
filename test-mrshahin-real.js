const puppeteer = require('puppeteer-core');
const path = require('path');
const os = require('os');

const CHAPTER_ID = '6a6855e1c3d08d90637d3b47'; // Sep 2025 INT 1 Module 1
const SUBJECT_ID = '6a622f21c3d08d90637d3466';
const QUESTION_TYPE_ID = '65a4963482dbaac16d820fc6';

async function testMrShahin() {
  const userDataDir = path.join(os.tmpdir(), 'chrome_puppeteer_mrshahin_' + Date.now());
  const browser = await puppeteer.launch({
    executablePath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    headless: true,
    userDataDir: userDataDir,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-web-security',
      '--disable-features=IsolateOrigins,site-per-process',
      '--allow-running-insecure-content'
    ]
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900 });

  page.on('console', msg => console.log('MRSHAHIN LOG:', msg.text()));
  page.on('pageerror', err => console.log('MRSHAHIN ERROR:', err.message));

  // Pre-set localStorage on domain
  await page.goto('https://mrshahin.com', { waitUntil: 'domcontentloaded' });
  await page.evaluate(() => {
    localStorage.setItem('O_authWEB', 'valid_token');
    localStorage.setItem('auth_role', 'Student');
    localStorage.setItem('pp_name', 'Student Preview');
  });

  const targetUrl = `https://mrshahin.com/question/${CHAPTER_ID}/${QUESTION_TYPE_ID}/${SUBJECT_ID}`;
  console.log('Navigating to target:', targetUrl);
  await page.goto(targetUrl, { waitUntil: 'domcontentloaded' });

  console.log('Waiting for questions to render on mrshahin.com...');
  await new Promise(r => setTimeout(r, 8000));

  const shotPath = path.join('C:\\Users\\hp\\.gemini\\antigravity-ide\\brain\\c8c50faa-9c6f-4d06-b90e-11c004ec8659', 'mrshahin_sep2025_m1_q1_real.png');
  await page.screenshot({ path: shotPath, fullPage: false });
  console.log('Saved mrshahin screenshot to:', shotPath);

  await browser.close();
}

testMrShahin().catch(err => console.error(err));
