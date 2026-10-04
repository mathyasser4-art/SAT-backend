const puppeteer = require('puppeteer-core');
const path = require('path');

const CHAPTER_ID = '6a6855e1c3d08d90637d3b47'; // Sep 2025 INT 1 Module 1
const SUBJECT_ID = '6a622f21c3d08d90637d3466';
const QUESTION_TYPE_ID = '65a4963482dbaac16d820fc6';

async function testFullUI() {
  const browser = await puppeteer.launch({
    executablePath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900 });

  await page.setRequestInterception(true);
  page.on('request', req => {
    const url = req.url();
    if (url.includes('backend-production-6752.up.railway.app')) {
      req.continue({ url: url.replace('backend-production-6752.up.railway.app', 'sat-backend-production.up.railway.app') });
    } else {
      req.continue();
    }
  });

  await page.evaluateOnNewDocument(() => {
    localStorage.setItem('O_authWEB', 'valid_token');
    localStorage.setItem('auth_role', 'Student');
    localStorage.setItem('pp_name', 'Student Preview');
  });

  const targetUrl = `https://abacusheroes.com/question/${CHAPTER_ID}/${QUESTION_TYPE_ID}/${SUBJECT_ID}`;
  console.log('Navigating to:', targetUrl);

  await page.goto(targetUrl, { waitUntil: 'domcontentloaded' });

  // Wait for loading overlays to vanish
  console.log('Waiting for exam UI to appear...');
  await page.waitForFunction(() => {
    return !document.querySelector('.mrshahin-global-loader-container') &&
           !document.querySelector('.question-loading') &&
           document.querySelector('.bluebook-exam-body, .bluebook-question-main-area, .practice-mode-overlay');
  }, { timeout: 20000 }).catch(e => console.log('Wait condition timed out:', e.message));

  // If practice mode modal is visible, click 'Independent Practice' or 'Guided Practice'
  const practiceModal = await page.$('.practice-mode-overlay, .practice-mode-modal');
  if (practiceModal) {
    console.log('Practice mode modal detected! Clicking Independent Practice...');
    const btn = await page.$('button.independent-btn, button.btn-independent, .practice-mode-btn');
    if (btn) await btn.click();
    await new Promise(r => setTimeout(r, 1000));
  }

  await new Promise(r => setTimeout(r, 2000));

  const shotPath = path.join(__dirname, 'ui_sep2025_m1_q1_success.png');
  await page.screenshot({ path: shotPath, fullPage: false });
  console.log('Saved exam UI screenshot to:', shotPath);

  await browser.close();
}

testFullUI().catch(err => console.error(err));
