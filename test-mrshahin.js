const puppeteer = require('puppeteer-core');
const path = require('path');

const CHAPTER_ID = '6a6855e1c3d08d90637d3b47'; // Sep 2025 INT 1 Module 1
const SUBJECT_ID = '6a622f21c3d08d90637d3466';
const QUESTION_TYPE_ID = '65a4963482dbaac16d820fc6';

async function testMrShahin() {
  const browser = await puppeteer.launch({
    executablePath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900 });

  page.on('console', msg => console.log('MRSHAHIN LOG:', msg.text()));
  page.on('pageerror', err => console.log('MRSHAHIN ERROR:', err.message));

  await page.setRequestInterception(true);
  page.on('request', req => {
    const url = req.url();
    if (url.includes('/teacher/getClass')) {
      console.log('Intercepting getClass and returning mock classes');
      req.respond({
        status: 200,
        contentType: 'application/json',
        headers: { 'Access-Control-Allow-Origin': '*' },
        body: JSON.stringify({ message: 'success', teacherClasess: { classList: [] } })
      });
    } else {
      req.continue();
    }
  });

  await page.evaluateOnNewDocument(() => {
    localStorage.setItem('O_authWEB', 'valid_preview_token');
    localStorage.setItem('auth_role', 'Student');
    localStorage.setItem('pp_name', 'Student Preview');
  });

  const targetUrl = `https://mrshahin.com/question/${CHAPTER_ID}/${QUESTION_TYPE_ID}/${SUBJECT_ID}`;
  console.log('Navigating to mrshahin:', targetUrl);

  await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });

  // Wait for loading to finish and UI to render
  console.log('Waiting for questions to render...');
  await new Promise(r => setTimeout(r, 7000));

  // If Practice Mode modal appears, select Independent Practice
  try {
    const btn = await page.$('.practice-mode-btn, button.independent-btn, button:has-text("Independent")');
    if (btn) {
      console.log('Dismissing practice mode modal...');
      await btn.click();
      await new Promise(r => setTimeout(r, 1000));
    }
  } catch(e) {}

  const shotPath = path.join('C:\\Users\\hp\\.gemini\\antigravity-ide\\brain\\c8c50faa-9c6f-4d06-b90e-11c004ec8659', 'mrshahin_sep2025_m1_q1_clean.png');
  await page.screenshot({ path: shotPath, fullPage: false });
  console.log('Saved clean mrshahin screenshot to:', shotPath);

  await browser.close();
}

testMrShahin().catch(err => console.error(err));
