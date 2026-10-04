const puppeteer = require('puppeteer-core');
const path = require('path');

const CHAPTER_ID = '6a6855e1c3d08d90637d3b47'; // Sep 2025 INT 1 Module 1
const SUBJECT_ID = '6a622f21c3d08d90637d3466';
const QUESTION_TYPE_ID = '65a4963482dbaac16d820fc6';

async function testModuleUI() {
  const browser = await puppeteer.launch({
    executablePath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900 });

  page.on('console', msg => console.log('BROWSER LOG:', msg.text()));
  page.on('pageerror', err => console.log('BROWSER ERROR:', err.message));

  await page.evaluateOnNewDocument(() => {
    localStorage.setItem('O_authWEB', 'mock_token_for_student_view');
    localStorage.setItem('auth_role', 'Student');
    localStorage.setItem('pp_name', 'Student Preview');
    localStorage.setItem('user_email', 'student@preview.com');
  });

  const targetUrl = `https://abacusheroes.com/question/${CHAPTER_ID}/${QUESTION_TYPE_ID}/${SUBJECT_ID}`;
  console.log('Navigating to:', targetUrl);

  await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });

  // Wait 10 seconds for initial 2s delay + API response + render
  console.log('Waiting for loading to finish...');
  await new Promise(r => setTimeout(r, 10000));

  const shotPath = path.join(__dirname, 'ui_test_m1_q1_loaded.png');
  await page.screenshot({ path: shotPath, fullPage: false });
  console.log('Saved loaded UI screenshot to:', shotPath);

  await browser.close();
}

testModuleUI().catch(err => console.error(err));
