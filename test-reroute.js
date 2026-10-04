const puppeteer = require('puppeteer-core');
const path = require('path');

const CHAPTER_ID = '6a6855e1c3d08d90637d3b47'; // Sep 2025 INT 1 Module 1
const SUBJECT_ID = '6a622f21c3d08d90637d3466';
const QUESTION_TYPE_ID = '65a4963482dbaac16d820fc6';

async function testReroute() {
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
      const newUrl = url.replace('backend-production-6752.up.railway.app', 'sat-backend-production.up.railway.app');
      console.log('Rerouting API request:', url, '->', newUrl);
      req.continue({ url: newUrl });
    } else {
      req.continue();
    }
  });

  page.on('response', res => {
    if (res.url().includes('getChapterQuestion')) {
      console.log('getChapterQuestion status:', res.status());
    }
  });

  await page.evaluateOnNewDocument(() => {
    localStorage.setItem('O_authWEB', 'mock_token_for_student_view');
    localStorage.setItem('auth_role', 'Student');
    localStorage.setItem('pp_name', 'Student Preview');
    localStorage.setItem('user_email', 'student@preview.com');
  });

  const targetUrl = `https://abacusheroes.com/question/${CHAPTER_ID}/${QUESTION_TYPE_ID}/${SUBJECT_ID}`;
  console.log('Navigating to:', targetUrl);

  await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });

  console.log('Waiting for questions to load...');
  await new Promise(r => setTimeout(r, 6000));

  const shotPath = path.join(__dirname, 'ui_test_rerouted.png');
  await page.screenshot({ path: shotPath, fullPage: false });
  console.log('Saved screenshot to:', shotPath);

  await browser.close();
}

testReroute().catch(err => console.error(err));
