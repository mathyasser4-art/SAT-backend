const puppeteer = require('puppeteer-core');
const path = require('path');

const CHAPTER_ID = '6a6855e1c3d08d90637d3b47'; // Sep 2025 INT 1 Module 1
const SUBJECT_ID = '6a622f21c3d08d90637d3466';
const QUESTION_TYPE_ID = '65a4963482dbaac16d820fc6';

async function testQ2Screenshot() {
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
  await page.goto(targetUrl, { waitUntil: 'domcontentloaded' });

  // Wait for questions to load
  await new Promise(r => setTimeout(r, 6000));

  // Click on Question 2 pill
  console.log('Clicking Question 2...');
  await page.evaluate(() => {
    const pills = Array.from(document.querySelectorAll('.loading-number-container > div, .d-flex div'));
    const pill2 = pills.find(el => el.textContent.trim() === '2');
    if (pill2) pill2.click();
  });

  await new Promise(r => setTimeout(r, 2000));

  const shotPath = path.join(__dirname, 'ui_sep2025_m1_q2_light_image.png');
  await page.screenshot({ path: shotPath, fullPage: false });
  console.log('Saved Q2 screenshot to:', shotPath);

  await browser.close();
}

testQ2Screenshot().catch(err => console.error(err));
