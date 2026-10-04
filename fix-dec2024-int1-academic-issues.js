const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';

function updateQuestion(questionId, payloadObj) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(payloadObj);
    const req = https.request(`${API_BASE}/question/updateQuestion/${questionId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          resolve({ raw: data });
        }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

async function run() {
  console.log('🚀 Applying Academic & Choice Fixes for December 2024 · INT 1...\n');

  // --- MODULE 1 ---
  console.log('1. Fixing Module 1 questions...');

  // M1 Q1: Fix answer from -5 to 2
  await updateQuestion('6aa58665ec7ba02921a44445', {
    answer: '2',
    wrongAnswer: ['-5', '-4', '3']
  });
  console.log('M1 Q1 fixed: ✅');

  // M1 Q2: Fix answer from 27 to 40
  await updateQuestion('6aa586b2ec7ba02921a44449', {
    answer: '40',
    wrongAnswer: ['27', '30', '50']
  });
  console.log('M1 Q2 fixed: ✅');

  // M1 Q3: Deduplicate choices
  await updateQuestion('6aa5874bec7ba02921a4444d', {
    answer: '<span class="ql-formula" data-value="y = x + 22"></span>',
    wrongAnswer: [
      '<span class="ql-formula" data-value="y = 24x"></span>',
      '<span class="ql-formula" data-value="y = 24x + 2"></span>',
      '<span class="ql-formula" data-value="y = 22x"></span>'
    ]
  });
  console.log('M1 Q3 fixed: ✅');

  // M1 Q4: Fix answer from f(x) = 21x to f(x) = 4x + 21
  await updateQuestion('6aa5883eec7ba02921a44458', {
    answer: '<span class="ql-formula" data-value="f(x) = 4x + 21"></span>',
    wrongAnswer: [
      '<span class="ql-formula" data-value="f(x) = 21x"></span>',
      '<span class="ql-formula" data-value="f(x) = 21x + 4"></span>',
      '<span class="ql-formula" data-value="f(x) = 4x"></span>'
    ]
  });
  console.log('M1 Q4 fixed: ✅');

  // M1 Q5: Restore equation 2x - y = 2 in stem and fix choices
  await updateQuestion('6aa588bbec7ba02921a4445c', {
    question: '<p>One of the two equations in a system of linear equations is <span class="ql-formula" data-value="2x - y = 2"></span>. The system has infinitely many solutions. If the second equation in the system is <span class="ql-formula" data-value="y = mx + b"></span>, where <span class="ql-formula" data-value="m"></span> and <span class="ql-formula" data-value="b"></span> are constants, what is the value of <span class="ql-formula" data-value="b"></span>?</p>',
    answer: '-2',
    wrongAnswer: [
      '<span class="ql-formula" data-value="-\\frac{1}{2}"></span>',
      '<span class="ql-formula" data-value="\\frac{1}{2}"></span>',
      '2'
    ]
  });
  console.log('M1 Q5 fixed: ✅');

  // M1 Q6: Deduplicate choices
  await updateQuestion('6aa5896aec7ba02921a44460', {
    answer: 'From x = 0 to x = 2',
    wrongAnswer: ['From x = 0 to x = 4', 'From x = 2 to x = 3', 'From x = 3 to x = 4']
  });
  console.log('M1 Q6 fixed: ✅');

  // M1 Q7: Deduplicate choices
  await updateQuestion('6aa589e3ec7ba02921a44464', {
    answer: '<span class="ql-formula" data-value="y = 90(1.20)^x"></span>',
    wrongAnswer: [
      '<span class="ql-formula" data-value="y = 90(1.02)^x"></span>',
      '<span class="ql-formula" data-value="y = 20(1.90)^x"></span>',
      '<span class="ql-formula" data-value="y = 20(1.09)^x"></span>'
    ]
  });
  console.log('M1 Q7 fixed: ✅');

  // M1 Q8: Deduplicate choices
  await updateQuestion('6aa58a32ec7ba02921a44468', {
    answer: '10',
    wrongAnswer: ['8', '11', '12']
  });
  console.log('M1 Q8 fixed: ✅');

  // M1 Q9: Deduplicate choices
  await updateQuestion('6aa58a70ec7ba02921a4446c', {
    answer: '14',
    wrongAnswer: ['-14', '5', '9']
  });
  console.log('M1 Q9 fixed: ✅');

  // M1 Q10: Deduplicate choices
  await updateQuestion('6aa58ad8ec7ba02921a44470', {
    answer: '-0.84',
    wrongAnswer: ['-11.19', '0.84', '11.19']
  });
  console.log('M1 Q10 fixed: ✅');

  // M1 Q11: Deduplicate choices
  await updateQuestion('6aa58b67ec7ba02921a44474', {
    answer: '48',
    wrongAnswer: ['35', '42', '58']
  });
  console.log('M1 Q11 fixed: ✅');

  // M1 Q13: Fix answer from y = 7x - 1/3 to y = -x/3 + 7
  await updateQuestion('6aa58f72ec7ba02921a44486', {
    answer: '<span class="ql-formula" data-value="y = -\\frac{x}{3} + 7"></span>',
    wrongAnswer: [
      '<span class="ql-formula" data-value="y = 7x - \\frac{1}{3}"></span>',
      '<span class="ql-formula" data-value="y = 9x + 4"></span>',
      '<span class="ql-formula" data-value="y = -\\frac{x}{3} + 4"></span>'
    ]
  });
  console.log('M1 Q13 fixed: ✅');

  // M1 Q15: Fix answer from 26pi to 156pi
  await updateQuestion('6aa59015ec7ba02921a4448e', {
    answer: '<span class="ql-formula" data-value="156\\pi"></span>',
    wrongAnswer: [
      '<span class="ql-formula" data-value="26\\pi"></span>',
      '<span class="ql-formula" data-value="78\\pi"></span>',
      '<span class="ql-formula" data-value="468\\pi"></span>'
    ]
  });
  console.log('M1 Q15 fixed: ✅');

  // M1 Q17: Fix answer and deduplicate choices
  await updateQuestion('6aa5906cec7ba02921a44496', {
    answer: 'The estimated number of online newsletter subscribers at the end of January 1997 was 500.',
    wrongAnswer: [
      'The estimated number of online newsletter subscribers at the end of the first six-month period was 500.',
      'The estimated number of online newsletter subscribers at the end of January 1998 was 1,000.',
      'The estimated number of online newsletter subscribers at the end of January 1997 was 1,000.'
    ]
  });
  console.log('M1 Q17 fixed: ✅');

  // M1 Q18: Clean up answer from 147014701470 to 1470
  await updateQuestion('6aa59163ec7ba02921a4449d', {
    answer: '1470'
  });
  console.log('M1 Q18 fixed: ✅');

  // M1 Q19: Fix answer from 0 < x < 8 to 0 < x < 40
  await updateQuestion('6aa591b1ec7ba02921a444a1', {
    answer: '0 < x < 40',
    wrongAnswer: ['0 < x < 8', '40 < x < 90', '40 < x < 130']
  });
  console.log('M1 Q19 fixed: ✅');

  // M1 Q20: Fix answer from 3m to 3
  await updateQuestion('6aa591f2ec7ba02921a444a5', {
    answer: '3',
    wrongAnswer: ['3m', '21', '21 - 3m']
  });
  console.log('M1 Q20 fixed: ✅');

  // M1 Q22: Clean up answer to 17.9
  await updateQuestion('6aa59278ec7ba02921a444ad', {
    answer: '17.9'
  });
  console.log('M1 Q22 fixed: ✅');


  // --- MODULE 2 ---
  console.log('\n2. Fixing Module 2 questions...');

  // M2 Q1: Fix answer from 24 to 66
  await updateQuestion('6aa599feec7ba02921a444c7', {
    answer: '66',
    wrongAnswer: ['24', '90', '56']
  });
  console.log('M2 Q1 fixed: ✅');

  // M2 Q2: Deduplicate choices
  await updateQuestion('6aa59a22ec7ba02921a444cb', {
    answer: '3',
    wrongAnswer: ['5', '8', '15']
  });
  console.log('M2 Q2 fixed: ✅');

  // M2 Q4: Deduplicate choices
  await updateQuestion('6aa59ac4ec7ba02921a444d3', {
    answer: '<span class="ql-formula" data-value="v = \\sqrt{\\frac{2K}{49}}"></span>',
    wrongAnswer: [
      '<span class="ql-formula" data-value="v = \\sqrt{\\frac{49}{2K}}"></span>',
      '<span class="ql-formula" data-value="v = \\frac{49v}{2K}"></span>',
      '<span class="ql-formula" data-value="v = \\frac{2K}{49v}"></span>'
    ]
  });
  console.log('M2 Q4 fixed: ✅');

  // M2 Q6: Fix answer from (0,0) to (0, 1/9)
  await updateQuestion('6aa59b62ec7ba02921a444db', {
    answer: '<span class="ql-formula" data-value="(0, \\frac{1}{9})"></span>',
    wrongAnswer: [
      '(0, 0)',
      '<span class="ql-formula" data-value="(0, \\frac{5}{9})"></span>',
      '(0, 5)'
    ]
  });
  console.log('M2 Q6 fixed: ✅');

  // M2 Q9: Fix answer from 35/16 to 54
  await updateQuestion('6aa59cadec7ba02921a444e7', {
    answer: '54',
    wrongAnswer: [
      '<span class="ql-formula" data-value="\\frac{35}{16}"></span>',
      '<span class="ql-formula" data-value="\\frac{15}{4}"></span>',
      '72'
    ]
  });
  console.log('M2 Q9 fixed: ✅');

  // M2 Q10: Fix answer from Zero to Exactly two
  await updateQuestion('6aa59ce0ec7ba02921a444eb', {
    answer: 'Exactly two',
    wrongAnswer: ['Zero', 'Exactly one', 'Infinitely many']
  });
  console.log('M2 Q10 fixed: ✅');

  // M2 Q11: Restore equation in stem and set answer to -7 only
  await updateQuestion('6aa59d26ec7ba02921a444ef', {
    question: '<p>In the given equation, <span class="ql-formula" data-value="0x = a + 7"></span>, <span class="ql-formula" data-value="a"></span> is a constant. The equation has infinitely many solutions. What are all possible values of <span class="ql-formula" data-value="a"></span>?</p>',
    answer: '-7 only',
    wrongAnswer: ['0 only', 'Any real number', 'No real number']
  });
  console.log('M2 Q11 fixed: ✅');

  // M2 Q12: Deduplicate choices
  await updateQuestion('6aa5a34dec7ba02921a44502', {
    answer: '<span class="ql-formula" data-value="\\frac{100}{33}x"></span>',
    wrongAnswer: [
      '<span class="ql-formula" data-value="\\frac{10}{33}x"></span>',
      '<span class="ql-formula" data-value="\\frac{1}{33}x"></span>',
      '<span class="ql-formula" data-value="\\frac{67}{100}x"></span>'
    ]
  });
  console.log('M2 Q12 fixed: ✅');

  // M2 Q13: Clean up answer to 5/7
  await updateQuestion('6aa5a9a2ec7ba02921a4450c', {
    answer: '5/7'
  });
  console.log('M2 Q13 fixed: ✅');

  // M2 Q14: Fix answer from y = x + 13 to y = 11(x - 1) + 13
  await updateQuestion('6aa5a9d4ec7ba02921a44510', {
    answer: '<span class="ql-formula" data-value="y = 11(x - 1) + 13"></span>',
    wrongAnswer: [
      '<span class="ql-formula" data-value="y = x + 13"></span>',
      '<span class="ql-formula" data-value="y = 11x + 13"></span>',
      '<span class="ql-formula" data-value="y = (x - 1) + 13"></span>'
    ]
  });
  console.log('M2 Q14 fixed: ✅');

  // M2 Q15: Set answer to 31.3
  await updateQuestion('6aa5addaec7ba02921a44514', {
    answer: '31.3',
    wrongAnswer: ['0.171', '0.829', '17.1']
  });
  console.log('M2 Q15 fixed: ✅');

  // M2 Q16: Set answer to f(x) = -d - cx
  await updateQuestion('6aa5aeb1ec7ba02921a44518', {
    answer: '<span class="ql-formula" data-value="f(x) = -d - cx"></span>',
    wrongAnswer: [
      '<span class="ql-formula" data-value="f(x) = d + cx"></span>',
      '<span class="ql-formula" data-value="f(x) = d - cx"></span>',
      '<span class="ql-formula" data-value="f(x) = -d + cx"></span>'
    ]
  });
  console.log('M2 Q16 fixed: ✅');

  // M2 Q18: Set answer to 12,560c
  await updateQuestion('6aa5af7dec7ba02921a44520', {
    answer: '<span class="ql-formula" data-value="12,560c"></span>',
    wrongAnswer: [
      '<span class="ql-formula" data-value="6,125c"></span>',
      '<span class="ql-formula" data-value="6,008c"></span>',
      '<span class="ql-formula" data-value="1,850c"></span>'
    ]
  });
  console.log('M2 Q18 fixed: ✅');

  // M2 Q19: Set answer to -112
  await updateQuestion('6aa5afe1ec7ba02921a44524', {
    answer: '-112',
    wrongAnswer: ['-56', '-28', '-7']
  });
  console.log('M2 Q19 fixed: ✅');

  // M2 Q20: Set answer to 100(b - 1)
  await updateQuestion('6aa5b053ec7ba02921a4460e', {
    answer: '<span class="ql-formula" data-value="100(b - 1)"></span>',
    wrongAnswer: [
      '<span class="ql-formula" data-value="1 + \\frac{b}{100}"></span>',
      '<span class="ql-formula" data-value="b + 100"></span>',
      '<span class="ql-formula" data-value="100(b + 1)"></span>'
    ]
  });
  console.log('M2 Q20 fixed: ✅');

  // M2 Q21: Set answer to 1,044k/m
  await updateQuestion('6aa5b082ec7ba02921a44612', {
    answer: '<span class="ql-formula" data-value="\\frac{1,044k}{m}"></span>',
    wrongAnswer: [
      '<span class="ql-formula" data-value="\\frac{29m}{4k}"></span>',
      '<span class="ql-formula" data-value="\\frac{29k}{4m}"></span>',
      '<span class="ql-formula" data-value="\\frac{1,044m}{k}"></span>'
    ]
  });
  console.log('M2 Q21 fixed: ✅');

  // M2 Q22: Clean up answer to 86.5
  await updateQuestion('6aa5b103ec7ba02921a44616', {
    answer: '86.5'
  });
  console.log('M2 Q22 fixed: ✅');

  console.log('\n🎉 All Academic & Choice Fixes Successfully Applied for December 2024 INT 1!');
}

run().catch(console.error);
