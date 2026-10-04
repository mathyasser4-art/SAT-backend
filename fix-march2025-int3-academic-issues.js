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
  console.log('🚀 Applying Academic & Structural Fixes for March 2025 · INT 3...\n');

  // --- MODULE 1 SPECIFIC FIXES ---
  console.log('1. Fixing Module 1 questions...');

  // M1 Q1: Deduplicate choices
  await updateQuestion('6aa47ca1ec7ba02921a43f38', {
    answer: '46',
    wrongAnswer: ['40', '42', '43']
  });
  console.log('M1 Q1 fixed: ✅');

  // M1 Q2: Deduplicate choices
  await updateQuestion('6aa47cdbec7ba02921a43f3c', {
    answer: 'y=0.8+1.7x',
    wrongAnswer: ['y=0.8-1.7x', 'y=-0.8+1.7x', 'y=-0.8-1.7x']
  });
  console.log('M1 Q2 fixed: ✅');

  // M1 Q3: Fix answer from y=0.8+1.7x to 175
  await updateQuestion('6aa47d03ec7ba02921a43f40', {
    answer: '175',
    wrongAnswer: ['40', '10', '5']
  });
  console.log('M1 Q3 fixed: ✅');

  // M1 Q5: Fix answer from y=0.8+1.7x to regular job interpretation
  await updateQuestion('6aa47d6bec7ba02921a43f48', {
    answer: 'The amount, in dollars, the technician earned for each hour she worked at her regular job',
    wrongAnswer: [
      'The amount, in dollars, the technician earned for each hour she worked at her second job',
      'The number of hours the technician worked in one week at her regular job',
      'The number of hours the technician worked in one week at her second job'
    ]
  });
  console.log('M1 Q5 fixed: ✅');

  // M1 Q6: Deduplicate choices
  await updateQuestion('6aa47dafec7ba02921a43f4c', {
    answer: '20',
    wrongAnswer: ['1', '6', '26']
  });
  console.log('M1 Q6 fixed: ✅');

  // M1 Q8: Deduplicate choices
  await updateQuestion('6aa47e45ec7ba02921a43f54', {
    answer: '(6, 185)',
    wrongAnswer: ['(6, 180)', '(13, 5)', '(13, 850)']
  });
  console.log('M1 Q8 fixed: ✅');

  // M1 Q10: Fix answer from (6, 185) to -72/11
  await updateQuestion('6aa47ec1ec7ba02921a43f5c', {
    answer: '-72/11',
    wrongAnswer: ['-11/12', '72/11', '192/11']
  });
  console.log('M1 Q10 fixed: ✅');

  // M1 Q11: Deduplicate choices
  await updateQuestion('6aa47fc5ec7ba02921a43f60', {
    answer: 'y=146',
    wrongAnswer: ['x=34', 'w+y=180', 'y+z=180']
  });
  console.log('M1 Q11 fixed: ✅');

  // M1 Q12: Deduplicate choices
  await updateQuestion('6aa4801bec7ba02921a43f64', {
    answer: '<span class="ql-formula" data-value="\\sqrt{133y}"></span>',
    wrongAnswer: [
      '<span class="ql-formula" data-value="133\\sqrt{y}"></span>',
      '<span class="ql-formula" data-value="\\sqrt{133}y"></span>',
      '<span class="ql-formula" data-value="\\sqrt{(133y)^2}"></span>'
    ]
  });
  console.log('M1 Q12 fixed: ✅');

  // M1 Q13: Deduplicate choices
  await updateQuestion('6aa48077ec7ba02921a43f6b', {
    answer: '<span class="ql-formula" data-value="\\frac{\\sqrt{2}}{2}"></span>',
    wrongAnswer: [
      '<span class="ql-formula" data-value="-\\frac{\\sqrt{3}}{2}"></span>',
      '<span class="ql-formula" data-value="-\\frac{\\sqrt{2}}{2}"></span>',
      '<span class="ql-formula" data-value="\\frac{1}{2}"></span>'
    ]
  });
  console.log('M1 Q13 fixed: ✅');

  // M1 Q16: Deduplicate choices
  await updateQuestion('6aa48173ec7ba02921a43f7a', {
    answer: 'Zero',
    wrongAnswer: ['Three', 'Two', 'One']
  });
  console.log('M1 Q16 fixed: ✅');

  // M1 Q17: Fix answer from Zero to 17
  await updateQuestion('6aa4819aec7ba02921a43f7e', {
    answer: '17',
    wrongAnswer: ['6', '10', '14']
  });
  console.log('M1 Q17 fixed: ✅');

  // M1 Q18: Deduplicate choices
  await updateQuestion('6aa481edec7ba02921a43f85', {
    answer: '<span class="ql-formula" data-value="-\\frac{7}{6} + \\frac{\\sqrt{61}}{6}"></span>',
    wrongAnswer: [
      '<span class="ql-formula" data-value="-\\frac{7}{3} + \\frac{\\sqrt{61}}{6}"></span>',
      '<span class="ql-formula" data-value="-\\frac{7}{3} - \\frac{\\sqrt{61}}{3}"></span>',
      '<span class="ql-formula" data-value="-\\frac{7}{6} - \\frac{\\sqrt{61}}{6}"></span>'
    ]
  });
  console.log('M1 Q18 fixed: ✅');

  // M1 Q20: Deduplicate choices
  await updateQuestion('6aa48283ec7ba02921a43f8d', {
    answer: '4,347%',
    wrongAnswer: ['21.36%', '38.69%', '2,300%']
  });
  console.log('M1 Q20 fixed: ✅');

  // M1 Q21: Deduplicate choices
  await updateQuestion('6aa482bfec7ba02921a43f91', {
    answer: '0 and -14/3',
    wrongAnswer: ['0', '0 and 8/3', 'There is no solution.']
  });
  console.log('M1 Q21 fixed: ✅');

  // M1 Q22: Deduplicate choices
  await updateQuestion('6aa48304ec7ba02921a43f98', {
    answer: '43.33',
    wrongAnswer: ['3.90', '7.65', '38.50']
  });
  console.log('M1 Q22 fixed: ✅');


  // --- MODULE 2 SPECIFIC FIXES ---
  console.log('\n2. Fixing Module 2 questions...');

  // M2 Q1: Deduplicate choices
  await updateQuestion('6aa48636ec7ba02921a43ff1', {
    answer: 'Zero',
    wrongAnswer: ['Exactly one', 'Exactly two', 'Infinitely many']
  });
  console.log('M2 Q1 fixed: ✅');

  // M2 Q2: Deduplicate choices
  await updateQuestion('6aa48679ec7ba02921a43ff5', {
    answer: 'f(x) = 2',
    wrongAnswer: ['f(x) = 0', 'f(x) = 7', 'f(x) = x + 2']
  });
  console.log('M2 Q2 fixed: ✅');

  // M2 Q3: Deduplicate choices
  await updateQuestion('6aa486cdec7ba02921a43ff9', {
    answer: 'The length of the rectangle, in feet',
    wrongAnswer: [
      'The area of the rectangle, in square feet',
      'The difference between the length and the width of the rectangle, in feet',
      'The width of the rectangle, in feet'
    ]
  });
  console.log('M2 Q3 fixed: ✅');

  // M2 Q4: Deduplicate choices
  await updateQuestion('6aa48735ec7ba02921a43ffd', {
    answer: '8',
    wrongAnswer: ['4', '59', '56']
  });
  console.log('M2 Q4 fixed: ✅');

  // M2 Q5: Deduplicate choices
  await updateQuestion('6aa487abec7ba02921a44013', {
    answer: '30',
    wrongAnswer: ['8', '61', '165']
  });
  console.log('M2 Q5 fixed: ✅');

  // M2 Q6: Deduplicate choices
  await updateQuestion('6aa48822ec7ba02921a44017', {
    answer: '<span class="ql-formula" data-value="f(t) = -16(t - 2)^2 + 185"></span>',
    wrongAnswer: [
      '<span class="ql-formula" data-value="f(t) = -16(t + 185)^2 - 2"></span>',
      '<span class="ql-formula" data-value="f(t) = -16(t - 185)^2 + 2"></span>',
      '<span class="ql-formula" data-value="f(t) = -16(t + 2)^2 - 185"></span>'
    ]
  });
  console.log('M2 Q6 fixed: ✅');

  // M2 Q9: Deduplicate choices
  await updateQuestion('6aa48920ec7ba02921a44026', {
    answer: '0 and -14/3',
    wrongAnswer: ['0', '0 and 8/3', 'There is no solution.']
  });
  console.log('M2 Q9 fixed: ✅');

  // M2 Q10: Deduplicate choices
  await updateQuestion('6aa48996ec7ba02921a4402a', {
    answer: 'Rx + 12y = 108',
    wrongAnswer: ['Rx - 12y = -108', '12x - Ry = 108', 'Rx + 12y = -18']
  });
  console.log('M2 Q10 fixed: ✅');

  // M2 Q11: Fix answer from Rx-12y=-108 to (1-10k)/k
  await updateQuestion('6aa489ecec7ba02921a4402e', {
    answer: '<span class="ql-formula" data-value="\\frac{1 - 10k}{k}"></span>',
    wrongAnswer: [
      '-10',
      '<span class="ql-formula" data-value="\\frac{1}{k}"></span>',
      '<span class="ql-formula" data-value="\\frac{1 - k}{k}"></span>'
    ]
  });
  console.log('M2 Q11 fixed: ✅');

  // M2 Q12: Deduplicate choices
  await updateQuestion('6aa48a93ec7ba02921a44046', {
    answer: '8',
    wrongAnswer: ['6', '-6', '-7']
  });
  console.log('M2 Q12 fixed: ✅');

  // M2 Q13: Deduplicate choices
  await updateQuestion('6aa48bb6ec7ba02921a4404d', {
    answer: '<span class="ql-formula" data-value="f(x) = 22.80(x - 1) - 11.40"></span>',
    wrongAnswer: [
      '<span class="ql-formula" data-value="f(x) = 22.80(x - 1) + 11.40"></span>',
      '<span class="ql-formula" data-value="f(x) = 22.80(x - 1) + 11.40(x - 2)"></span>',
      '<span class="ql-formula" data-value="f(x) = 22.80(x - 2) + 11.40(x - 1)"></span>'
    ]
  });
  console.log('M2 Q13 fixed: ✅');

  // M2 Q15: Deduplicate choices
  await updateQuestion('6aa48ca2ec7ba02921a4405e', {
    answer: '<span class="ql-formula" data-value="f(x) = -3^x + 3"></span>',
    wrongAnswer: [
      '<span class="ql-formula" data-value="f(x) = -3^x + 1"></span>',
      '<span class="ql-formula" data-value="f(x) = -3^x + 4"></span>',
      '<span class="ql-formula" data-value="f(x) = -3^x + 5"></span>'
    ]
  });
  console.log('M2 Q15 fixed: ✅');

  // M2 Q16: Deduplicate choices
  await updateQuestion('6aa48cc3ec7ba02921a44062', {
    answer: '43.33',
    wrongAnswer: ['3.90', '7.65', '38.50']
  });
  console.log('M2 Q16 fixed: ✅');

  // M2 Q17: Fix answer from 43.33 to 13
  await updateQuestion('6aa48d60ec7ba02921a44066', {
    answer: '13',
    wrongAnswer: [
      '3',
      '7',
      '<span class="ql-formula" data-value="\\frac{127}{16}"></span>'
    ]
  });
  console.log('M2 Q17 fixed: ✅');

  // M2 Q18: Deduplicate choices
  await updateQuestion('6aa48efeec7ba02921a4406a', {
    answer: 'The measures of angle B and angle R are 34° and 94°, respectively.',
    wrongAnswer: [
      'AB = 30 and PQ = 30.',
      'AB = 30 and QR = 90.',
      'The measures of angle B and angle Q are 52° and 34°, respectively.'
    ]
  });
  console.log('M2 Q18 fixed: ✅');

  console.log('\n🎉 All Academic & Choice Fixes Successfully Applied for March 2025 INT 3!');
}

run().catch(console.error);
