const https = require('https');
const fs = require('fs');

const API_BASE = 'https://sat-backend-production.up.railway.app';

function f(formula) {
  return `<span class="ql-formula" data-value="${formula}"></span>`;
}

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
  console.log('Applying Academic & Structural Fixes for March 2026 US 2...\n');

  // Load both modules
  const m1 = JSON.parse(fs.readFileSync('scratch_march_2026_us2_m1.json', 'utf8')).chapter.questions;
  const m2 = JSON.parse(fs.readFileSync('scratch_march_2026_us2_m2.json', 'utf8')).chapter.questions;

  // 1. Remove duplicate correctAnswer from wrongAnswer across all MCQs in M1 and M2
  console.log('1. Cleaning duplicate choices across all MCQs in M1 & M2...');
  for (const q of [...m1, ...m2]) {
    if (q.typeOfAnswer === 'MCQ' && Array.isArray(q.wrongAnswer)) {
      const filtered = q.wrongAnswer.filter(w => w !== q.correctAnswer);
      if (filtered.length !== q.wrongAnswer.length) {
        process.stdout.write(`Deduplicating ${q._id}... `);
        const res = await updateQuestion(q._id, { wrongAnswer: filtered });
        console.log(res.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(res));
      }
    }
  }

  // 2. Specific Academic Fixes
  console.log('\n2. Applying specific academic & stem fixes...');

  // M1 Q1 (6a52d4d14d554e04aa1bf38c) - Fix corrupted formula 231.20^x to 23(1.20)^{x/8}
  console.log('Fixing M1 Q1 formula...');
  await updateQuestion('6a52d4d14d554e04aa1bf38c', {
    question: `<p>${f('f(x) = 23(1.20)^{x/8}')}</p><p>For the given function ${f('f')}, the value of ${f('f(x)')} increased by ${f('p\\%')} for every increase of ${f('x')} by 8. What is the value of ${f('p')}?</p>`
  });

  // M1 Q3 (6a52d69a4d554e04aa1bf3a4) - Fix correct key to d = -60.1 + 2.0t
  console.log('Fixing M1 Q3 correct key to d = -60.1 + 2.0t...');
  await updateQuestion('6a52d69a4d554e04aa1bf3a4', {
    correctAnswer: `<p>${f('d = -60.1 + 2.0t')}</p>`,
    wrongAnswer: [
      `<p>${f('d = 359.8 + 2.0t')}</p>`,
      `<p>${f('d = 160.1 + 2.0t')}</p>`,
      `<p>${f('d = 394.8 + 2.0t')}</p>`
    ]
  });

  // M1 Q7 (6a52e25a4d554e04aa1bf40c) - Fix equation to 4x^2 - px + w = -86 and correct key to 25
  console.log('Fixing M1 Q7 equation (-86) and correct key (25)...');
  await updateQuestion('6a52e25a4d554e04aa1bf40c', {
    question: `<p>In the given equation, ${f('p')} and ${f('w')} are integer constants. The equation has exactly one real solution. Which is NOT a possible value of ${f('w')}?</p><p>${f('4x^2 - px + w = -86')}</p>`,
    correctAnswer: '<p>25</p>',
    wrongAnswer: ['<p>-22</p>', '<p>14</p>', '<p>314</p>']
  });

  // M1 Q15 (6a52e8e44d554e04aa1bf462) - Fix correct key to y < 4x + 1
  console.log('Fixing M1 Q15 correct key to y < 4x + 1...');
  await updateQuestion('6a52e8e44d554e04aa1bf462', {
    correctAnswer: `<p>${f('y < 4x + 1')}</p>`,
    wrongAnswer: [
      `<p>${f('y > \\frac{1}{4}x + 1')}</p>`,
      `<p>${f('y < \\frac{1}{4}x + 1')}</p>`,
      `<p>${f('y > 4x + 1')}</p>`
    ]
  });

  // M2 Q9 (6a53be6e4d554e04aa1bf788) - Fix stem typo "Line segments NH are tangent" -> "Line segments MH and NH are tangent"
  console.log('Fixing M2 Q9 stem typo...');
  await updateQuestion('6a53be6e4d554e04aa1bf788', {
    question: `<p>A circle has center ${f('G')}, and points ${f('M')} and ${f('N')} lie on the circle. Line segments ${f('MH')} and ${f('NH')} are tangent to the circle at points ${f('M')} and ${f('N')}, respectively. If the radius of the circle is 247 millimeters and the perimeter of quadrilateral ${f('GMHN')} is 5,174 millimeters, what is the distance, in millimeters, between points ${f('G')} and ${f('H')}?</p>`
  });

  // M2 Q12 (6a53c3a14d554e04aa1bf7f5) - Fix correct key to y < 3x + 5
  console.log('Fixing M2 Q12 correct key to y < 3x + 5...');
  await updateQuestion('6a53c3a14d554e04aa1bf7f5', {
    correctAnswer: `<p>${f('y < 3x + 5')}</p>`,
    wrongAnswer: [
      `<p>${f('y > \\frac{1}{3}x + 5')}</p>`,
      `<p>${f('y < \\frac{1}{3}x + 5')}</p>`,
      `<p>${f('y > 3x + 5')}</p>`
    ]
  });

  // M2 Q18 (6a53ce624d554e04aa1bf83e) - Fix function to f(x) = 3x - 4 so that a = 1 is mathematically true
  console.log('Fixing M2 Q18 function to f(x) = 3x - 4...');
  await updateQuestion('6a53ce624d554e04aa1bf83e', {
    question: `<p>The function ${f('f')} is defined by ${f('f(x) = 3x - 4')}. If ${f('f(a + 1) = 2a')}, what is the value of ${f('a')}?</p>`,
    correctAnswer: '<p>1</p>',
    wrongAnswer: ['<p>-1</p>', '<p>5</p>', '<p>6</p>']
  });

  // M2 Q19 (6a53cf164d554e04aa1bf842) - Fix dollar700 typo
  console.log('Fixing M2 Q19 dollar700 typo...');
  await updateQuestion('6a53cf164d554e04aa1bf842', {
    question: `<p>A certain investment account offers a special interest rate for the first 4 months the account is open followed by a lower interest rate for the remainder of the time the account is open. Bennett opened one of these accounts with an original account balance of 700 dollars and did not make any other deposits or withdrawals. 4 months after Bennett opened the account, the balance had increased by ${f('0.6\\%')} of the original balance. 6 months after Bennett opened the account, the balance had increased by an additional ${f('0.2\\%')} of the balance at the end of the first 4 months. Every 2 months after the first 6 months, the balance had increased by an additional ${f('0.2\\%')} of the balance 2 months before. Which of the following equations could represent the account balance ${f('B_x')}, in dollars, ${f('x')} months after the account was opened, where ${f('x \\ge 4')}?</p>`
  });

  // M2 Q21 (6a53d0854d554e04aa1bf853) - Restore missing stem and fix formula (+w = -85)
  console.log('Restoring M2 Q21 missing stem and formula...');
  await updateQuestion('6a53d0854d554e04aa1bf853', {
    question: `<p>In the given equation, ${f('p')} and ${f('w')} are integer constants. The equation has exactly one real solution. Which is NOT a possible value of ${f('w')}?</p><p>${f('4x^2 - px + w = -85')}</p>`,
    correctAnswer: `<p>${f('64')}</p>`,
    wrongAnswer: [
      `<p>${f('-21')}</p>`,
      `<p>${f('15')}</p>`,
      `<p>${f('315')}</p>`
    ]
  });

  console.log('\n🎉 Finished applying all academic & structural fixes!');
}

run().catch(console.error);
