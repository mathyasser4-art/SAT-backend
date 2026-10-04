const https = require('https');

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

function stripHtml(s) {
  if (!s) return '';
  return s.replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
}

async function run() {
  console.log('🚀 Applying Academic & Structural Fixes for March 2026 · INT 2...\n');

  const m1Res = await new Promise((resolve, reject) => {
    https.get(`${API_BASE}/chapter/getChapterQuestion/6a53d2914d554e04aa1bf8e2`, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve(JSON.parse(data)));
    }).on('error', reject);
  });
  const m2Res = await new Promise((resolve, reject) => {
    https.get(`${API_BASE}/chapter/getChapterQuestion/6a53d2994d554e04aa1bf8e8`, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve(JSON.parse(data)));
    }).on('error', reject);
  });

  const m1 = m1Res.chapter.questions;
  const m2 = m2Res.chapter.questions;

  // 1. Choice Deduplication across M1 and M2
  console.log('1. Deduplicating choices across all MCQs...');
  for (const q of [...m1, ...m2]) {
    if (q.typeOfAnswer === 'MCQ' && Array.isArray(q.wrongAnswer)) {
      const correctClean = stripHtml(q.correctAnswer);
      const seen = new Set([correctClean]);
      const uniqueWrong = [];

      for (const w of q.wrongAnswer) {
        const wClean = stripHtml(w);
        if (!seen.has(wClean) && w !== q.correctAnswer) {
          seen.add(wClean);
          uniqueWrong.push(w);
        }
      }

      if (uniqueWrong.length !== q.wrongAnswer.length) {
        process.stdout.write(`Deduplicating Q ${q._id}... `);
        const res = await updateQuestion(q._id, { wrongAnswer: uniqueWrong });
        console.log(res.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(res));
      }
    }
  }

  // 2. Specific Question Fixes
  console.log('\n2. Applying specific question fixes...');

  // M1 Q15 (6a53dc254d554e04aa1bf984) - Fix stem "Which equation defines f?" and clean choices
  console.log('Fixing M1 Q15 stem and choices...');
  await updateQuestion('6a53dc254d554e04aa1bf984', {
    question: `<p>An object is launched from a height of 132 feet above the ground. A quadratic function ${f('f')} models the height above the ground, in feet, of the object ${f('t')} seconds after it is launched. According to the model, 3 seconds after the object is launched, it reaches a maximum height of 276 feet above the ground. Which equation defines ${f('f')}?</p>`,
    correctAnswer: `<p>${f('f(t) = -16(t - 3)^2 + 276')}</p>`,
    wrongAnswer: [
      `<p>${f('f(t) = -16(t + 3)^2 + 276')}</p>`,
      `<p>${f('f(t) = -16(t - 3)^2 + 132')}</p>`,
      `<p>${f('f(t) = -16(t + 3)^2 + 132')}</p>`
    ]
  });

  // M1 Q16 (6a53dcac4d554e04aa1bf988) - Fix y-intercept calculation: f(0)=72, h(0)=72+7=79 (DB had 11!)
  console.log('Fixing M1 Q16 correctAnswer to 79 and wrongAnswers...');
  await updateQuestion('6a53dcac4d554e04aa1bf988', {
    correctAnswer: `<p>${f('79')}</p>`,
    wrongAnswer: [
      `<p>${f('72')}</p>`,
      `<p>${f('7')}</p>`,
      `<p>${f('0')}</p>`
    ]
  });

  // M1 Q17 (6a53dd5a4d554e04aa1bf994) - Clean choices for angle conversion
  console.log('Fixing M1 Q17 choices LaTeX...');
  await updateQuestion('6a53dd5a4d554e04aa1bf994', {
    correctAnswer: `<p>${f('\\frac{9}{11} \\times 540')}</p>`,
    wrongAnswer: [
      `<p>${f('\\frac{9}{11} \\times 90 \\times 3')}</p>`,
      `<p>${f('\\frac{90}{11\\pi} \\times 3')}</p>`,
      `<p>${f('\\frac{9\\pi}{11} \\times 180 \\times 3')}</p>`
    ]
  });

  // M1 Q20 (6a53df374d554e04aa1bf9b2) - Fix function notation P(t)
  console.log('Fixing M1 Q20 function notation P(t)...');
  await updateQuestion('6a53df374d554e04aa1bf9b2', {
    question: `<p><strong>Reindeer Population Study</strong></p><p>A reindeer population was introduced into an area and researched for 19 years. Function ${f('P')} models this reindeer population ${f('t')} years after the population was introduced into the area.</p><p>${f('P(t) = 67.5\\left(\\frac{5}{4}\\right)^t')}</p><p>Which statement is the best interpretation of ${f('\\frac{5}{4}')} in this context?</p>`
  });

  // M2 Q8 (6a53f2fc4d554e04aa1bfa47) - Clean stem "What value of x is the solution to the given equation?"
  console.log('Fixing M2 Q8 stem wording...');
  await updateQuestion('6a53f2fc4d554e04aa1bfa47', {
    question: `<p>What value of ${f('x')} is the solution to the given equation?</p><p>${f('97 - x + 5 = 95')}</p>`,
    correctAnswer: `<p>${f('7')}</p>`,
    wrongAnswer: [
      `<p>${f('14')}</p>`,
      `<p>${f('-3')}</p>`,
      `<p>${f('-14')}</p>`
    ]
  });

  // M2 Q9 (6a53f3604d554e04aa1bfa4d) - Add missing question prompt and clean choices
  console.log('Fixing M2 Q9 stem and choices LaTeX...');
  await updateQuestion('6a53f3604d554e04aa1bfa4d', {
    question: `<p>${f('f(x) = x^2 - 4x - 780')}</p><p>The function ${f('f')} is defined by the given equation. Which of the following equivalent forms of the equation displays the minimum value of the function as a constant or coefficient?</p>`,
    correctAnswer: `<p>${f('f(x) = (x - 2)^2 - 784')}</p>`,
    wrongAnswer: [
      `<p>${f('f(x) = (x + 26)(x - 30)')}</p>`,
      `<p>${f('f(x) = x(x - 4) - 780')}</p>`,
      `<p>${f('f(x) = x^2 - 4x + 195')}</p>`
    ]
  });

  // M2 Q22 (6a53fb134d554e04aa1bfb2c) - Restore missing negative sign in RHS: 4x^2 - px + w = -85
  console.log('Fixing M2 Q22 stem formula (-85)...');
  await updateQuestion('6a53fb134d554e04aa1bfb2c', {
    question: `<p>In the given equation, ${f('p')} and ${f('w')} are integer constants. The equation has exactly one real solution. Which is NOT a possible value of ${f('w')}?</p><p>${f('4x^2 - px + w = -85')}</p>`,
    correctAnswer: `<p>${f('64')}</p>`,
    wrongAnswer: [
      `<p>${f('-21')}</p>`,
      `<p>${f('15')}</p>`,
      `<p>${f('315')}</p>`
    ]
  });

  console.log('\n✅ All Academic & Structural Fixes Applied for March 2026 INT 2!');
}

run().catch(console.error);
