const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a6d4b8e14cab24f9785a814';
const M2_ID = '6a6d4b9614cab24f9785a81a';

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
  console.log('🚀 Applying Academic & Structural Fixes for June 2025 · INT 2...\n');

  // 1. Specific Question Fixes
  console.log('1. Applying specific question fixes...');

  // M1 Q4 (6a6d4e0214cab24f9785a84b) - Add missing expression to stem
  console.log('Fixing M1 Q4 stem...');
  const resM1Q4 = await updateQuestion('6a6d4e0214cab24f9785a84b', {
    question: `<p>Which expression is equivalent to ${f('(x^3 + 9x^2 - 8x) + 5(x^2 + 8)')}?</p>`
  });
  console.log('M1 Q4 update:', resM1Q4.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(resM1Q4));

  // M1 Q12 (6a6d581714cab24f9785a8ba) - Add question text to stem
  console.log('Fixing M1 Q12 stem...');
  const resM1Q12 = await updateQuestion('6a6d581714cab24f9785a8ba', {
    question: `<p>The given equation relates the positive variables ${f('C')}, ${f('N')}, and ${f('P')}. Which equation correctly expresses ${f('C')} in terms of ${f('N')} and ${f('P')}?</p><p>${f('PC = N(18 - C)')}</p>`,
    correctAnswer: `<p>${f('C = \\frac{18N}{N + P}')}</p>`,
    wrongAnswer: [
      `<p>${f('C = \\frac{C(N + P)}{N}')}</p>`,
      `<p>${f('C = \\frac{PC}{18 - C}')}</p>`,
      `<p>${f('C = \\frac{18N}{P + 1}')}</p>`
    ]
  });
  console.log('M1 Q12 update:', resM1Q12.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(resM1Q12));

  // M1 Q21 (6a6d60ce14cab24f9785a8e2) - Add question text to stem
  console.log('Fixing M1 Q21 stem...');
  const resM1Q21 = await updateQuestion('6a6d60ce14cab24f9785a8e2', {
    question: `<p>${f('f(x) = (x - 1)^2 + 7')}</p><p>What is the minimum value of the given function?</p>`
  });
  console.log('M1 Q21 update:', resM1Q21.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(resM1Q21));

  // Fetch updated modules for deduplication
  const m1Res = await new Promise((resolve, reject) => {
    https.get(`${API_BASE}/chapter/getChapterQuestion/${M1_ID}`, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve(JSON.parse(data)));
    }).on('error', reject);
  });
  const m2Res = await new Promise((resolve, reject) => {
    https.get(`${API_BASE}/chapter/getChapterQuestion/${M2_ID}`, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve(JSON.parse(data)));
    }).on('error', reject);
  });

  const m1 = m1Res.chapter.questions;
  const m2 = m2Res.chapter.questions;

  // 2. Choice Deduplication across all MCQs
  console.log('\n2. Deduplicating choices across all MCQs...');
  for (const q of [...m1, ...m2]) {
    if (q._id === '6a6d581714cab24f9785a8ba') continue;

    if (q.typeOfAnswer === 'MCQ' && Array.isArray(q.wrongAnswer)) {
      const correctClean = stripHtml(q.correctAnswer);
      const seen = new Set([correctClean]);
      const uniqueWrong = [];

      for (const w of q.wrongAnswer) {
        const wClean = stripHtml(w);
        const wKey = wClean.length > 0 ? wClean : w.trim();
        const cKey = correctClean.length > 0 ? correctClean : q.correctAnswer.trim();

        if (!seen.has(wKey) && wKey !== cKey) {
          seen.add(wKey);
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

  console.log('\n✅ All Academic & Structural Fixes Applied for June 2025 INT 2!');
}

run().catch(console.error);
