const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a6d285814cab24f9785a709';
const M2_ID = '6a6d285d14cab24f9785a70f';

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
  console.log('🚀 Applying Academic & Structural Fixes for June 2025 · INT 1...\n');

  // 1. Specific Question Fixes
  console.log('1. Applying specific question fixes...');

  // M1 Q2 (6a6d2d1f14cab24f9785a721) - Fix duplicated text in stem
  console.log('Fixing M1 Q2 stem...');
  const resM1Q2 = await updateQuestion('6a6d2d1f14cab24f9785a721', {
    question: `<p>The function ${f('f')} is defined by ${f('f(x) = 3^x')}. The function ${f('g')} is an increasing linear function. In the ${f('xy')}-plane, the graphs of ${f('y = f(x)')} and ${f('y = g(x)')} intersect at two points ${f('(a, j)')} and ${f('(b, k)')}, where ${f('j < k')}. When ${f('g(x) > f(x)')}, which of the following must be true?</p>`
  });
  console.log('M1 Q2 update:', resM1Q2.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(resM1Q2));

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
    if (q.typeOfAnswer === 'MCQ' && Array.isArray(q.wrongAnswer)) {
      const correctClean = stripHtml(q.correctAnswer);
      const seen = new Set([correctClean]);
      const uniqueWrong = [];

      for (const w of q.wrongAnswer) {
        const wClean = stripHtml(w);
        // Also check raw string in case HTML stripping leaves empty string for images
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

  console.log('\n✅ All Academic & Structural Fixes Applied for June 2025 INT 1!');
}

run().catch(console.error);
