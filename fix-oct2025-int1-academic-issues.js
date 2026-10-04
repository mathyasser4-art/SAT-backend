const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a624c21c3d08d90637d361e';
const M2_ID = '6a624c27c3d08d90637d3624';

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
  console.log('🚀 Applying Academic & Structural Fixes for October 2025 · INT 1...\n');

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

  // M2 Q10 (6a665553c3d08d90637d399d) - Fix misplaced (x, y) formula
  console.log('Fixing M2 Q10 misplaced (x, y) formula...');
  const resQ10 = await updateQuestion('6a665553c3d08d90637d399d', {
    question: `<p>The solution to the given system of equations is ${f('(x, y)')}. What is the value of ${f('8x + 6y')}?</p><p>${f('2(8x) + 7(6y) = 21')}</p><p>${f('-2(8x) + 7(6y) = 21')}</p>`
  });
  console.log('M2 Q10 update:', resQ10.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(resQ10));

  console.log('\n✅ All Academic & Structural Fixes Applied for October 2025 INT 1!');
}

run().catch(console.error);
