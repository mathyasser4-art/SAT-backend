const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a626236c3d08d90637d367e';
const M2_ID = '6a626240c3d08d90637d3684';

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
  console.log('🚀 Applying Academic & Structural Fixes for October 2025 · INT 2...\n');

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

  // 1. Specific Question Fixes BEFORE deduplication
  console.log('1. Applying specific question fixes...');

  // M1 Q4 (6a6267efc3d08d90637d36d8) - Correct answer sign error (-16 -> 16)
  console.log('Fixing M1 Q4 sign error in correct answer...');
  const resQ4 = await updateQuestion('6a6267efc3d08d90637d36d8', {
    correctAnswer: '<p>16</p>',
    wrongAnswer: ['<p>-16</p>', '<p>-2</p>', '<p>2</p>']
  });
  console.log('M1 Q4 update:', resQ4.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(resQ4));

  // M1 Q15 (6a6279b9c3d08d90637d3724) - Correct answer sign error (-12 -> 12)
  console.log('Fixing M1 Q15 sign error in correct answer...');
  const resQ15 = await updateQuestion('6a6279b9c3d08d90637d3724', {
    correctAnswer: '<p>12</p>',
    wrongAnswer: ['<p>-12</p>', '<p>-2</p>', '<p>2</p>']
  });
  console.log('M1 Q15 update:', resQ15.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(resQ15));

  // M1 Q5 (6a62714dc3d08d90637d36dc) - Typo in stem ("a" vs "x")
  console.log('Fixing M1 Q5 variable typo in stem...');
  const resQ5 = await updateQuestion('6a62714dc3d08d90637d36dc', {
    question: `<p>The function ${f('g')} is defined by ${f('g(x) = 16x + 25')}. For what value of ${f('x')} does ${f('g(x) = 29')}?</p>`
  });
  console.log('M1 Q5 update:', resQ5.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(resQ5));

  // 2. Choice Deduplication across all other MCQs
  console.log('\n2. Deduplicating choices across all MCQs...');
  for (const q of [...m1, ...m2]) {
    if (q._id === '6a6267efc3d08d90637d36d8' || q._id === '6a6279b9c3d08d90637d3724') continue;

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

  console.log('\n✅ All Academic & Structural Fixes Applied for October 2025 INT 2!');
}

run().catch(console.error);
