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

function stripHtml(s) {
  if (!s) return '';
  return s.replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
}

async function run() {
  console.log('🚀 Applying Academic & Structural Fixes for November 2025 · INT 3...\n');

  const m1Res = await new Promise((resolve, reject) => {
    https.get(`${API_BASE}/chapter/getChapterQuestion/6a622fc3c3d08d90637d34a6`, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve(JSON.parse(data)));
    }).on('error', reject);
  });
  const m2Res = await new Promise((resolve, reject) => {
    https.get(`${API_BASE}/chapter/getChapterQuestion/6a622fc8c3d08d90637d34ac`, res => {
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
    // Skip M1 Q13 because we handle it specifically below
    if (q._id === '6a62352dc3d08d90637d3503') continue;

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

  // M1 Q13 (6a62352dc3d08d90637d3503) - Missing dollar values in choices
  console.log('Fixing M1 Q13 missing dollar amounts in choices...');
  const resQ13 = await updateQuestion('6a62352dc3d08d90637d3503', {
    correctAnswer: '<p>Each game costs $16</p>',
    wrongAnswer: [
      '<p>The video game system costs $50</p>',
      '<p>Each game costs $50</p>',
      '<p>The video game system costs $16</p>'
    ]
  });
  console.log('M1 Q13 update:', resQ13.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(resQ13));

  console.log('\n✅ All Academic & Structural Fixes Applied for November 2025 INT 3!');
}

run().catch(console.error);
