const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a6946b7c3d08d90637d3cc3';
const M2_ID = '6a6946bec3d08d90637d3cc9';

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
  console.log('🚀 Applying Academic & Structural Fixes for September 2025 · US 1...\n');

  // 1. Specific Question Fixes
  console.log('1. Applying specific question fixes...');

  // M2 Q20 (6a6963d2c3d08d90637d3ddf) - Add exact fraction 22/3 and 7.33
  console.log('Fixing M2 Q20 answer formats...');
  const resM2Q20 = await updateQuestion('6a6963d2c3d08d90637d3ddf', {
    answer: ["22/3", "7.33", "7.34", "367/50"]
  });
  console.log('M2 Q20 update:', resM2Q20.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(resM2Q20));

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

  console.log('\n✅ All Academic & Structural Fixes Applied for September 2025 US 1!');
}

run().catch(console.error);
