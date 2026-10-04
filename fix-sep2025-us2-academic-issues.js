const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a6964cbc3d08d90637d3df5';
const M2_ID = '6a6964d0c3d08d90637d3dfb';

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
  console.log('🚀 Applying Academic & Structural Fixes for September 2025 · US 2...\n');

  // 1. Specific Question Fixes
  console.log('1. Applying specific question fixes...');

  // M1 Q5 (6a6b690ec3d08d90637d3e5e) - Initial deposit on graph is 30 (allow 30 and 40)
  console.log('Fixing M1 Q5 answer key...');
  const resM1Q5 = await updateQuestion('6a6b690ec3d08d90637d3e5e', {
    answer: ["30", "40"]
  });
  console.log('M1 Q5 update:', resM1Q5.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(resM1Q5));

  // M1 Q13 (6a6b728ac3d08d90637d3e84) - Fix stem formula to b - 19/y = x and correct answer to x = (by-19)/y
  console.log('Fixing M1 Q13 stem and answer choices...');
  const resM1Q13 = await updateQuestion('6a6b728ac3d08d90637d3e84', {
    question: `<p>The given equation relates the positive numbers ${f('b')}, ${f('x')}, and ${f('y')}. Which equation correctly expresses ${f('x')} in terms of ${f('b')} and ${f('y')}?</p><p>${f('b - \\frac{19}{y} = x')}</p>`,
    correctAnswer: `<p>${f('x = \\frac{by - 19}{y}')}</p>`,
    wrongAnswer: [
      `<p>${f('x = by - 19')}</p>`,
      `<p>${f('x = \\frac{b - 19}{y}')}</p>`,
      `<p>${f('x = b - 19y')}</p>`
    ]
  });
  console.log('M1 Q13 update:', resM1Q13.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(resM1Q13));

  // M2 Q20 (6a6cadd0c3d08d90637d3fb7) - Fix truncated choice [4]
  console.log('Fixing M2 Q20 truncated option...');
  const resM2Q20 = await updateQuestion('6a6cadd0c3d08d90637d3fb7', {
    wrongAnswer: [
      `<p>${f('AB = 45')} and ${f('PQ = 45')}.</p>`,
      `<p>${f('AB = 45')} and ${f('QR = 135')}.</p>`,
      `<p>The measures of angle ${f('B')} and angle ${f('Q')} are ${f('40^\\circ')} and ${f('88^\\circ')}, respectively.</p>`
    ]
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
    if (q._id === '6a6b728ac3d08d90637d3e84' || q._id === '6a6cadd0c3d08d90637d3fb7') continue;

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

  console.log('\n✅ All Academic & Structural Fixes Applied for September 2025 US 2!');
}

run().catch(console.error);
