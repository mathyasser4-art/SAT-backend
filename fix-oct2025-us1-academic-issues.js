const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a66595cc3d08d90637d39ee';
const M2_ID = '6a665962c3d08d90637d39f4';

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
  console.log('🚀 Applying Academic & Structural Fixes for October 2025 · US 1...\n');

  // 1. Specific Question Fixes BEFORE deduplication
  console.log('1. Applying specific question fixes...');

  // M1 Q8 (6a665c46c3d08d90637d3a30) - Typo in stem: tan A = 612/35 (was 612/613)
  console.log('Fixing M1 Q8 stem typo and choices...');
  const resQ8 = await updateQuestion('6a665c46c3d08d90637d3a30', {
    question: `<p>Triangle ${f('ABC')} is similar to triangle ${f('DEF')}, where angle ${f('A')} corresponds to angle ${f('D')} and angle ${f('C')} corresponds to angle ${f('F')}. Angles ${f('C')} and ${f('F')} are right angles. If ${f('\\tan A = \\frac{612}{35}')}, what is the value of ${f('\\sin D')}?</p>`,
    correctAnswer: `<p>${f('\\frac{612}{613}')}</p>`,
    wrongAnswer: [
      `<p>${f('\\frac{35}{613}')}</p>`,
      `<p>${f('\\frac{613}{612}')}</p>`,
      `<p>${f('\\frac{613}{35}')}</p>`
    ]
  });
  console.log('M1 Q8 update:', resQ8.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(resQ8));

  // M1 Q16 (6a665e73c3d08d90637d3a52) - Remove misplaced questionPic
  console.log('Fixing M1 Q16 removing misplaced questionPic...');
  const resQ16 = await updateQuestion('6a665e73c3d08d90637d3a52', {
    questionPic: ""
  });
  console.log('M1 Q16 update:', resQ16.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(resQ16));

  // M2 Q1 (6a666305c3d08d90637d3a82) - Correct shaded region option (horizontal line at y = -36, shaded above)
  console.log('Fixing M2 Q1 correct shaded region choice...');
  const resM2Q1 = await updateQuestion('6a666305c3d08d90637d3a82', {
    correctAnswer: '<p><img src="https://res.cloudinary.com/drxqzhgce/image/upload/v1785094826/quill-images/ru7opokfhfpqpeytw7dd.png"></p>',
    wrongAnswer: [
      '<p><img src="https://res.cloudinary.com/drxqzhgce/image/upload/v1785094810/quill-images/xj7n4h2qwpbkxmckb14r.png"></p>',
      '<p><img src="https://res.cloudinary.com/drxqzhgce/image/upload/v1785094837/quill-images/uqt3y4sqdsizbeeswgba.png"></p>',
      '<p><img src="https://res.cloudinary.com/drxqzhgce/image/upload/v1785094865/quill-images/j0835ufg83fzg67gvplz.png"></p>'
    ]
  });
  console.log('M2 Q1 update:', resM2Q1.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(resM2Q1));

  // M2 Q11 (6a667618c3d08d90637d3abc) - Complementary angle: 90 - 14 = 76 (was 14)
  console.log('Fixing M2 Q11 complementary angle answer...');
  const resM2Q11 = await updateQuestion('6a667618c3d08d90637d3abc', {
    answer: ["76"]
  });
  console.log('M2 Q11 update:', resM2Q11.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(resM2Q11));

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

  // 2. Choice Deduplication across all other MCQs
  console.log('\n2. Deduplicating choices across all MCQs...');
  for (const q of [...m1, ...m2]) {
    if (q._id === '6a665c46c3d08d90637d3a30' || q._id === '6a666305c3d08d90637d3a82') continue;

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

  console.log('\n✅ All Academic & Structural Fixes Applied for October 2025 US 1!');
}

run().catch(console.error);
