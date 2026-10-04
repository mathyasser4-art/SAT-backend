const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a6cb17cc3d08d90637d4043';
const M2_ID = '6a6cb182c3d08d90637d4049';

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
  console.log('🚀 Applying Academic & Structural Fixes for August 2025 · INT 2...\n');

  // 1. Specific Question Fixes
  console.log('1. Applying specific question fixes...');

  // M2 Q9 (6a6d186464c8e41fac128f7b) - Fix stem prompt
  console.log('Fixing M2 Q9 stem...');
  const resM2Q9 = await updateQuestion('6a6d186464c8e41fac128f7b', {
    question: `<p>In quadrilateral ${f('KLMN')} shown, ${f('KL = 3')}, ${f('LM = 3')}, ${f('KN = 27')}, and ${f('MN = 27')}. Diagonals ${f('KM')} and ${f('LN')} (not shown) intersect at point ${f('G')} (not shown), where ${f('GK = 1')} and ${f('GM = 1')}. If the length of diagonal ${f('LN')} is ${f('\\sqrt{p} + \\sqrt{w}')}, where ${f('p')} and ${f('w')} are positive integers, what is the value of ${f('p + w')}?</p>`
  });
  console.log('M2 Q9 update:', resM2Q9.message === 'success' ? '✅' : '⚠️ ' + JSON.stringify(resM2Q9));

  // M2 Q11 (6a6d196364c8e41fac128f91) - Clean stem, remove stray "A ", fix truncated option [4]
  console.log('Fixing M2 Q11 stem and choices...');
  const resM2Q11 = await updateQuestion('6a6d196364c8e41fac128f91', {
    question: `<p>In the given equation, ${f('c')} and ${f('k')} are constants. The equation has exactly one solution:</p><p>${f('c(x - 6) = -7(x + k)')}</p><p>Which of the following statements must be true?</p>`,
    correctAnswer: `<p>The value of ${f('c')} cannot be ${f('-7')}.</p>`,
    wrongAnswer: [
      `<p>The value of ${f('c')} cannot be ${f('-\\frac{7}{6}')}.</p>`,
      `<p>The value of ${f('k')} cannot be ${f('\\frac{6}{7}')}.</p>`,
      `<p>The value of ${f('k')} cannot be ${f('-6')}.</p>`
    ]
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

  // 2. Choice Deduplication across all MCQs
  console.log('\n2. Deduplicating choices across all MCQs...');
  for (const q of [...m1, ...m2]) {
    if (q._id === '6a6d196364c8e41fac128f91') continue;

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

  console.log('\n✅ All Academic & Structural Fixes Applied for August 2025 INT 2!');
}

run().catch(console.error);
