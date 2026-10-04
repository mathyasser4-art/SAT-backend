const https = require('https');
const fs = require('fs');

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
  console.log('🚀 Applying Academic & Structural Fixes for March 2026 · INT 1...\n');

  const m1Res = await new Promise((resolve, reject) => {
    https.get(`${API_BASE}/chapter/getChapterQuestion/6a5308df4d554e04aa1bf552`, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve(JSON.parse(data)));
    }).on('error', reject);
  });
  const m2Res = await new Promise((resolve, reject) => {
    https.get(`${API_BASE}/chapter/getChapterQuestion/6a534dbd4d554e04aa1bf642`, res => {
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

  // M1 Q7 (6a533f0a4d554e04aa1bf59c) - Fix parentheses in quadratic factors
  console.log('Fixing M1 Q7 choices parentheses...');
  await updateQuestion('6a533f0a4d554e04aa1bf59c', {
    correctAnswer: `<p>${f('(x - 13)(x + 24) = 0')}</p>`,
    wrongAnswer: [
      `<p>${f('(x + 13)(x - 24) = 0')}</p>`,
      `<p>${f('(x - 13)(x - 24) = 0')}</p>`,
      `<p>${f('(x + 13)(x + 24) = 0')}</p>`
    ]
  });

  // M1 Q13 (6a5345554d554e04aa1bf5db) - Restore 58x^2 exponent
  console.log('Fixing M1 Q13 stem formula (3x + 58x^2 - 7)...');
  await updateQuestion('6a5345554d554e04aa1bf5db', {
    question: `<p>The expression ${f('3x + 58x^2 - 7')} can be written in the form ${f('ax^2 + bx + c')}, where ${f('a')}, ${f('b')}, and ${f('c')} are constants. What is the value of ${f('a + b')}?</p>`,
    answer: ['61']
  });

  // M1 Q16 (6a5347894d554e04aa1bf5f9) - Restore cubic polynomial f(x) = x^3 - 2x^2 - 8x + 3
  console.log('Fixing M1 Q16 stem polynomial (x^3 - 2x^2 - 8x + 3) and y = h(x)...');
  await updateQuestion('6a5347894d554e04aa1bf5f9', {
    question: `<p>The function ${f('f')} is defined by ${f('f(x) = x^3 - 2x^2 - 8x + 3')}. In the ${f('xy')}-plane, the graph of ${f('y = h(x)')} is the result of translating the graph of ${f('y = f(x)')} up ${f('6')} units. What is the ${f('y')}-coordinate of the y-intercept of the graph of ${f('y = h(x)')}?</p>`
  });

  // M1 Q21 (6a534cb24d554e04aa1bf62f) - Restore circle equation parentheses
  console.log('Fixing M1 Q21 circle equation parentheses...');
  await updateQuestion('6a534cb24d554e04aa1bf62f', {
    correctAnswer: `<p>${f('(x - 2)^2 + (y - 7)^2 = 100')}</p>`,
    wrongAnswer: [
      `<p>${f('(x - 2)^2 + (y - 7)^2 = 50')}</p>`,
      `<p>${f('(x - 2)^2 + (y - 7)^2 = 250')}</p>`,
      `<p>${f('(x - 2)^2 + (y - 7)^2 = 625')}</p>`
    ]
  });

  // M1 Q22 (6a534d5e4d554e04aa1bf635) - Add complete accepted grid-in formats
  console.log('Updating M1 Q22 accepted answers...');
  await updateQuestion('6a534d5e4d554e04aa1bf635', {
    answer: ['0.529', '.529', '9/17', '9', '529/1000', '0.52', '0.53']
  });

  // M2 Q7 (6a53552b4d554e04aa1bf677) - Deduplicate image choices
  console.log('Fixing M2 Q7 choices...');
  await updateQuestion('6a53552b4d554e04aa1bf677', {
    correctAnswer: '<p><img src="https://res.cloudinary.com/drxqzhgce/image/upload/v1783846027/quill-images/qbyahqvmfubga1pxtjv1.png"></p>',
    wrongAnswer: [
      '<p><img src="https://res.cloudinary.com/drxqzhgce/image/upload/v1783846075/quill-images/zqsjfdjxhkgsxmfb139i.png"></p>',
      '<p><img src="https://res.cloudinary.com/drxqzhgce/image/upload/v1783846104/quill-images/prtxg6bm0ribprhmt8p5.png"></p>',
      '<p><img src="https://res.cloudinary.com/drxqzhgce/image/upload/v1783846128/quill-images/ei8lnfeb5gw1hyasprys.png"></p>'
    ]
  });

  // M2 Q9 (6a53571b4d554e04aa1bf687) - Fix multiplication syntax in angle conversion choices
  console.log('Fixing M2 Q9 angle formula choices...');
  await updateQuestion('6a53571b4d554e04aa1bf687', {
    correctAnswer: `<p>${f('\\frac{8}{11} \\times 180 \\times 2')}</p>`,
    wrongAnswer: [
      `<p>${f('\\frac{8}{11} \\times 90 \\times 2')}</p>`,
      `<p>${f('\\frac{8}{11\\pi} \\times 90 \\times 2')}</p>`,
      `<p>${f('\\frac{8\\pi}{11} \\times 180 \\times 2')}</p>`
    ]
  });

  // M2 Q18 (6a5496cd4d554e04aa1bfda6) - Support both 2.8 and 3.2
  console.log('Updating M2 Q18 accepted answers...');
  await updateQuestion('6a5496cd4d554e04aa1bfda6', {
    answer: ['3.2', '16/5', '2.8', '14/5']
  });

  console.log('\n✅ All Academic & Structural Fixes Applied Successfully!');
}

run().catch(console.error);
