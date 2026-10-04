const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a9c19964471c51d35c19dd3';
const M2_ID = '6a9c199e4471c51d35c19dd9';

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

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    https.get(url, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', reject);
  });
}

function cleanHtml(s) {
  if (!s) return '';
  return s.replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
}

async function run() {
  console.log('🚀 Applying Academic & Structural Fixes for May 2025 · INT 3...\n');

  console.log('1. Applying specific question fixes for Module 1...');

  // M1 Q1 (6a9c1aad4471c51d35c19de1)
  await updateQuestion('6a9c1aad4471c51d35c19de1', {
    correctAnswer: `<p>${f('56^\\circ')}</p>`,
    wrongAnswer: [`<p>${f('34^\\circ')}</p>`, `<p>${f('90^\\circ')}</p>`, `<p>${f('180^\\circ')}</p>`]
  });
  console.log('M1 Q1 fixed: ✅');

  // M1 Q2 (6a9c1aef4471c51d35c19de7)
  await updateQuestion('6a9c1aef4471c51d35c19de7', {
    correctAnswer: `<p>${f('6x^3y + 21xy^2')}</p>`,
    wrongAnswer: [
      `<p>${f('5x^3y + 10xy^2')}</p>`,
      `<p>${f('6x^2y + 7y')}</p>`,
      `<p>${f('6x^2y + 21xy')}</p>`
    ]
  });
  console.log('M1 Q2 fixed: ✅');

  // M1 Q4 (6a9c1b5d4471c51d35c19df3)
  await updateQuestion('6a9c1b5d4471c51d35c19df3', {
    correctAnswer: `<p>184</p>`,
    wrongAnswer: [`<p>276</p>`, `<p>94</p>`, `<p>90</p>`]
  });
  console.log('M1 Q4 fixed: ✅');

  // M1 Q7 (6a9c1c014471c51d35c19e05)
  await updateQuestion('6a9c1c014471c51d35c19e05', {
    correctAnswer: `<p>The estimated length of the pothos plant was 9 inches when Shruti purchased it.</p>`,
    wrongAnswer: [
      `<p>Shruti will keep the pothos plant for 9 months.</p>`,
      `<p>The pothos plant is expected to grow 9 inches each month.</p>`,
      `<p>The pothos plant is expected to grow to a maximum length of 9 inches.</p>`
    ]
  });
  console.log('M1 Q7 fixed: ✅');

  // M1 Q8 (6a9c1c2c4471c51d35c19e0b)
  await updateQuestion('6a9c1c2c4471c51d35c19e0b', {
    correctAnswer: `<p>105</p>`,
    wrongAnswer: [`<p>28</p>`, `<p>43</p>`, `<p>90</p>`]
  });
  console.log('M1 Q8 fixed: ✅');

  // M1 Q9 (6a9c1c694471c51d35c19e11)
  await updateQuestion('6a9c1c694471c51d35c19e11', {
    correctAnswer: `<p>28</p>`,
    wrongAnswer: [`<p>56</p>`, `<p>14</p>`, `<p>${f('\\sqrt{28}')}</p>`]
  });
  console.log('M1 Q9 fixed: ✅');

  // M1 Q12 (6a9c1ebc4471c51d35c19fa8)
  await updateQuestion('6a9c1ebc4471c51d35c19fa8', {
    correctAnswer: `<p>6</p>`,
    wrongAnswer: [`<p>2</p>`, `<p>3</p>`, `<p>9</p>`]
  });
  console.log('M1 Q12 fixed: ✅');

  // M1 Q16 (6a9c1fc34471c51d35c19fc0)
  await updateQuestion('6a9c1fc34471c51d35c19fc0', {
    correctAnswer: `<p>${f('x^2 - 16x + 64 = 0')}</p>`,
    wrongAnswer: [
      `<p>${f('x^2 - 16 = 0')}</p>`,
      `<p>${f('x^2 + 16 = 0')}</p>`,
      `<p>${f('x^2 - 16x + 56 = 0')}</p>`
    ]
  });
  console.log('M1 Q16 fixed: ✅');

  // M1 Q17 (6a9c201f4471c51d35c19fc6)
  await updateQuestion('6a9c201f4471c51d35c19fc6', {
    correctAnswer: `<p>Quinidra drove 60 miles from her home and then returned home.</p>`,
    wrongAnswer: [
      `<p>Quinidra drove 50 miles from her home and stopped before returning home.</p>`,
      `<p>Quinidra drove 60 miles from her home and stopped before returning home.</p>`,
      `<p>Quinidra drove 80 miles from her home and then returned home.</p>`
    ]
  });
  console.log('M1 Q17 fixed: ✅');

  // M1 Q21 (6aa0deebdf63ca493d479911)
  await updateQuestion('6aa0deebdf63ca493d479911', {
    correctAnswer: `<p>16,974,848</p>`,
    wrongAnswer: [`<p>552</p>`, `<p>964</p>`, `<p>9,645</p>`]
  });
  console.log('M1 Q21 fixed: ✅');

  console.log('\n2. Applying specific question fixes for Module 2...');

  // M2 Q1 (6aa0e0fddf63ca493d479922)
  await updateQuestion('6aa0e0fddf63ca493d479922', {
    correctAnswer: `<p>8,200</p>`,
    wrongAnswer: [`<p>6,200</p>`, `<p>7,000</p>`, `<p>25,300</p>`]
  });
  console.log('M2 Q1 fixed: ✅');

  // M2 Q3 (6aa0e1c5df63ca493d479933)
  await updateQuestion('6aa0e1c5df63ca493d479933', {
    correctAnswer: `<p>5</p>`,
    wrongAnswer: [`<p>21</p>`, `<p>8</p>`, `<p>7</p>`]
  });
  console.log('M2 Q3 fixed: ✅');

  // M2 Q4 (6aa0e230df63ca493d479939)
  await updateQuestion('6aa0e230df63ca493d479939', {
    correctAnswer: `<p>37</p>`,
    wrongAnswer: [`<p>74</p>`, `<p>28</p>`, `<p>14</p>`]
  });
  console.log('M2 Q4 fixed: ✅');

  // M2 Q5 (6aa0e289df63ca493d47993f)
  await updateQuestion('6aa0e289df63ca493d47993f', {
    correctAnswer: `<p>10</p>`,
    wrongAnswer: [`<p>12,250</p>`, `<p>1,225</p>`, `<p>1,000</p>`]
  });
  console.log('M2 Q5 fixed: ✅');

  // M2 Q6 (6aa0e2e8df63ca493d479945)
  await updateQuestion('6aa0e2e8df63ca493d479945', {
    correctAnswer: `<p>${f('h(x) = 3x + 5')}</p>`,
    wrongAnswer: [
      `<p>${f('h(x) = \\frac{1}{3}x - \\frac{5}{3}')}</p>`,
      `<p>${f('h(x) = 4x + 17')}</p>`,
      `<p>${f('h(x) = 6x + 23')}</p>`
    ]
  });
  console.log('M2 Q6 fixed: ✅');

  // M2 Q8 (6aa0e34cdf63ca493d479951)
  await updateQuestion('6aa0e34cdf63ca493d479951', {
    correctAnswer: `<p>88</p>`,
    wrongAnswer: [`<p>25</p>`, `<p>29</p>`, `<p>58</p>`]
  });
  console.log('M2 Q8 fixed: ✅');

  // M2 Q11 (6aa0e8c7df63ca493d479976)
  await updateQuestion('6aa0e8c7df63ca493d479976', {
    correctAnswer: `<p>(14, 0)</p>`,
    wrongAnswer: [`<p>(0, -14)</p>`, `<p>(0, 14)</p>`, `<p>(-14, 0)</p>`]
  });
  console.log('M2 Q11 fixed: ✅');

  // M2 Q12 (6aa0e92cdf63ca493d47997c)
  await updateQuestion('6aa0e92cdf63ca493d47997c', {
    correctAnswer: `<p>${f('\\frac{5}{6} + \\frac{\\sqrt{85}}{6}')}</p>`,
    wrongAnswer: [
      `<p>${f('\\frac{5}{6} - \\frac{\\sqrt{85}}{6}')}</p>`,
      `<p>${f('\\frac{5}{3} - \\frac{\\sqrt{85}}{3}')}</p>`,
      `<p>${f('\\frac{5}{3} + \\frac{\\sqrt{85}}{3}')}</p>`
    ]
  });
  console.log('M2 Q12 fixed: ✅');

  // M2 Q14 (6aa0e9c8df63ca493d479988)
  await updateQuestion('6aa0e9c8df63ca493d479988', {
    correctAnswer: `<p>${f('\\left(0, \\frac{8}{13}\\right)')}</p>`,
    wrongAnswer: [`<p>(8, 13)</p>`, `<p>(0, 13)</p>`, `<p>(0, 8)</p>`]
  });
  console.log('M2 Q14 fixed: ✅');

  // M2 Q15 (6aa0ea09df63ca493d47998e)
  await updateQuestion('6aa0ea09df63ca493d47998e', {
    correctAnswer: `<p>${f('f(x) = (x - 2)^2 + (-324)')}</p>`,
    wrongAnswer: [
      `<p>${f('f(x) = x^2 - 4(x + 80)')}</p>`,
      `<p>${f('f(x) = x(x - 4) + (-320)')}</p>`,
      `<p>${f('f(x) = (x + 16)(x - 20)')}</p>`
    ]
  });
  console.log('M2 Q15 fixed: ✅');

  // M2 Q17 (6aa0eaa8df63ca493d47999a)
  await updateQuestion('6aa0eaa8df63ca493d47999a', {
    correctAnswer: `<p>3</p>`,
    wrongAnswer: [`<p>-84</p>`, `<p>-3</p>`, `<p>84</p>`]
  });
  console.log('M2 Q17 fixed: ✅');

  // M2 Q18 (6aa0ead3df63ca493d4799a0)
  await updateQuestion('6aa0ead3df63ca493d4799a0', {
    correctAnswer: `<p>y = 60x + 36</p>`,
    wrongAnswer: [
      `<p>y = 60x + 216</p>`,
      `<p>y = 216x + 396</p>`,
      `<p>y = 216x + 60</p>`
    ]
  });
  console.log('M2 Q18 fixed: ✅');

  // Deduplicate all other MCQs
  console.log('\n3. Deduplicating choices across all other MCQs...');
  const m1Res = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/${M1_ID}`);
  const m2Res = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/${M2_ID}`);

  const customHandled = [
    '6a9c1aad4471c51d35c19de1', '6a9c1aef4471c51d35c19de7', '6a9c1b5d4471c51d35c19df3',
    '6a9c1c014471c51d35c19e05', '6a9c1c2c4471c51d35c19e0b', '6a9c1c694471c51d35c19e11',
    '6a9c1ebc4471c51d35c19fa8', '6a9c1fc34471c51d35c19fc0', '6a9c201f4471c51d35c19fc6',
    '6aa0deebdf63ca493d479911', '6aa0e0fddf63ca493d479922', '6aa0e1c5df63ca493d479933',
    '6aa0e230df63ca493d479939', '6aa0e289df63ca493d47993f', '6aa0e2e8df63ca493d479945',
    '6aa0e34cdf63ca493d479951', '6aa0e8c7df63ca493d479976', '6aa0e92cdf63ca493d47997c',
    '6aa0e9c8df63ca493d479988', '6aa0ea09df63ca493d47998e', '6aa0eaa8df63ca493d47999a',
    '6aa0ead3df63ca493d4799a0'
  ];

  const allQs = [...m1Res.chapter.questions, ...m2Res.chapter.questions];

  for (const q of allQs) {
    if (q.typeOfAnswer !== 'MCQ') continue;
    if (customHandled.includes(q._id)) continue;

    const correctClean = cleanHtml(q.correctAnswer);
    const seen = new Set();
    seen.add(correctClean);

    const newWrongs = [];
    for (const w of q.wrongAnswer || []) {
      const wClean = cleanHtml(w);
      if (!seen.has(wClean) && wClean.length > 0) {
        seen.add(wClean);
        newWrongs.push(w);
      }
    }

    if (newWrongs.length !== (q.wrongAnswer || []).length || (q.wrongAnswer || []).length > 3) {
      process.stdout.write(`Deduplicating Q ${q._id}... `);
      await updateQuestion(q._id, { wrongAnswer: newWrongs.slice(0, 3) });
      console.log('✅');
    }
  }

  console.log('\n✅ All Academic & Structural Fixes Applied for May 2025 INT 3!');
}

run().catch(console.error);
