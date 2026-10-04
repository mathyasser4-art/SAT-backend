const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a9b2dcc111ffc76c2e611cb';
const M2_ID = '6a9b2dd4111ffc76c2e611d1';

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
  console.log('🚀 Applying Academic & Structural Fixes for May 2025 · INT 2...\n');

  console.log('1. Applying specific question fixes for Module 1...');

  // M1 Q1 (6a9b35b0111ffc76c2e61f50)
  await updateQuestion('6a9b35b0111ffc76c2e61f50', {
    correctAnswer: `<p>56</p>`,
    wrongAnswer: [`<p>34</p>`, `<p>90</p>`, `<p>180</p>`]
  });
  console.log('M1 Q1 fixed: ✅');

  // M1 Q2 (6a9b3616111ffc76c2e62025)
  await updateQuestion('6a9b3616111ffc76c2e62025', {
    correctAnswer: `<p>${f('6x^3y + 21xy^2')}</p>`,
    wrongAnswer: [
      `<p>${f('5x^3y + 10xy^2')}</p>`,
      `<p>${f('6x^2y + 7y')}</p>`,
      `<p>${f('6x^2y + 21xy')}</p>`
    ]
  });
  console.log('M1 Q2 fixed: ✅');

  // M1 Q3 (6a9b365b111ffc76c2e62104)
  await updateQuestion('6a9b365b111ffc76c2e62104', {
    correctAnswer: `<p>${f('6(5x^2 + x + 1)')}</p>`,
    wrongAnswer: [
      `<p>${f('5x^2(6x + 6)')}</p>`,
      `<p>${f('30x(x + 1)')}</p>`,
      `<p>${f('4(2x^2 + x + 1)')}</p>`
    ]
  });
  console.log('M1 Q3 fixed: ✅');

  // M1 Q4 (6a9b36a6111ffc76c2e62121)
  await updateQuestion('6a9b36a6111ffc76c2e62121', {
    correctAnswer: `<p>184</p>`,
    wrongAnswer: [`<p>276</p>`, `<p>94</p>`, `<p>90</p>`]
  });
  console.log('M1 Q4 fixed: ✅');

  // M1 Q6 (6a9b39c7111ffc76c2e62593)
  await updateQuestion('6a9b39c7111ffc76c2e62593', {
    correctAnswer: `<p>The estimated length of the pothos plant was 9 inches when Shruti purchased it.</p>`,
    wrongAnswer: [
      `<p>Shruti will keep the pothos plant for 9 months.</p>`,
      `<p>The pothos plant is expected to grow 9 inches each month.</p>`,
      `<p>The pothos plant is expected to grow to a maximum length of 9 inches.</p>`
    ]
  });
  console.log('M1 Q6 fixed: ✅');

  // M1 Q7 (6a9b3a64111ffc76c2e6260c)
  await updateQuestion('6a9b3a64111ffc76c2e6260c', {
    correctAnswer: `<p>105</p>`,
    wrongAnswer: [`<p>28</p>`, `<p>43</p>`, `<p>90</p>`]
  });
  console.log('M1 Q7 fixed: ✅');

  // M1 Q8 (6a9b3af6111ffc76c2e62787)
  await updateQuestion('6a9b3af6111ffc76c2e62787', {
    correctAnswer: `<p>28</p>`,
    wrongAnswer: [`<p>56</p>`, `<p>14</p>`, `<p>${f('\\sqrt{28}')}</p>`]
  });
  console.log('M1 Q8 fixed: ✅');

  // M1 Q10 (6a9b3db7111ffc76c2e62d51)
  await updateQuestion('6a9b3db7111ffc76c2e62d51', {
    correctAnswer: `<p>${f('V(t) = 240(1.01)^t')}</p>`,
    wrongAnswer: [
      `<p>${f('V(t) = 240(1.01t)')}</p>`,
      `<p>${f('V(t) = 240(1.1t)')}</p>`,
      `<p>${f('V(t) = 240(1.1)^t')}</p>`
    ]
  });
  console.log('M1 Q10 fixed: ✅');

  // M1 Q11 (6a9b3e2c111ffc76c2e62d57)
  await updateQuestion('6a9b3e2c111ffc76c2e62d57', {
    correctAnswer: `<p>27</p>`,
    wrongAnswer: [`<p>-3</p>`, `<p>12</p>`, `<p>18</p>`]
  });
  console.log('M1 Q11 fixed: ✅');

  // M1 Q12 (6a9b3e81111ffc76c2e62d5d)
  await updateQuestion('6a9b3e81111ffc76c2e62d5d', {
    correctAnswer: `<p>6</p>`,
    wrongAnswer: [`<p>2</p>`, `<p>3</p>`, `<p>9</p>`]
  });
  console.log('M1 Q12 fixed: ✅');

  // M1 Q16 (6a9b4019111ffc76c2e62f16)
  await updateQuestion('6a9b4019111ffc76c2e62f16', {
    correctAnswer: `<p>${f('x^2 - 16x + 64 = 0')}</p>`,
    wrongAnswer: [
      `<p>${f('x^2 - 16 = 0')}</p>`,
      `<p>${f('x^2 + 16 = 0')}</p>`,
      `<p>${f('x^2 - 16x + 56 = 0')}</p>`
    ]
  });
  console.log('M1 Q16 fixed: ✅');

  // M1 Q18 (6a9b41c1111ffc76c2e63219)
  await updateQuestion('6a9b41c1111ffc76c2e63219', {
    correctAnswer: `<p>Quinidra drove away from her home at a constant speed for 1 hour; spent 4 hours at the location, then drove back to her home at a constant speed for 1 hour.</p>`,
    wrongAnswer: [
      `<p>Quinidra drove away from her home at a constant speed for 1 hour; spent 4 hours at the location, then continued to drive away from her home at a constant speed for 1 hour.</p>`,
      `<p>Quinidra drove away from her home at an increasing speed for 1 hour; spent 4 hours at the location, then drove back to her home at a decreasing speed for 1 hour.</p>`,
      `<p>Quinidra drove away from her home at an increasing speed for 1 hour, drove at a constant speed for 4 hours, then drove back to her home at a decreasing speed for 1 hour.</p>`
    ]
  });
  console.log('M1 Q18 fixed: ✅');

  console.log('\n2. Applying specific question fixes for Module 2...');

  // M2 Q1 (6a9b475c111ffc76c2e63e78)
  await updateQuestion('6a9b475c111ffc76c2e63e78', {
    correctAnswer: `<p>8,200</p>`,
    wrongAnswer: [`<p>6,200</p>`, `<p>7,000</p>`, `<p>25,300</p>`]
  });
  console.log('M2 Q1 fixed: ✅');

  // M2 Q3 (6a9c03d24471c51d35c18e2d)
  await updateQuestion('6a9c03d24471c51d35c18e2d', {
    correctAnswer: `<p>5</p>`,
    wrongAnswer: [`<p>21</p>`, `<p>8</p>`, `<p>7</p>`]
  });
  console.log('M2 Q3 fixed: ✅');

  // M2 Q4 (6a9c042d4471c51d35c18e33)
  await updateQuestion('6a9c042d4471c51d35c18e33', {
    correctAnswer: `<p>37</p>`,
    wrongAnswer: [`<p>74</p>`, `<p>28</p>`, `<p>14</p>`]
  });
  console.log('M2 Q4 fixed: ✅');

  // M2 Q5 (6a9c04744471c51d35c18e39)
  await updateQuestion('6a9c04744471c51d35c18e39', {
    correctAnswer: `<p>10</p>`,
    wrongAnswer: [`<p>12,250</p>`, `<p>1,225</p>`, `<p>1,000</p>`]
  });
  console.log('M2 Q5 fixed: ✅');

  // M2 Q8 (6a9c06d04471c51d35c18e4d)
  await updateQuestion('6a9c06d04471c51d35c18e4d', {
    correctAnswer: `<p>88</p>`,
    wrongAnswer: [`<p>25</p>`, `<p>29</p>`, `<p>58</p>`]
  });
  console.log('M2 Q8 fixed: ✅');

  // M2 Q10 (6a9c07ae4471c51d35c18e59)
  await updateQuestion('6a9c07ae4471c51d35c18e59', {
    correctAnswer: `<p>(14, 0)</p>`,
    wrongAnswer: [`<p>(0, -14)</p>`, `<p>(0, 14)</p>`, `<p>(-14, 0)</p>`]
  });
  console.log('M2 Q10 fixed: ✅');

  // M2 Q11 (6a9c09234471c51d35c1902d)
  await updateQuestion('6a9c09234471c51d35c1902d', {
    correctAnswer: `<p>${f('\\frac{5}{6} + \\frac{\\sqrt{85}}{6}')}</p>`,
    wrongAnswer: [
      `<p>${f('\\frac{5}{6} - \\frac{\\sqrt{85}}{6}')}</p>`,
      `<p>${f('\\frac{5}{3} - \\frac{\\sqrt{85}}{3}')}</p>`,
      `<p>${f('\\frac{5}{3} + \\frac{\\sqrt{85}}{3}')}</p>`
    ]
  });
  console.log('M2 Q11 fixed: ✅');

  // M2 Q13 (6a9c0ace4471c51d35c190d1)
  await updateQuestion('6a9c0ace4471c51d35c190d1', {
    correctAnswer: `<p>${f('\\left(0, \\frac{8}{13}\\right)')}</p>`,
    wrongAnswer: [
      `<p>(8, 13)</p>`,
      `<p>(0, 13)</p>`,
      `<p>(0, 8)</p>`
    ]
  });
  console.log('M2 Q13 fixed: ✅');

  // M2 Q14 (6a9c0b2a4471c51d35c19127)
  await updateQuestion('6a9c0b2a4471c51d35c19127', {
    correctAnswer: `<p>${f('f(x) = (x - 2)^2 + (-324)')}</p>`,
    wrongAnswer: [
      `<p>${f('f(x) = x^2 - 4(x + 80)')}</p>`,
      `<p>${f('f(x) = x(x - 4) + (-320)')}</p>`,
      `<p>${f('f(x) = (x + 16)(x - 20)')}</p>`
    ]
  });
  console.log('M2 Q14 fixed: ✅');

  // M2 Q16 (6a9c0c054471c51d35c1915c)
  await updateQuestion('6a9c0c054471c51d35c1915c', {
    correctAnswer: `<p>3</p>`,
    wrongAnswer: [`<p>-84</p>`, `<p>-3</p>`, `<p>84</p>`]
  });
  console.log('M2 Q16 fixed: ✅');

  // M2 Q17 (6a9c0c694471c51d35c1918c)
  await updateQuestion('6a9c0c694471c51d35c1918c', {
    correctAnswer: `<p>The standard deviation of weight for the objects in group A is greater than the standard deviation of weight for the objects in group B.</p>`,
    wrongAnswer: [
      `<p>The standard deviation of weight for the objects in group A is less than the standard deviation of weight for the objects in group B.</p>`,
      `<p>The standard deviation of weight for the objects in group A is equal to the standard deviation of weight for the objects in group B.</p>`,
      `<p>There is not enough information to compare the standard deviations of weight for the objects in these two groups.</p>`
    ]
  });
  console.log('M2 Q17 fixed: ✅');

  // M2 Q18 (6a9c0ca34471c51d35c19192)
  await updateQuestion('6a9c0ca34471c51d35c19192', {
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
    '6a9b35b0111ffc76c2e61f50', '6a9b3616111ffc76c2e62025', '6a9b365b111ffc76c2e62104',
    '6a9b36a6111ffc76c2e62121', '6a9b39c7111ffc76c2e62593', '6a9b3a64111ffc76c2e6260c',
    '6a9b3af6111ffc76c2e62787', '6a9b3db7111ffc76c2e62d51', '6a9b3e2c111ffc76c2e62d57',
    '6a9b3e81111ffc76c2e62d5d', '6a9b4019111ffc76c2e62f16', '6a9b41c1111ffc76c2e63219',
    '6a9b475c111ffc76c2e63e78', '6a9c03d24471c51d35c18e2d', '6a9c042d4471c51d35c18e33',
    '6a9c04744471c51d35c18e39', '6a9c06d04471c51d35c18e4d', '6a9c07ae4471c51d35c18e59',
    '6a9c09234471c51d35c1902d', '6a9c0ace4471c51d35c190d1', '6a9c0b2a4471c51d35c19127',
    '6a9c0c054471c51d35c1915c', '6a9c0c694471c51d35c1918c', '6a9c0ca34471c51d35c19192'
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

  console.log('\n✅ All Academic & Structural Fixes Applied for May 2025 INT 2!');
}

run().catch(console.error);
