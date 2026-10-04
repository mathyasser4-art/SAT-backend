const https = require('https');
const fs = require('fs');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a6e262e5db514110caca7b9';
const M2_ID = '6a6e26345db514110caca7bf';

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
  console.log('🚀 Applying Academic & Structural Fixes for May 2025 · INT 1...\n');

  // Specific fixes
  console.log('1. Applying specific question fixes...');

  // M1 Q2 (6a984ad5e57881aee77ea217)
  await updateQuestion('6a984ad5e57881aee77ea217', {
    correctAnswer: `<p>-21</p>`,
    wrongAnswer: [`<p>21</p>`, `<p>13</p>`, `<p>-13</p>`]
  });
  console.log('M1 Q2 fixed: ✅');

  // M1 Q6 (6a984d17e57881aee77ea236)
  await updateQuestion('6a984d17e57881aee77ea236', {
    correctAnswer: `<p>${f('1.40x + 3.40y = 85.60')}</p>`,
    wrongAnswer: [
      `<p>${f('1.40x + 64.60y = 85.60')}</p>`,
      `<p>${f('64.60x + 1.40y = 85.60')}</p>`,
      `<p>${f('3.40x + 1.40y = 85.60')}</p>`
    ]
  });
  console.log('M1 Q6 fixed: ✅');

  // M1 Q7 (6a98507ee57881aee77ea953)
  await updateQuestion('6a98507ee57881aee77ea953', {
    correctAnswer: `<p>${f('\\frac{1}{10}')}</p>`,
    wrongAnswer: [
      `<p>${f('\\frac{1}{5}')}</p>`,
      `<p>${f('\\frac{9}{10}')}</p>`,
      `<p>${f('\\frac{1}{50}')}</p>`
    ]
  });
  console.log('M1 Q7 fixed: ✅');

  // M1 Q10 (6a98523fe57881aee77ea9df)
  await updateQuestion('6a98523fe57881aee77ea9df', {
    correctAnswer: `<p>${f('25x^2 + 3')}</p>`,
    wrongAnswer: [
      `<p>${f('25x^4 + 3')}</p>`,
      `<p>${f('28x^4')}</p>`,
      `<p>${f('28x^2')}</p>`
    ]
  });
  console.log('M1 Q10 fixed: ✅');

  // M1 Q12 (6a985475e57881aee77ead19)
  await updateQuestion('6a985475e57881aee77ead19', {
    correctAnswer: `<p>(0, 1)</p>`,
    wrongAnswer: [`<p>(0, 15)</p>`, `<p>(0, 14)</p>`, `<p>(0, -1)</p>`]
  });
  console.log('M1 Q12 fixed: ✅');

  // M1 Q13 (6a985535e57881aee77ead74)
  await updateQuestion('6a985535e57881aee77ead74', {
    correctAnswer: `<p>-8</p>`,
    wrongAnswer: [`<p>8</p>`, `<p>-20</p>`, `<p>20</p>`]
  });
  console.log('M1 Q13 fixed: ✅');

  // M1 Q14 (6a985607e57881aee77eaf50)
  await updateQuestion('6a985607e57881aee77eaf50', {
    correctAnswer: `<p>0.22</p>`,
    wrongAnswer: [`<p>0.12</p>`, `<p>1.08</p>`, `<p>1.98</p>`]
  });
  console.log('M1 Q14 fixed: ✅');

  // M1 Q16 (6a9af216838c4fe747f6d9b5)
  await updateQuestion('6a9af216838c4fe747f6d9b5', {
    correctAnswer: `<p>28</p>`,
    wrongAnswer: [`<p>7</p>`, `<p>14</p>`, `<p>56</p>`]
  });
  console.log('M1 Q16 fixed: ✅');

  // M1 Q17 (6a9af2e2838c4fe747f6de37)
  await updateQuestion('6a9af2e2838c4fe747f6de37', {
    correctAnswer: `<p>1.6</p>`,
    wrongAnswer: [`<p>0.8</p>`, `<p>2.56</p>`, `<p>3.2</p>`]
  });
  console.log('M1 Q17 fixed: ✅');

  // M1 Q18 (6a9af4bf838c4fe747f6e2e8)
  await updateQuestion('6a9af4bf838c4fe747f6e2e8', {
    correctAnswer: `<p>The rate of rainfall was 0 centimeters per hour between x = 2 and x = 4.</p>`,
    wrongAnswer: [
      `<p>The rate of rainfall was 2 centimeters per hour between x = 2 and x = 4.</p>`,
      `<p>The rate of rainfall was the greatest between x = 4 and x = 10.</p>`,
      `<p>The rate of rainfall increased between x = 0 and x = 2.</p>`
    ]
  });
  console.log('M1 Q18 fixed: ✅');

  // M1 Q19 (6a9af4ec838c4fe747f6e335)
  await updateQuestion('6a9af4ec838c4fe747f6e335', {
    correctAnswer: `<p>51</p>`,
    wrongAnswer: [`<p>49</p>`, `<p>50</p>`, `<p>52</p>`]
  });
  console.log('M1 Q19 fixed: ✅');

  // M1 Q20 (6a9af577838c4fe747f6e49c)
  await updateQuestion('6a9af577838c4fe747f6e49c', {
    correctAnswer: `<p>3,312</p>`,
    wrongAnswer: [`<p>2,320</p>`, `<p>2,340</p>`, `<p>2,760</p>`]
  });
  console.log('M1 Q20 fixed: ✅');

  // M1 Q21 (6a9af5c0838c4fe747f6e4c1)
  await updateQuestion('6a9af5c0838c4fe747f6e4c1', {
    correctAnswer: `<p>84</p>`,
    wrongAnswer: [`<p>42</p>`, `<p>43</p>`, `<p>85</p>`]
  });
  console.log('M1 Q21 fixed: ✅');

  // M2 Q2 (6a9afb07838c4fe747f6f030)
  await updateQuestion('6a9afb07838c4fe747f6f030', {
    correctAnswer: `<p>111</p>`,
    wrongAnswer: [`<p>31</p>`, `<p>69</p>`, `<p>131</p>`]
  });
  console.log('M2 Q2 fixed: ✅');

  // M2 Q3 (6a9afb97838c4fe747f6f04c)
  await updateQuestion('6a9afb97838c4fe747f6f04c', {
    correctAnswer: `<p>${f('f(x) = -\\frac{3}{7}x - 5')}</p>`,
    wrongAnswer: [
      `<p>${f('f(x) = \\frac{3}{7}x - 5')}</p>`,
      `<p>${f('f(x) = \\frac{7}{3}x - 5')}</p>`,
      `<p>${f('f(x) = -\\frac{7}{3}x - 5')}</p>`
    ]
  });
  console.log('M2 Q3 fixed: ✅');

  // M2 Q4 (6a9afd77838c4fe747f6f052)
  await updateQuestion('6a9afd77838c4fe747f6f052', {
    correctAnswer: `<p>A DNA molecule with a GC content of 98% has an estimated melting temperature between ${f('80^\\circ\\text{C}')} and ${f('90^\\circ\\text{C}')}.</p>`,
    wrongAnswer: [
      `<p>For each increase of x by 1, f(x) increases by approximately ${f('\\frac{2}{5}')}.</p>`,
      `<p>A DNA molecule with a GC content of 0% has an estimated melting temperature between ${f('60^\\circ\\text{C}')} and ${f('65^\\circ\\text{C}')}.</p>`,
      `<p>A DNA molecule with a GC content of 95% has an estimated melting temperature between ${f('100^\\circ\\text{C}')} and ${f('105^\\circ\\text{C}')}.</p>`
    ]
  });
  console.log('M2 Q4 fixed: ✅');

  // M2 Q5 (6a9afddf838c4fe747f6f05e)
  await updateQuestion('6a9afddf838c4fe747f6f05e', {
    correctAnswer: `<p>7</p>`,
    wrongAnswer: [`<p>-16</p>`, `<p>-7</p>`, `<p>16</p>`]
  });
  console.log('M2 Q5 fixed: ✅');

  // M2 Q6 (6a9afe67838c4fe747f6f064)
  await updateQuestion('6a9afe67838c4fe747f6f064', {
    question: `<p>Scientists collected fallen acorns that each housed a colony of the ant species P. ohioensis and analyzed each colony's structure. For any of these colonies, if the colony has ${f('x')} worker ants, the equation ${f('y = 0.67x + 2.6')}, where ${f('20 \\le x \\le 110')}, gives the predicted number of larvae, ${f('y')}, in the colony. If one of these colonies has 39 worker ants, which of the following is closest to the predicted number of larvae in the colony?</p>`
  });
  console.log('M2 Q6 fixed: ✅');

  // M2 Q8 (6a9affb6838c4fe747f6f1e3)
  await updateQuestion('6a9affb6838c4fe747f6f1e3', {
    correctAnswer: `<p>${f('34 - \\frac{P}{N}')}</p>`,
    wrongAnswer: [
      `<p>${f('C + \\frac{P}{N}')}</p>`,
      `<p>${f('34 + \\frac{P}{N}')}</p>`,
      `<p>${f('34 - \\frac{P}{C}')}</p>`
    ]
  });
  console.log('M2 Q8 fixed: ✅');

  // M2 Q10 (6a9b007c838c4fe747f6f1ef)
  await updateQuestion('6a9b007c838c4fe747f6f1ef', {
    correctAnswer: `<p>${f('297 + 27\\sqrt{73}')}</p>`,
    wrongAnswer: [
      `<p>${f('297 + 9\\sqrt{73}')}</p>`,
      `<p>${f('162 + 27\\sqrt{73}')}</p>`,
      `<p>${f('162 + 9\\sqrt{73}')}</p>`
    ]
  });
  console.log('M2 Q10 fixed: ✅');

  // M2 Q13 (6a9b0d96838c4fe747f71f58)
  await updateQuestion('6a9b0d96838c4fe747f71f58', {
    correctAnswer: `<p>14,500</p>`,
    wrongAnswer: [`<p>14,300</p>`, `<p>6,635</p>`, `<p>200</p>`]
  });
  console.log('M2 Q13 fixed: ✅');

  // M2 Q14 (6a9b0f07111ffc76c2e5f937)
  await updateQuestion('6a9b0f07111ffc76c2e5f937', {
    correctAnswer: `<p>13</p>`,
    wrongAnswer: [`<p>-13</p>`, `<p>26</p>`, `<p>-26</p>`]
  });
  console.log('M2 Q14 fixed: ✅');

  // M2 Q16 (6a9b1069111ffc76c2e5fdcf)
  await updateQuestion('6a9b1069111ffc76c2e5fdcf', {
    correctAnswer: `<p>0.00812</p>`,
    wrongAnswer: [`<p>0.812</p>`, `<p>0.0812</p>`, `<p>8.12</p>`]
  });
  console.log('M2 Q16 fixed: ✅');

  // M2 Q18 (6a9b11fc111ffc76c2e5fed3)
  await updateQuestion('6a9b11fc111ffc76c2e5fed3', {
    correctAnswer: `<p>${f('\\frac{31}{5}')}</p>`,
    wrongAnswer: [
      `<p>${f('\\frac{29}{5}')}</p>`,
      `<p>${f('\\frac{33}{5}')}</p>`,
      `<p>${f('\\frac{36}{5}')}</p>`
    ]
  });
  console.log('M2 Q18 fixed: ✅');

  // M2 Q20 (6a9b12d5111ffc76c2e600fa)
  await updateQuestion('6a9b12d5111ffc76c2e600fa', {
    correctAnswer: `<p>${f('\\frac{5}{3}')}</p>`,
    wrongAnswer: [
      `<p>${f('-\\frac{5}{3}')}</p>`,
      `<p>${f('\\frac{3}{5}')}</p>`,
      `<p>${f('-\\frac{3}{5}')}</p>`
    ]
  });
  console.log('M2 Q20 fixed: ✅');

  // M2 Q21 (6a9b13a9111ffc76c2e603c4)
  await updateQuestion('6a9b13a9111ffc76c2e603c4', {
    correctAnswer: `<p>167</p>`,
    wrongAnswer: [`<p>2</p>`, `<p>169</p>`, `<p>334</p>`]
  });
  console.log('M2 Q21 fixed: ✅');

  // Deduplicate all other MCQs
  console.log('\n2. Deduplicating choices across all other MCQs...');
  const m1Res = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/${M1_ID}`);
  const m2Res = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/${M2_ID}`);

  const customHandled = [
    '6a984ad5e57881aee77ea217', '6a984d17e57881aee77ea236', '6a98507ee57881aee77ea953',
    '6a98523fe57881aee77ea9df', '6a985475e57881aee77ead19', '6a985535e57881aee77ead74',
    '6a985607e57881aee77eaf50', '6a9af216838c4fe747f6d9b5', '6a9af2e2838c4fe747f6de37',
    '6a9af4bf838c4fe747f6e2e8', '6a9af4ec838c4fe747f6e335', '6a9af577838c4fe747f6e49c',
    '6a9af5c0838c4fe747f6e4c1', '6a9afb07838c4fe747f6f030', '6a9afb97838c4fe747f6f04c',
    '6a9afd77838c4fe747f6f052', '6a9afddf838c4fe747f6f05e', '6a9affb6838c4fe747f6f1e3',
    '6a9b007c838c4fe747f6f1ef', '6a9b0d96838c4fe747f71f58', '6a9b0f07111ffc76c2e5f937',
    '6a9b1069111ffc76c2e5fdcf', '6a9b11fc111ffc76c2e5fed3', '6a9b12d5111ffc76c2e600fa',
    '6a9b13a9111ffc76c2e603c4'
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

  console.log('\n✅ All Academic & Structural Fixes Applied for May 2025 INT 1!');
}

run().catch(console.error);
