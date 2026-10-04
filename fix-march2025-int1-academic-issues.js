const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6aa0f076df63ca493d4799ef';
const M2_ID = '6aa0f07cdf63ca493d4799f5';

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
  console.log('🚀 Applying Academic & Structural Fixes for March 2025 · INT 1...\n');

  console.log('1. Applying specific question fixes for Module 1...');

  // M1 Q1 (6aa0f3fbdf63ca493d4799fd)
  await updateQuestion('6aa0f3fbdf63ca493d4799fd', {
    question: `<p>The cost ${f('y')}, in dollars, for a manufacturer to make ${f('x')} rings is represented by the line shown. What is the cost, in dollars, for the manufacturer to make 50 rings?</p>`,
    correctAnswer: `<p>175</p>`,
    wrongAnswer: [`<p>100</p>`, `<p>125</p>`, `<p>225</p>`]
  });
  console.log('M1 Q1 fixed: ✅');

  // M1 Q2 (6aa0f439df63ca493d479a03)
  await updateQuestion('6aa0f439df63ca493d479a03', {
    correctAnswer: `<p>${f('9x^2 + 54')}</p>`,
    wrongAnswer: [
      `<p>${f('9x^2 + 3')}</p>`,
      `<p>${f('9x^2 + 6')}</p>`,
      `<p>${f('9x^2 + 15')}</p>`
    ]
  });
  console.log('M1 Q2 fixed: ✅');

  // M1 Q3 (6aa0f5cfdf63ca493d479a0b)
  await updateQuestion('6aa0f5cfdf63ca493d479a0b', {
    correctAnswer: `<p>A graph showing two lines that intersect at (5, 5)</p>`,
    wrongAnswer: [
      `<p>A graph showing two lines that intersect at (2.5, 2.5)</p>`,
      `<p>A graph showing two lines that intersect at (5, 0)</p>`,
      `<p>A graph showing two lines that are parallel</p>`
    ]
  });
  console.log('M1 Q3 fixed: ✅');

  // M1 Q8 (6aa0f6dedf63ca493d479a29)
  await updateQuestion('6aa0f6dedf63ca493d479a29', {
    correctAnswer: `<p>${f('59^\\circ')}</p>`,
    wrongAnswer: [
      `<p>${f('(28 \\times 59)^\\circ')}</p>`,
      `<p>${f('(28 + 59)^\\circ')}</p>`,
      `<p>${f('28^\\circ')}</p>`
    ]
  });
  console.log('M1 Q8 fixed: ✅');

  // M1 Q9 (6aa0f716df63ca493d479a2f)
  await updateQuestion('6aa0f716df63ca493d479a2f', {
    correctAnswer: `<p>${f('s + 30 \\ge 190')}</p>`,
    wrongAnswer: [
      `<p>${f('s + 30 \\le 190')}</p>`,
      `<p>${f('s - 30 \\le 190')}</p>`,
      `<p>${f('s - 30 \\ge 190')}</p>`
    ]
  });
  console.log('M1 Q9 fixed: ✅');

  // M1 Q10 (6aa0f75bdf63ca493d479a35)
  await updateQuestion('6aa0f75bdf63ca493d479a35', {
    correctAnswer: `<p>${f('7x^2(x^4 - 2)')}</p>`,
    wrongAnswer: [
      `<p>${f('7(x^3 - 2x^2)^2')}</p>`,
      `<p>${f('x^2(7x - 2)^4')}</p>`,
      `<p>${f('7x^2(x - 2)^4')}</p>`
    ]
  });
  console.log('M1 Q10 fixed: ✅');

  // M1 Q13 (6aa0fd88df63ca493d479a5e)
  await updateQuestion('6aa0fd88df63ca493d479a5e', {
    correctAnswer: `<p>Increasing exponential</p>`,
    wrongAnswer: [
      `<p>Decreasing exponential</p>`,
      `<p>Decreasing linear</p>`,
      `<p>Increasing linear</p>`
    ]
  });
  console.log('M1 Q13 fixed: ✅');

  // M1 Q14 (6aa0fe0ddf63ca493d479a64)
  await updateQuestion('6aa0fe0ddf63ca493d479a64', {
    correctAnswer: `<p>${f('\\frac{2\\sqrt{10}}{7}')}</p>`,
    wrongAnswer: [
      `<p>${f('\\frac{3\\sqrt{10}}{20}')}</p>`,
      `<p>${f('\\frac{7\\sqrt{10}}{20}')}</p>`,
      `<p>${f('\\frac{2\\sqrt{10}}{3}')}</p>`
    ]
  });
  console.log('M1 Q14 fixed: ✅');

  // M1 Q15 (6aa0fe45df63ca493d479a6a)
  await updateQuestion('6aa0fe45df63ca493d479a6a', {
    correctAnswer: `<p>2</p>`,
    wrongAnswer: [`<p>14</p>`, `<p>${f('\\frac{1}{2}')}</p>`, `<p>${f('\\frac{1}{14}')}</p>`]
  });
  console.log('M1 Q15 fixed: ✅');

  console.log('\n2. Applying specific question fixes for Module 2...');

  // M2 Q2 (6aa11386febc2d25093882c8)
  await updateQuestion('6aa11386febc2d25093882c8', {
    question: `<p>For the linear function ${f('p')}, ${f('p(c) = -5')}, where ${f('c')} is a constant, ${f('p(3) = 23')}, and the slope of the graph of ${f('y = p(x)')} in the xy-plane is 7. For the linear function ${f('t')}, ${f('t(c) = -6')} and ${f('t(4) = 34')}. What is the slope of the graph of ${f('y = t(x)')} in the xy-plane?</p>`,
    correctAnswer: `<p>8</p>`,
    wrongAnswer: [`<p>-1</p>`, `<p>2</p>`, `<p>7</p>`]
  });
  console.log('M2 Q2 fixed: ✅');

  // M2 Q4 (6aa115d2febc2d25093882d0)
  await updateQuestion('6aa115d2febc2d25093882d0', {
    correctAnswer: `<p>84.6</p>`,
    wrongAnswer: [`<p>795.2</p>`, `<p>9.4</p>`, `<p>5.3</p>`]
  });
  console.log('M2 Q4 fixed: ✅');

  // M2 Q5 (6aa1169efebc2d25093882d4)
  await updateQuestion('6aa1169efebc2d25093882d4', {
    correctAnswer: `<p>632</p>`,
    wrongAnswer: [`<p>-53</p>`, `<p>127</p>`, `<p>643</p>`]
  });
  console.log('M2 Q5 fixed: ✅');

  // M2 Q6 (6aa1172ef5c99543faeb6316)
  await updateQuestion('6aa1172ef5c99543faeb6316', {
    correctAnswer: `<p>9</p>`,
    wrongAnswer: [`<p>4</p>`, `<p>39</p>`, `<p>108</p>`]
  });
  console.log('M2 Q6 fixed: ✅');

  // M2 Q8 (6aa117aef5c99543faeb63ec)
  await updateQuestion('6aa117aef5c99543faeb63ec', {
    correctAnswer: `<p>${f('11x(x^9 - x^8 + 7)')}</p>`,
    wrongAnswer: [
      `<p>${f('x(10x^{10} - 10x^9 + 76x)')}</p>`,
      `<p>${f('x(11x^{10} - 11x^9 + 77)')}</p>`,
      `<p>${f('11x(x^{10} - x^9 + 7x)')}</p>`
    ]
  });
  console.log('M2 Q8 fixed: ✅');

  // M2 Q10 (6aa1181bf5c99543faeb6434)
  await updateQuestion('6aa1181bf5c99543faeb6434', {
    correctAnswer: `<p>The length, in inches, Audrey's hair will grow each month</p>`,
    wrongAnswer: [
      `<p>The time, in months, it will take Audrey's hair to grow 1 inch</p>`,
      `<p>The time, in months, it will take Audrey's hair to reach a length of 11 inches</p>`,
      `<p>The length, in inches, Audrey's hair will grow in 11 months</p>`
    ]
  });
  console.log('M2 Q10 fixed: ✅');

  // M2 Q11 (6aa119ccf5c99543faeb65aa)
  await updateQuestion('6aa119ccf5c99543faeb65aa', {
    correctAnswer: `<p>y = 226 + 3x</p>`,
    wrongAnswer: [
      `<p>y = 226 - 3x</p>`,
      `<p>y = 3 + 226x</p>`,
      `<p>y = 3 - 226x</p>`
    ]
  });
  console.log('M2 Q11 fixed: ✅');

  // M2 Q14 (6aa11dc5ec7ba02921a31b76)
  await updateQuestion('6aa11dc5ec7ba02921a31b76', {
    correctAnswer: `<p>184</p>`,
    wrongAnswer: [`<p>73</p>`, `<p>119</p>`, `<p>211</p>`]
  });
  console.log('M2 Q14 fixed: ✅');

  // M2 Q16 (6aa11e30ec7ba02921a31b7e)
  await updateQuestion('6aa11e30ec7ba02921a31b7e', {
    correctAnswer: `<p>3 &lt; x &lt; 17</p>`,
    wrongAnswer: [
      `<p>x &lt; 17</p>`,
      `<p>x &gt; 17</p>`,
      `<p>x &lt; 3 or x &gt; 17</p>`
    ]
  });
  console.log('M2 Q16 fixed: ✅');

  // M2 Q17 (6aa11e8aec7ba02921a31b82)
  await updateQuestion('6aa11e8aec7ba02921a31b82', {
    correctAnswer: `<p>${f('f(x) = -6^x + 5')}</p>`,
    wrongAnswer: [
      `<p>${f('f(x) = -6^x + 1')}</p>`,
      `<p>${f('f(x) = -6^x + 8')}</p>`,
      `<p>${f('f(x) = -6^x + 9')}</p>`
    ]
  });
  console.log('M2 Q17 fixed: ✅');

  // M2 Q18 (6aa11f14ec7ba02921a31b86)
  await updateQuestion('6aa11f14ec7ba02921a31b86', {
    correctAnswer: `<p>${f('\\frac{441}{4}')}</p>`,
    wrongAnswer: [
      `<p>${f('\\frac{576}{49}')}</p>`,
      `<p>${f('\\frac{144}{7}')}</p>`,
      `<p>63</p>`
    ]
  });
  console.log('M2 Q18 fixed: ✅');

  // Deduplicate all other MCQs
  console.log('\n3. Deduplicating choices across all other MCQs...');
  const m1Res = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/${M1_ID}`);
  const m2Res = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/${M2_ID}`);

  const customHandled = [
    '6aa0f3fbdf63ca493d4799fd', '6aa0f439df63ca493d479a03', '6aa0f5cfdf63ca493d479a0b',
    '6aa0f6dedf63ca493d479a29', '6aa0f716df63ca493d479a2f', '6aa0f75bdf63ca493d479a35',
    '6aa0fd88df63ca493d479a5e', '6aa0fe0ddf63ca493d479a64', '6aa0fe45df63ca493d479a6a',
    '6aa11386febc2d25093882c8', '6aa115d2febc2d25093882d0', '6aa1169efebc2d25093882d4',
    '6aa1172ef5c99543faeb6316', '6aa117aef5c99543faeb63ec', '6aa1181bf5c99543faeb6434',
    '6aa119ccf5c99543faeb65aa', '6aa11dc5ec7ba02921a31b76', '6aa11e30ec7ba02921a31b7e',
    '6aa11e8aec7ba02921a31b82', '6aa11f14ec7ba02921a31b86'
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

  console.log('\n✅ All Academic & Structural Fixes Applied for March 2025 INT 1!');
}

run().catch(console.error);
