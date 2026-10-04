const https = require('https');
const fs = require('fs');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a6d680707c5da645a88cae3';
const M2_ID = '6a6d680d07c5da645a88caeb';

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
  console.log('🚀 Applying Academic & Structural Fixes for June 2025 · US 1...\n');

  // 1. Specific question fixes
  console.log('1. Applying specific question fixes...');

  // M1 Q13 (6a6e0799f37fd34c9d2ad08f)
  console.log('Fixing M1 Q13 options...');
  await updateQuestion('6a6e0799f37fd34c9d2ad08f', {
    correctAnswer: `<p>The center is at ${f('(14, k)')} and the radius is 6.</p>`,
    wrongAnswer: [
      `<p>The center is at ${f('(k, 14)')} and the radius is 6.</p>`,
      `<p>The center is at ${f('(k, 14)')} and the radius is 36.</p>`,
      `<p>The center is at ${f('(14, k)')} and the radius is 36.</p>`
    ]
  });
  console.log('M1 Q13 update: ✅');

  // M1 Q21 (6a6e0dfdf37fd34c9d2ad0cc)
  console.log('Fixing M1 Q21 stem...');
  await updateQuestion('6a6e0dfdf37fd34c9d2ad0cc', {
    question: `<p>Line ${f('j')} is defined by ${f('4x + 5y = 55')}. Line ${f('k')} is parallel to line ${f('j')} in the xy-plane. An equation of line ${f('k')} is ${f('24x + ry = 15')}, where ${f('r')} is a constant. If line ${f('k')} passes through the point ${f('(0, b)')}, what is the value of ${f('b')}?</p>`
  });
  console.log('M1 Q21 update: ✅');

  // M2 Q4 (6a6e10adf37fd34c9d2ad115)
  console.log('Fixing M2 Q4 stem and options...');
  await updateQuestion('6a6e10adf37fd34c9d2ad115', {
    question: `<p>An object has a mass of 3,080 grams and a volume of 280 cubic centimeters. What is the density, in grams per cubic centimeter, of the object?</p>`,
    correctAnswer: `<p>11</p>`,
    wrongAnswer: [
      `<p>280</p>`,
      `<p>3,080</p>`,
      `<p>8,624</p>`
    ]
  });
  console.log('M2 Q4 update: ✅');

  // M2 Q6 (6a6e1127f37fd34c9d2ad11d)
  console.log('Fixing M2 Q6 stem and options...');
  await updateQuestion('6a6e1127f37fd34c9d2ad11d', {
    question: `<p>The graph of ${f('y = f(x) - 9')} is shown. Which equation defines the linear function ${f('f')}?</p>`,
    correctAnswer: `<p>${f('f(x) = -5x + 8')}</p>`,
    wrongAnswer: [
      `<p>${f('f(x) = -14x - 9')}</p>`,
      `<p>${f('f(x) = -5x - 9')}</p>`,
      `<p>${f('f(x) = -14x + 8')}</p>`
    ]
  });
  console.log('M2 Q6 update: ✅');

  // M2 Q12 (6a6e1898808167941fdca79d)
  console.log('Fixing M2 Q12 stem and options...');
  const tableHtml = 
    `<table style="border-collapse: collapse; margin: 12px 0; text-align: center;">` +
      `<thead>` +
        `<tr style="border-bottom: 2px solid #333;">` +
          `<th style="padding: 6px 14px; text-align: left;">Type of tree</th>` +
          `<th style="padding: 6px 14px;">Site A</th>` +
          `<th style="padding: 6px 14px;">Site B</th>` +
          `<th style="padding: 6px 14px;">Total</th>` +
        `</tr>` +
      `</thead>` +
      `<tbody>` +
        `<tr style="border-bottom: 1px solid #ccc;">` +
          `<td style="padding: 6px 14px; text-align: left;">Red maple</td>` +
          `<td style="padding: 6px 14px;">35</td>` +
          `<td style="padding: 6px 14px;">15</td>` +
          `<td style="padding: 6px 14px;">50</td>` +
        `</tr>` +
        `<tr style="border-bottom: 1px solid #ccc;">` +
          `<td style="padding: 6px 14px; text-align: left;">Silver maple</td>` +
          `<td style="padding: 6px 14px;">45</td>` +
          `<td style="padding: 6px 14px;">35</td>` +
          `<td style="padding: 6px 14px;">80</td>` +
        `</tr>` +
        `<tr style="font-weight: bold;">` +
          `<td style="padding: 6px 14px; text-align: left;">Total</td>` +
          `<td style="padding: 6px 14px;">80</td>` +
          `<td style="padding: 6px 14px;">50</td>` +
          `<td style="padding: 6px 14px;">130</td>` +
        `</tr>` +
      `</tbody>` +
    `</table>`;

  await updateQuestion('6a6e1898808167941fdca79d', {
    question: `<p>The table shows the distribution of two types of trees at two different sites.</p>${tableHtml}<p>If a tree represented in the table is selected at random, what is the probability of selecting a tree from site A, given that the tree is a red maple? (Express your answer as a decimal or fraction, not as a percent.)</p>`,
    correctAnswer: `<p>${f('\\frac{35}{50}')}</p>`,
    wrongAnswer: [
      `<p>${f('0.3')}</p>`,
      `<p>${f('\\frac{15}{50}')}</p>`,
      `<p>${f('\\frac{35}{80}')}</p>`
    ]
  });
  console.log('M2 Q12 update: ✅');

  // 2. Deduplicate choices across all MCQs
  console.log('\n2. Deduplicating choices across all MCQs...');
  const m1Res = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/${M1_ID}`);
  const m2Res = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/${M2_ID}`);

  const allQs = [...m1Res.chapter.questions, ...m2Res.chapter.questions];

  for (const q of allQs) {
    if (q.typeOfAnswer !== 'MCQ') continue;
    // Skip if already custom handled above
    if (['6a6e0799f37fd34c9d2ad08f', '6a6e10adf37fd34c9d2ad115', '6a6e1127f37fd34c9d2ad11d', '6a6e1898808167941fdca79d'].includes(q._id)) continue;

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

  console.log('\n✅ All Academic & Structural Fixes Applied for June 2025 US 1!');
}

run().catch(console.error);
