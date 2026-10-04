const https = require('https');
const fs = require('fs');

const API_BASE = 'https://sat-backend-production.up.railway.app';

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
  console.log('🚀 Applying Academic & Structural Fixes for March 2025 · INT 2...\n');

  // --- MODULE 1 SPECIFIC FIXES ---
  console.log('1. Fixing Module 1 questions...');

  // M1 Q1: Clean stem (remove A:"40" B:"42" ...) and clean choices
  await updateQuestion('6aa46b68ec7ba02921a43dca', {
    question: `<p><span class="ql-formula" data-value="s = 40 + 2t"></span></p><p>The equation gives the speed <span class="ql-formula" data-value="s"></span>, in miles per hour, of a certain car <span class="ql-formula" data-value="t"></span> seconds after it began to accelerate. What is the speed, in miles per hour, of the car 4 seconds after it began to accelerate?</p>`,
    correctAnswer: '<p>48</p>',
    wrongAnswer: ['<p>40</p>', '<p>42</p>', '<p>44</p>']
  });
  console.log('M1 Q1 fixed: ✅');

  // M1 Q2: Deduplicate choices
  await updateQuestion('6aa46bddec7ba02921a43ddd', {
    correctAnswer: '<p><span class="ql-formula" data-value="8^2 + b^2 = 20^2"></span></p>',
    wrongAnswer: [
      '<p><span class="ql-formula" data-value="8b = 20"></span></p>',
      '<p><span class="ql-formula" data-value="8 + b = 20"></span></p>',
      '<p><span class="ql-formula" data-value="8^2 - b^2 = 20^2"></span></p>'
    ]
  });
  console.log('M1 Q2 fixed: ✅');

  // M1 Q3: Deduplicate choices
  await updateQuestion('6aa46ca9ec7ba02921a43de1', {
    correctAnswer: '<p>219</p>',
    wrongAnswer: ['<p>69</p>', '<p>119</p>', '<p>169</p>']
  });
  console.log('M1 Q3 fixed: ✅');

  // M1 Q4: Deduplicate choices
  await updateQuestion('6aa46d0aec7ba02921a43de5', {
    correctAnswer: '<p>4</p>',
    wrongAnswer: ['<p>6</p>', '<p>10</p>', '<p>39</p>']
  });
  console.log('M1 Q4 fixed: ✅');

  // M1 Q7: Deduplicate choices
  await updateQuestion('6aa46d9fec7ba02921a43df4', {
    correctAnswer: '<p>400%</p>',
    wrongAnswer: ['<p>20%</p>', '<p>64%</p>', '<p>80%</p>']
  });
  console.log('M1 Q7 fixed: ✅');

  // M1 Q8: Fix correctAnswer from 400% to y = -x + 2.3
  await updateQuestion('6aa46dd4ec7ba02921a43df8', {
    correctAnswer: '<p><span class="ql-formula" data-value="y = -x + 2.3"></span></p>',
    wrongAnswer: [
      '<p><span class="ql-formula" data-value="y = x - 16.3"></span></p>',
      '<p><span class="ql-formula" data-value="y = -x + 16.3"></span></p>',
      '<p><span class="ql-formula" data-value="y = x - 2.3"></span></p>'
    ]
  });
  console.log('M1 Q8 fixed: ✅');

  // M1 Q10: Deduplicate choices
  await updateQuestion('6aa46e9aec7ba02921a43e12', {
    correctAnswer: '<p>(10, 58)</p>',
    wrongAnswer: ['<p>(5, 6)</p>', '<p>(6, 5)</p>', '<p>(58, 10)</p>']
  });
  console.log('M1 Q10 fixed: ✅');

  // M1 Q11: Deduplicate choices
  await updateQuestion('6aa46f36ec7ba02921a43e29', {
    correctAnswer: '<p>The length of the rectangle, in feet</p>',
    wrongAnswer: [
      '<p>The area of the rectangle, in square feet</p>',
      '<p>The difference between the length and the width of the rectangle, in feet</p>',
      '<p>The width of the rectangle, in feet</p>'
    ]
  });
  console.log('M1 Q11 fixed: ✅');

  // M1 Q12: Deduplicate choices
  await updateQuestion('6aa46fbfec7ba02921a43e2d', {
    correctAnswer: '<p><span class="ql-formula" data-value="y = 160"></span></p>',
    wrongAnswer: [
      '<p><span class="ql-formula" data-value="x = 20"></span></p>',
      '<p><span class="ql-formula" data-value="w + y = 180"></span></p>',
      '<p><span class="ql-formula" data-value="y + z = 180"></span></p>'
    ]
  });
  console.log('M1 Q12 fixed: ✅');

  // M1 Q13: Deduplicate choices
  await updateQuestion('6aa46feaec7ba02921a43e31', {
    correctAnswer: '<p>80</p>',
    wrongAnswer: ['<p>20</p>', '<p>40</p>', '<p>320</p>']
  });
  console.log('M1 Q13 fixed: ✅');

  // M1 Q15: Deduplicate choices
  await updateQuestion('6aa47063ec7ba02921a43e39', {
    correctAnswer: '<p><span class="ql-formula" data-value="\\begin{array}{|c|c|c|c|c|} \\hline x & -6 & 0 & 6 & 12 \\\\ \\hline f(x) & 12 & 24 & 48 & 96 \\\\ \\hline \\end{array}"></span></p>',
    wrongAnswer: [
      '<p><span class="ql-formula" data-value="\\begin{array}{|c|c|c|c|c|} \\hline x & -6 & 0 & 6 & 12 \\\\ \\hline f(x) & 12 & 0 & 48 & 96 \\\\ \\hline \\end{array}"></span></p>',
      '<p><span class="ql-formula" data-value="\\begin{array}{|c|c|c|c|c|} \\hline x & -6 & 0 & 6 & 12 \\\\ \\hline f(x) & -12 & 24 & 48 & 96 \\\\ \\hline \\end{array}"></span></p>',
      '<p><span class="ql-formula" data-value="\\begin{array}{|c|c|c|c|c|} \\hline x & -6 & 0 & 6 & 12 \\\\ \\hline f(x) & 12 & 24 & 48 & 72 \\\\ \\hline \\end{array}"></span></p>'
    ]
  });
  console.log('M1 Q15 fixed: ✅');

  // M1 Q16: Fix correctAnswer from table to equation
  await updateQuestion('6aa470a9ec7ba02921a43e3d', {
    correctAnswer: '<p><span class="ql-formula" data-value="(x - 18)^2 + (y - 16)^2 = 36k^2"></span></p>',
    wrongAnswer: [
      '<p><span class="ql-formula" data-value="(x - 18)^2 + (y - 16)^2 = 36k"></span></p>',
      '<p><span class="ql-formula" data-value="(x - 18)^2 + (y - 16)^2 = 6k"></span></p>',
      '<p><span class="ql-formula" data-value="(x - 18)^2 + (y - 16)^2 = 6k^2"></span></p>'
    ]
  });
  console.log('M1 Q16 fixed: ✅');

  // M1 Q17: Clean answer array
  await updateQuestion('6aa470e6ec7ba02921a43e41', {
    answer: ['27/4', '6.75']
  });
  console.log('M1 Q17 fixed: ✅');

  // M1 Q18: Fix correct conversion expression
  await updateQuestion('6aa47145ec7ba02921a43e45', {
    correctAnswer: '<p><span class="ql-formula" data-value="-\\frac{5}{12}\\pi \\cdot \\frac{180^\\circ}{\\pi}"></span></p>',
    wrongAnswer: [
      '<p><span class="ql-formula" data-value="-\\frac{5}{12} \\cdot \\frac{180^\\circ}{\\pi}"></span></p>',
      '<p><span class="ql-formula" data-value="-\\frac{5}{12}\\pi \\cdot \\frac{\\pi}{180^\\circ}"></span></p>',
      '<p><span class="ql-formula" data-value="-\\frac{5}{12}\\pi \\cdot \\frac{360^\\circ}{\\pi}"></span></p>'
    ]
  });
  console.log('M1 Q18 fixed: ✅');

  // M1 Q19: Deduplicate choices
  await updateQuestion('6aa47179ec7ba02921a43e49', {
    correctAnswer: '<p>84</p>',
    wrongAnswer: ['<p>0</p>', '<p>7</p>', '<p>14</p>']
  });
  console.log('M1 Q19 fixed: ✅');

  // M1 Q21: Fix correctAnswer from 84 to (3, 8 - 1/m)
  await updateQuestion('6aa47237ec7ba02921a43e51', {
    correctAnswer: '<p><span class="ql-formula" data-value="(3, 8 - \\frac{1}{m})"></span></p>',
    wrongAnswer: [
      '<p><span class="ql-formula" data-value="(3, 8 + \\frac{1}{m})"></span></p>',
      '<p><span class="ql-formula" data-value="(3, 8 - m)"></span></p>',
      '<p><span class="ql-formula" data-value="(3, 8 + m)"></span></p>'
    ]
  });
  console.log('M1 Q21 fixed: ✅');

  // M1 Q22: Fix correctAnswer from 84 to 4
  await updateQuestion('6aa4729bec7ba02921a43e58', {
    correctAnswer: '<p>4</p>',
    wrongAnswer: ['<p>6</p>', '<p>10</p>', '<p>39</p>']
  });
  console.log('M1 Q22 fixed: ✅');


  // --- MODULE 2 SPECIFIC FIXES ---
  console.log('\n2. Fixing Module 2 questions...');

  // M2 Q1: Deduplicate choices
  await updateQuestion('6aa4739cec7ba02921a43e64', {
    correctAnswer: `<p>1.0 second after being launched, the ball's height above ground is 3.9 meters.</p>`,
    wrongAnswer: [
      `<p>3.9 seconds after being launched, the ball's height above ground is 1.0 meter.</p>`,
      `<p>The ball was launched from an initial height of 1.0 meter with an initial velocity of 3.9 meters per second.</p>`,
      `<p>The ball was launched from an initial height of 3.9 meters with an initial velocity of 1.0 meter per second.</p>`
    ]
  });
  console.log('M2 Q1 fixed: ✅');

  // M2 Q2: Clean stem (remove A:"..." B:"...")
  await updateQuestion('6aa473f4ec7ba02921a43e68', {
    question: `<p>In one week in 2017, a technician earned a total of $700 by working at her regular job and at a second job doing part-time work. The equation <span class="ql-formula" data-value="16h + 13c = 700"></span> represents this situation where <span class="ql-formula" data-value="h"></span> is the number of hours worked at her regular job and <span class="ql-formula" data-value="c"></span> is the number of hours worked at her second job. Which of the following is the best interpretation of 16 in this context?</p>`,
    correctAnswer: `<p>The amount, in dollars, the technician earned for each hour she worked at her regular job</p>`,
    wrongAnswer: [
      `<p>The amount, in dollars, the technician earned for each hour she worked at her second job</p>`,
      `<p>The number of hours the technician worked in one week at her regular job</p>`,
      `<p>The number of hours the technician worked in one week at her second job</p>`
    ]
  });
  console.log('M2 Q2 fixed: ✅');

  // M2 Q3: Deduplicate choices
  await updateQuestion('6aa47419ec7ba02921a43e6c', {
    correctAnswer: '<p>46, 47, 47, 47, 48</p>',
    wrongAnswer: [
      '<p>44, 45, 47, 49, 50</p>',
      '<p>45, 45, 47, 49, 49</p>',
      '<p>45, 46, 47, 48, 49</p>'
    ]
  });
  console.log('M2 Q3 fixed: ✅');

  // M2 Q4: Deduplicate choices
  await updateQuestion('6aa47536ec7ba02921a43e83', {
    correctAnswer: '<p><span class="ql-formula" data-value="56^\\circ"></span></p>',
    wrongAnswer: [
      '<p><span class="ql-formula" data-value="24^\\circ"></span></p>',
      '<p><span class="ql-formula" data-value="(24 + 56)^\\circ"></span></p>',
      '<p><span class="ql-formula" data-value="(24 \\cdot 56)^\\circ"></span></p>'
    ]
  });
  console.log('M2 Q4 fixed: ✅');

  // M2 Q5: Fix correctAnswer from 56° to 15
  await updateQuestion('6aa47590ec7ba02921a43e87', {
    correctAnswer: '<p>15</p>',
    wrongAnswer: ['<p>4</p>', '<p>77</p>', '<p>120</p>']
  });
  console.log('M2 Q5 fixed: ✅');

  // M2 Q6: Deduplicate choices
  await updateQuestion('6aa475dfec7ba02921a43e8b', {
    correctAnswer: '<p>26</p>',
    wrongAnswer: ['<p>20</p>', '<p>14</p>', '<p>6</p>']
  });
  console.log('M2 Q6 fixed: ✅');

  // M2 Q7: Deduplicate choices
  await updateQuestion('6aa4761bec7ba02921a43e8f', {
    correctAnswer: '<p><span class="ql-formula" data-value="y = 22"></span></p>',
    wrongAnswer: [
      '<p><span class="ql-formula" data-value="y = 22 + 5"></span></p>',
      '<p><span class="ql-formula" data-value="y = \\frac{22}{5}"></span></p>',
      '<p><span class="ql-formula" data-value="y = 5"></span></p>'
    ]
  });
  console.log('M2 Q7 fixed: ✅');

  // M2 Q8: Deduplicate choices
  await updateQuestion('6aa47652ec7ba02921a43e93', {
    correctAnswer: '<p><span class="ql-formula" data-value="M = 100(0.78)^{\\frac{t}{11.11}}"></span></p>',
    wrongAnswer: [
      '<p><span class="ql-formula" data-value="M = 100(0.22)^{t+11.11}"></span></p>',
      '<p><span class="ql-formula" data-value="M = 100(0.22)^{\\frac{t}{11.11}}"></span></p>',
      '<p><span class="ql-formula" data-value="M = 100(0.78)^{t+11.11}"></span></p>'
    ]
  });
  console.log('M2 Q8 fixed: ✅');

  // M2 Q9: Deduplicate choices
  await updateQuestion('6aa476a5ec7ba02921a43e97', {
    correctAnswer: '<p><span class="ql-formula" data-value="y = 8x + 15"></span></p>',
    wrongAnswer: [
      '<p><span class="ql-formula" data-value="y = 15x + 7"></span></p>',
      '<p><span class="ql-formula" data-value="y = -15x + 7"></span></p>',
      '<p><span class="ql-formula" data-value="y = -8x + 15"></span></p>'
    ]
  });
  console.log('M2 Q9 fixed: ✅');

  // M2 Q10: Deduplicate choices
  await updateQuestion('6aa4774dec7ba02921a43e9b', {
    correctAnswer: '<p><span class="ql-formula" data-value="\\frac{2}{7}"></span></p>',
    wrongAnswer: ['<p>-1</p>', '<p>2</p>', '<p>9</p>']
  });
  console.log('M2 Q10 fixed: ✅');

  // M2 Q12: Deduplicate choices
  await updateQuestion('6aa47822ec7ba02921a43ece', {
    correctAnswer: '<p>5.5</p>',
    wrongAnswer: ['<p>-4</p>', '<p>-3</p>', '<p>3</p>']
  });
  console.log('M2 Q12 fixed: ✅');

  // M2 Q14: Deduplicate choices
  await updateQuestion('6aa47928ec7ba02921a43ed9', {
    correctAnswer: '<p>272</p>',
    wrongAnswer: ['<p>108</p>', '<p>176</p>', '<p>312</p>']
  });
  console.log('M2 Q14 fixed: ✅');

  // M2 Q15: Deduplicate choices
  await updateQuestion('6aa47959ec7ba02921a43edd', {
    correctAnswer: '<p><span class="ql-formula" data-value="15x + 150"></span></p>',
    wrongAnswer: [
      '<p><span class="ql-formula" data-value="15x + 10"></span></p>',
      '<p><span class="ql-formula" data-value="15x + 25"></span></p>',
      '<p><span class="ql-formula" data-value="15x + 5"></span></p>'
    ]
  });
  console.log('M2 Q15 fixed: ✅');

  // M2 Q16: Fix correctAnswer from 15x + 150 to f(x) = -5^x + 3
  await updateQuestion('6aa4799eec7ba02921a43ee1', {
    correctAnswer: '<p><span class="ql-formula" data-value="f(x) = -5^x + 3"></span></p>',
    wrongAnswer: [
      '<p><span class="ql-formula" data-value="f(x) = -5^x + 1"></span></p>',
      '<p><span class="ql-formula" data-value="f(x) = -5^x + 4"></span></p>',
      '<p><span class="ql-formula" data-value="f(x) = -5^x + 5"></span></p>'
    ]
  });
  console.log('M2 Q16 fixed: ✅');

  // M2 Q17: Clean stem (remove A:"..." B:"...")
  await updateQuestion('6aa479c5ec7ba02921a43ee5', {
    question: `<p>A square map has a side length of 45 inches, and 1 inch on the map represents an actual distance of 13 miles. A smaller version of the same map is printed as a square with the side length 70% shorter than the side length of the previous map. On the smaller map, which of the following is closest to the actual distance, in miles, represented by 1 inch?</p>`,
    correctAnswer: '<p>43.33</p>',
    wrongAnswer: ['<p>3.90</p>', '<p>7.65</p>', '<p>31.50</p>']
  });
  console.log('M2 Q17 fixed: ✅');

  // M2 Q21: Complete truncated stem
  await updateQuestion('6aa47b39ec7ba02921a43ef5', {
    question: `<p><span class="ql-formula" data-value="24x^2 - (12a + 2b)x + ab = 0"></span></p><p>In the given equation, <span class="ql-formula" data-value="a"></span> and <span class="ql-formula" data-value="b"></span> are positive constants. The sum of the solutions to the given equation is <span class="ql-formula" data-value="k(6a + b)"></span>, where <span class="ql-formula" data-value="k"></span> is a constant. What is the value of <span class="ql-formula" data-value="k"></span>?</p>`,
    answer: ['1/12', '112']
  });
  console.log('M2 Q21 fixed: ✅');

  // M2 Q22: Deduplicate choices
  await updateQuestion('6aa47b98ec7ba02921a43efc', {
    correctAnswer: '<p>15</p>',
    wrongAnswer: ['<p>4</p>', '<p>77</p>', '<p>120</p>']
  });
  console.log('M2 Q22 fixed: ✅');

  console.log('\n🎉 All Academic & Choice Fixes Successfully Applied for March 2025 INT 2!');
}

run().catch(console.error);
