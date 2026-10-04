const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';

function f(formula) {
  return `<span class="ql-formula" data-value="${formula}"></span>`;
}

function updateExplanation(questionId, explanationHtml) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({ explanation: explanationHtml });
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

const explanations = {
  // Q1
  '6a69573fc3d08d90637d3d75':
    `<p>Distribute the negative sign and combine like terms:</p>` +
    `<p>${f('(3x^3 - 8x + 5) - (4x^6 + 9x - 2) = 3x^3 - 8x + 5 - 4x^6 - 9x + 2')}</p>` +
    `<p>Group terms in descending order of degrees:</p>` +
    `<p>${f('-4x^6 + 3x^3 + (-8x - 9x) + (5 + 2) = -4x^6 + 3x^3 - 17x + 7')}</p>`,

  // Q2
  '6a695c06c3d08d90637d3d7b':
    `<p>The equation ${f('y = \\frac{7}{12}x')} is in slope-intercept form ${f('y = mx + b')}, where ${f('m')} is the slope and ${f('b')} is the ${f('y')}-intercept.</p>` +
    `<p>Here, the slope is ${f('m = \\frac{7}{12}')}.</p>`,

  // Q3
  '6a695c66c3d08d90637d3d7f':
    `<p>Substitute ${f('y = 2')} into the given equation ${f('34x + 79y = 260')}:</p>` +
    `<p>${f('34x + 79(2) = 260')}</p>` +
    `<p>${f('34x + 158 = 260')}</p>` +
    `<p>Subtract 158 from both sides:</p>` +
    `<p>${f('34x = 102')} &implies; ${f('x = \\frac{102}{34} = 3')}</p>` +
    `<p>Thus, the volume of mulch is <strong>3</strong> cubic feet.</p>`,

  // Q4
  '6a695cafc3d08d90637d3d83':
    `<p>Test the points in the system of inequalities ${f('y < x')} and ${f('y > -4x - 9')}:</p>` +
    `<p>For the table with points ${f('(5, 4)')}, ${f('(6, 5)')}, and ${f('(7, 6)')}:</p>` +
    `<p>1. At ${f('(5, 4)')}: ${f('4 < 5')} (true) and ${f('4 > -4(5) - 9 = -29')} (true).</p>` +
    `<p>2. At ${f('(6, 5)')}: ${f('5 < 6')} (true) and ${f('5 > -4(6) - 9 = -33')} (true).</p>` +
    `<p>3. At ${f('(7, 6)')}: ${f('6 < 7')} (true) and ${f('6 > -4(7) - 9 = -37')} (true).</p>` +
    `<p>All pairs satisfy both inequalities.</p>`,

  // Q5
  '6a695cf4c3d08d90637d3d87':
    `<p>First, evaluate ${f('g(-10)')}:</p>` +
    `<p>${f('g(-10) = |13(-10) - 9| = |-130 - 9| = |-139| = 139')}</p>` +
    `<p>Next, substitute this result into ${f('f(x)')}:</p>` +
    `<p>${f('f(-10) = 5(g(-10)) - 3 = 5(139) - 3')}</p>` +
    `<p>${f('f(-10) = 695 - 3 = 692')}</p>`,

  // Q6
  '6a695d33c3d08d90637d3d8b':
    `<p>Given the equation:</p>` +
    `<p>${f('\\sqrt{x^2 - 95x + 300} = x\\sqrt{11}')}</p>` +
    `<p>Since the left-hand side is a principal square root, the right-hand side must be non-negative, meaning ${f('x \\ge 0')}.</p>` +
    `<p>Square both sides:</p>` +
    `<p>${f('x^2 - 95x + 300 = 11x^2')}</p>` +
    `<p>${f('10x^2 + 95x - 300 = 0')}</p>` +
    `<p>Divide by 5:</p>` +
    `<p>${f('2x^2 + 19x - 60 = 0')}</p>` +
    `<p>Factor the quadratic:</p>` +
    `<p>${f('(2x - 5)(x + 12) = 0')}</p>` +
    `<p>This gives ${f('x = \\frac{5}{2}')} or ${f('x = -12')}.</p>` +
    `<p>Because ${f('x = -12')} yields a negative right-hand side (${f('-12\\sqrt{11} < 0')}), it is extraneous. The only valid solution is ${f('\\frac{5}{2}')}.</p>`,

  // Q7
  '6a695d4dc3d08d90637d3d8f':
    `<p>The time elapsed between 1657 and 1957 is ${f('1957 - 1657 = 300')} years.</p>` +
    `<p>Since the population doubled every 75 years, the number of doubling periods is:</p>` +
    `<p>${f('\\frac{300}{75} = 4\\text{ doublings}')}</p>` +
    `<p>Let ${f('P')} be the population in 1657. In 1957:</p>` +
    `<p>${f('P \\times 2^4 = 240,000')}</p>` +
    `<p>${f('16P = 240,000')} &implies; ${f('P = \\frac{240,000}{16} = 15,000')}</p>`,

  // Q8
  '6a695d96c3d08d90637d3d93':
    `<p>Find the slope of line ${f('k')} by writing it in slope-intercept form:</p>` +
    `<p>${f('4x + 13y - 5 = 0 \\implies 13y = -4x + 5 \\implies y = -\\frac{4}{13}x + \\frac{5}{13}')}</p>` +
    `<p>The slope of line ${f('k')} is ${f('m_k = -\\frac{4}{13}')}.</p>` +
    `<p>Since line ${f('j')} is perpendicular to line ${f('k')}, its slope is the negative reciprocal:</p>` +
    `<p>${f('m_j = -\\frac{1}{m_k} = -\\frac{1}{-4/13} = \\frac{13}{4}')}</p>`,

  // Q9
  '6a695ddac3d08d90637d3d99':
    `<p>The equation of circle A is ${f('(x - 2)^2 + (y - 4)^2 = 9')}.</p>` +
    `<p>Its center is ${f('(2, 4)')} and its radius is ${f('r_A = \\sqrt{9} = 3')}.</p>` +
    `<p>Circle B has the same center ${f('(2, 4)')} and twice the radius:</p>` +
    `<p>${f('r_B = 2 \\times 3 = 6')}</p>` +
    `<p>The equation representing circle B is:</p>` +
    `<p>${f('(x - 2)^2 + (y - 4)^2 = 6^2 = 36')}</p>`,

  // Q10
  '6a695e8ac3d08d90637d3d9f':
    `<p>In a square with side length ${f('s')}, the length of the diagonal ${f('d')} is ${f('d = s\\sqrt{2}')}.</p>` +
    `<p>We are given ${f('d = \\frac{186\\sqrt{2}}{2} = 93\\sqrt{2}')}.</p>` +
    `<p>Setting ${f('s\\sqrt{2} = 93\\sqrt{2}')} gives ${f('s = 93')}.</p>` +
    `<p>The area of the square is:</p>` +
    `<p>${f('\\text{Area} = s^2 = 93^2 = 8,649\\text{ square units}')}</p>`,

  // Q11
  '6a695eb4c3d08d90637d3da3':
    `<p>To find which data set has the greatest mean, observe the weight given to the highest values:</p>` +
    `<p>The table with frequencies 1, 2, 3, 4 assigns the highest frequency (4) to the largest value (90) and the lowest frequency (1) to the smallest value (60):</p>` +
    `<p>${f('\\text{Mean} = \\frac{1(60) + 2(70) + 3(80) + 4(90)}{1 + 2 + 3 + 4} = \\frac{60 + 140 + 240 + 360}{10} = \\frac{800}{10} = 80')}</p>` +
    `<p>All other datasets are symmetric around 75 or skewed towards lower values, giving means of 75 or lower. Thus, this table has the greatest mean.</p>`,

  // Q12
  '6a695efec3d08d90637d3da7':
    `<p>The initial amount of water in the container is 26 milliliters.</p>` +
    `<p>The faucet drips 0.03 mL every 3 seconds, which is a rate of:</p>` +
    `<p>${f('\\text{Rate} = \\frac{0.03\\text{ mL}}{3\\text{ s}} = 0.01\\text{ mL per second}')}</p>` +
    `<p>After ${f('t')} seconds, the volume of water added is ${f('0.01t')} mL.</p>` +
    `<p>Therefore, the total volume is:</p>` +
    `<p>${f('v = 0.01t + 26')}</p>`,

  // Q13
  '6a695f63c3d08d90637d3db3':
    `<p>Initial temperature is ${f('23^\\circ\\text{C}')}.</p>` +
    `<p>Over the first 4.0 minutes at ${f('6.5^\\circ\\text{C}')} per minute, the temperature rises by:</p>` +
    `<p>${f('4.0 \\times 6.5 = 26^\\circ\\text{C}')}</p>` +
    `<p>So after 4.0 minutes, the temperature is ${f('23 + 26 = 49^\\circ\\text{C}')}.</p>` +
    `<p>After 4.0 minutes, the time elapsed is ${f('(x - 4.0)')} minutes, during which temperature increases at ${f('2.2^\\circ\\text{C}')} per minute.</p>` +
    `<p>Setting the total temperature equal to 61°C:</p>` +
    `<p>${f('61 = 2.2(x - 4.0) + 49')}</p>`,

  // Q14
  '6a695ff9c3d08d90637d3db9':
    `<p>In statistical sampling, results can only be generalized to the population from which the random sample was selected.</p>` +
    `<p>Because the sample of 100 students was randomly selected from a specific high school in Ohio, the largest population to which the findings can reliably be generalized is <strong>all students from the high school</strong>.</p>`,

  // Q15
  '6a6960dfc3d08d90637d3dbf':
    `<p>Translate the given statements into algebraic equations:</p>` +
    `<p>1) ${f('0.13h = 0.19j \\implies h = \\frac{19}{13}j')}</p>` +
    `<p>2) ${f('j = 0.91k = \\frac{91}{100}k')}</p>` +
    `<p>Substitute ${f('j')} into the equation for ${f('h')}:</p>` +
    `<p>${f('h = \\frac{19}{13} \\left(\\frac{91}{100}k\\right)')}</p>` +
    `<p>Since ${f('91 \\div 13 = 7')}:</p>` +
    `<p>${f('h = 19 \\times 7 \\times \\frac{1}{100}k = 133 \\times \\frac{1}{100}k = 1.33k = 133\\% \\text{ of } k')}</p>` +
    `<p>Thus, ${f('h')} is <strong>133</strong>% of ${f('k')}.</p>`,

  // Q16
  '6a6961abc3d08d90637d3dc3':
    `<p>Given ${f('f(x) = 11x^3')}, the function ${f('y = f(-x) + c')} becomes:</p>` +
    `<p>${f('y = 11(-x)^3 + c = -11x^3 + c')}</p>` +
    `<p>where ${f('c')} is a positive integer constant (${f('c > 0')}).</p>` +
    `<p>1. The ${f('y')}-intercept is ${f('(0, t)')}:</p>` +
    `<p>${f('t = -11(0)^3 + c = c')}. Since ${f('c > 0')}, ${f('t > 0')}.</p>` +
    `<p>2. The ${f('x')}-intercept is ${f('(r, 0)')}:</p>` +
    `<p>${f('0 = -11r^3 + c \\implies 11r^3 = c \\implies r^3 = \\frac{c}{11}')}</p>` +
    `<p>Since ${f('c > 0')}, ${f('r^3 > 0 \\implies r > 0')}.</p>` +
    `<p>Therefore, both <strong>${f('r > 0')} and ${f('t > 0')}</strong> must be true.</p>`,

  // Q17
  '6a696210c3d08d90637d3dcf':
    `<p>1. At the end of the first 6 months, the balance increased by 0.4% of $600:</p>` +
    `<p>${f('600 + (0.004 \\times 600) = 600 + 2.40 = 602.40\\text{ dollars}')}</p>` +
    `<p>2. For ${f('x \\ge 6')}, the balance increases by 0.3% every 2 months, which corresponds to multiplying by ${f('(1 + 0.003) = 1.003')} every 2 months.</p>` +
    `<p>The number of 2-month periods that have elapsed after the first 6 months is ${f('\\frac{x - 6}{2}')}.</p>` +
    `<p>Therefore, the model is:</p>` +
    `<p>${f('B(x) = 602.40(1.003)^{\\frac{x - 6}{2}}')}</p>`,

  // Q18
  '6a696256c3d08d90637d3dd5':
    `<p>The parabola ${f('y = -x^2 + 7x - 104')} opens downward.</p>` +
    `<p>A horizontal line ${f('y = c')} intersects the parabola at exactly one point if and only if it passes through the vertex.</p>` +
    `<p>The ${f('x')}-coordinate of the vertex is:</p>` +
    `<p>${f('x = -\\frac{b}{2a} = -\\frac{7}{2(-1)} = \\frac{7}{2}')}</p>` +
    `<p>Find the ${f('y')}-coordinate of the vertex:</p>` +
    `<p>${f('c = -\\left(\\frac{7}{2}\\right)^2 + 7\\left(\\frac{7}{2}\\right) - 104 = -\\frac{49}{4} + \\frac{49}{2} - 104')}</p>` +
    `<p>${f('c = \\frac{49}{4} - \\frac{416}{4} = -\\frac{367}{4}')}</p>`,

  // Q19
  '6a69630dc3d08d90637d3dd9':
    `<p>For any quadratic equation ${f('Ax^2 + Bx + C = 0')}, the product of the solutions is given by Vieta's formula: ${f('\\frac{C}{A}')}.</p>` +
    `<p>Here, ${f('A = \\frac{1}{24}')} and ${f('C = -st')}:</p>` +
    `<p>${f('\\text{Product} = \\frac{-st}{1/24} = -24st')}</p>` +
    `<p>We are given that the product is ${f('-2kst')}:</p>` +
    `<p>${f('-2kst = -24st \\implies -2k = -24 \\implies k = 12')}</p>`,

  // Q20
  '6a6963d2c3d08d90637d3ddf':
    `<p>In right triangle ${f('RST')} with right angle at ${f('T')}:</p>` +
    `<p>${f('\\text{Area} = \\frac{1}{2} \\times RT \\times ST = 396')}</p>` +
    `<p>Given ${f('RT = 72')}:</p>` +
    `<p>${f('\\frac{1}{2} \\times 72 \\times ST = 36 \\times ST = 396 \\implies ST = 11')}</p>` +
    `<p>Because ${f('LK \\parallel RT')}, triangle ${f('SKL')} is similar to triangle ${f('STR')}:</p>` +
    `<p>${f('\\frac{SK}{ST} = \\frac{LK}{RT} = \\frac{24}{72} = \\frac{1}{3}')}</p>` +
    `<p>Therefore, ${f('SK = \\frac{1}{3} \\times 11 = \\frac{11}{3}')}.</p>` +
    `<p>Since point ${f('K')} lies on segment ${f('ST')}:</p>` +
    `<p>${f('KT = ST - SK = 11 - \\frac{11}{3} = \\frac{22}{3} \\approx 7.33')}</p>`,

  // Q21
  '6a696407c3d08d90637d3de3':
    `<p>The rate of increase is 210 square feet per hour.</p>` +
    `<p>1. Convert hours to minutes: divide by 60.</p>` +
    `<p>2. Convert square feet to square meters: since ${f('1\\text{ meter} = 3.28\\text{ feet}')}, ${f('1\\text{ m}^2 = (3.28)^2 = 10.7584\\text{ ft}^2')}.</p>` +
    `<p>${f('\\text{Rate} = \\frac{210}{60 \\times (3.28)^2} = \\frac{3.5}{10.7584} \\approx 0.3253\\text{ m}^2/\\text{min}')}</p>` +
    `<p>Rounding to two decimal places gives <strong>0.33</strong>.</p>`,

  // Q22
  '6a696439c3d08d90637d3de7':
    `<p>Given the equation:</p>` +
    `<p>${f('\\frac{x + 5}{3} = \\frac{x + 5}{13}')}</p>` +
    `<p>Subtract ${f('\\frac{x + 5}{13}')} from both sides:</p>` +
    `<p>${f('\\frac{x + 5}{3} - \\frac{x + 5}{13} = 0')}</p>` +
    `<p>Factor out ${f('(x + 5)')}:</p>` +
    `<p>${f('(x + 5)\\left(\\frac{1}{3} - \\frac{1}{13}\\right) = 0')}</p>` +
    `<p>Since ${f('\\frac{1}{3} - \\frac{1}{13} = \\frac{10}{39} \\ne 0')}, we must have:</p>` +
    `<p>${f('x + 5 = 0')}</p>` +
    `<p>The value of ${f('x + 5')} is 0, which lies between <strong>-4 and 4</strong>.</p>`
};

async function run() {
  console.log('🚀 Injecting 22 explanations for September 2025 · US 1 (M2)...\n');
  const ids = Object.keys(explanations);
  let count = 0;
  for (const id of ids) {
    process.stdout.write(`Updating explanation for ${id}... `);
    const res = await updateExplanation(id, explanations[id]);
    if (res.message === 'success') {
      count++;
      console.log('✅ Success');
    } else {
      console.log('⚠️ Failed:', JSON.stringify(res));
    }
  }
  console.log(`\n🎉 Injected ${count}/${ids.length} explanations for Module 2!`);
}

run().catch(console.error);
