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
  '6a694e47c3d08d90637d3cd3':
    `<p>Distance is calculated as ${f('\\text{distance} = \\text{speed} \\times \\text{time}')}:</p>` +
    `<p>${f('\\text{Distance} = 16\\text{ m/s} \\times 6\\text{ s} = 96\\text{ meters}')}</p>` +
    `<p>Thus, the goose would fly <strong>96</strong> meters in 6 seconds.</p>`,

  // Q2
  '6a694ee3c3d08d90637d3cd9':
    `<p>In the figure, lines ${f('r')} and ${f('s')} are parallel, cut by transversal ${f('t')}.</p>` +
    `<p>The acute angle formed by line ${f('r')} and transversal ${f('t')} is ${f('77^\\circ')}.</p>` +
    `<p>Because lines ${f('r')} and ${f('s')} are parallel, corresponding angles are equal, and vertical angles are also equal.</p>` +
    `<p>Angle ${f('a^\\circ')} and the opposite vertical angle measure ${f('77^\\circ')}. Therefore, ${f('a = 77')}.</p>`,

  // Q3
  '6a694f2ec3d08d90637d3cdf':
    `<p>To find the body length predicted by the line of best fit for a 3-year-old seal:</p>` +
    `<p>1. Locate ${f('x = 3')} years on the horizontal axis (age).</p>` +
    `<p>2. Move vertically up to intersect the line of best fit.</p>` +
    `<p>3. Move horizontally to the vertical axis (body length in cm), which reads approximately ${f('100\\text{ cm}')}.</p>` +
    `<p>Rounded to the nearest 10 cm, the predicted length is <strong>100</strong>.</p>`,

  // Q4
  '6a694fa0c3d08d90637d3ce5':
    `<p>The relationship between the mass and extension length is linear. Determine the constant rate of extension per gram:</p>` +
    `<p>${f('\\text{Rate} = \\frac{7\\text{ cm}}{20\\text{ g}} = 0.35\\text{ cm per gram}')}</p>` +
    `<p>Check with the second point: ${f('\\frac{21\\text{ cm}}{60\\text{ g}} = 0.35\\text{ cm per gram}')}.</p>` +
    `<p>Now, calculate the extension for a 50-gram mass:</p>` +
    `<p>${f('\\text{Extension} = 50 \\times 0.35 = 17.5\\text{ centimeters}')}</p>`,

  // Q5
  '6a694feec3d08d90637d3ceb':
    `<p>The amount of remaining gas is given by the function:</p>` +
    `<p>${f('g = 13 - \\frac{x}{29}')}</p>` +
    `<p>Substitute ${f('x = 290')} into the equation:</p>` +
    `<p>${f('g = 13 - \\frac{290}{29} = 13 - 10 = 3')}</p>` +
    `<p>Thus, <strong>3</strong> gallons of gas remain in the tank.</p>`,

  // Q6
  '6a695025c3d08d90637d3cef':
    `<p>The given equation is:</p>` +
    `<p>${f('\\sqrt{x^2} = 80 - 9x')}</p>` +
    `<p>For positive values of ${f('x')}, ${f('\\sqrt{x^2} = x')}. Substituting gives:</p>` +
    `<p>${f('x = 80 - 9x')}</p>` +
    `<p>Add ${f('9x')} to both sides:</p>` +
    `<p>${f('10x = 80')} &implies; ${f('x = 8')}</p>` +
    `<p>Check the solution: ${f('\\sqrt{8^2} = 8')} and ${f('80 - 9(8) = 80 - 72 = 8')}. The solution is valid, so ${f('x = 8')}.</p>`,

  // Q7
  '6a695064c3d08d90637d3cf5':
    `<p>The volume of a right pyramid is given by ${f('V = \\frac{1}{3} B h')}, where ${f('B')} is the area of the base and ${f('h')} is the height.</p>` +
    `<p>For a square base with side length ${f('s')}, ${f('B = s^2')}:</p>` +
    `<p>${f('128 = \\frac{1}{3} s^2 (6)')}</p>` +
    `<p>${f('128 = 2s^2')} &implies; ${f('s^2 = 64')} &implies; ${f('s = 8')}</p>` +
    `<p>Thus, the side length of the base of the pyramid is <strong>8</strong> units.</p>`,

  // Q8
  '6a6950e3c3d08d90637d3cf9':
    `<p>The area of a rectangle is ${f('\\text{Area} = \\text{length} \\times \\text{width}')}:</p>` +
    `<p>${f('66 = 11 \\times \\text{width}')}</p>` +
    `<p>${f('\\text{width} = \\frac{66}{11} = 6\\text{ meters}')}</p>`,

  // Q9
  '6a6951ebc3d08d90637d3d27':
    `<p>To express ${f('a')} in terms of ${f('b')} and ${f('c')}, isolate ${f('a')} in the given equation:</p>` +
    `<p>${f('\\frac{a}{b + c} = 64')}</p>` +
    `<p>Multiply both sides by ${f('(b + c)')}:</p>` +
    `<p>${f('a = 64(b + c)')}</p>`,

  // Q10
  '6a69525ac3d08d90637d3d2b':
    `<p>The slope of a line passing through points ${f('(x_1, y_1)')} and ${f('(x_2, y_2)')} is:</p>` +
    `<p>${f('m = \\frac{y_2 - y_1}{x_2 - x_1}')}</p>` +
    `<p>Using the given points ${f('(0, 6)')} and ${f('(7, 7)')}:</p>` +
    `<p>${f('m = \\frac{7 - 6}{7 - 0} = \\frac{1}{7}')}</p>`,

  // Q11
  '6a695289c3d08d90637d3d31':
    `<p>We are given the system of equations:</p>` +
    `<p>1) ${f('x + 3y = 29')}</p>` +
    `<p>2) ${f('7x - 12y = -61')}</p>` +
    `<p>From equation 1, express ${f('x')} in terms of ${f('y')}:</p>` +
    `<p>${f('x = 29 - 3y')}</p>` +
    `<p>Substitute this into equation 2:</p>` +
    `<p>${f('7(29 - 3y) - 12y = -61')}</p>` +
    `<p>${f('203 - 21y - 12y = -61')}</p>` +
    `<p>${f('203 - 33y = -61')} &implies; ${f('-33y = -264')} &implies; ${f('y = 8')}</p>` +
    `<p>Thus, the value of ${f('y')} is <strong>8</strong>.</p>`,

  // Q12
  '6a6952e4c3d08d90637d3d35':
    `<p>If the graph of a polynomial function passes through ${f('(k, 0)')}, then ${f('x = k')} is an ${f('x')}-intercept (root), and ${f('(x - k)')} is a factor of ${f('f(x)')}.</p>` +
    `<p>The given ${f('x')}-intercepts are ${f('x = -4')}, ${f('x = 1')}, and ${f('x = 9')}.</p>` +
    `<p>The corresponding linear factors are ${f('(x + 4)')}, ${f('(x - 1)')}, and ${f('(x - 9)')}.</p>` +
    `<p>Among the given answer choices, <strong>${f('x - 1')}</strong> must be a factor of ${f('f(x)')}.</p>`,

  // Q13
  '6a695322c3d08d90637d3d39':
    `<p>In right triangle ${f('QRS')} with right angle at ${f('R')}:</p>` +
    `<p>For angle ${f('y^\\circ')} at vertex ${f('S')}:</p>` +
    `<p>${f('\\text{opposite leg} = QR = 4')}</p>` +
    `<p>${f('\\text{adjacent leg} = RS = 9')}</p>` +
    `<p>By definition of tangent:</p>` +
    `<p>${f('\\tan y^\\circ = \\frac{\\text{opposite}}{\\text{adjacent}} = \\frac{4}{9}')}</p>`,

  // Q14
  '6a69536fc3d08d90637d3d3d':
    `<p>We are given the system of equations:</p>` +
    `<p>1) ${f('8x + 32y = 30')}</p>` +
    `<p>2) ${f('12x + 48y = 45')}</p>` +
    `<p>Divide equation 1 by 8:</p>` +
    `<p>${f('x + 4y = \\frac{30}{8} = 3.75')}</p>` +
    `<p>Divide equation 2 by 12:</p>` +
    `<p>${f('x + 4y = \\frac{45}{12} = 3.75')}</p>` +
    `<p>Since both equations simplify to the exact same linear equation, they represent the same line and intersect at <strong>infinitely many</strong> points.</p>`,

  // Q15
  '6a695489c3d08d90637d3d41':
    `<p>Find the slope of the linear relationship using the points ${f('(2, 102)')} and ${f('(6, 294)')}:</p>` +
    `<p>${f('m = \\frac{294 - 102}{6 - 2} = \\frac{192}{4} = 48')}</p>` +
    `<p>Using point-slope form with ${f('(2, 102)')}:</p>` +
    `<p>${f('p - 102 = 48(c - 2)')}</p>` +
    `<p>${f('p - 102 = 48c - 96')}</p>` +
    `<p>Rearrange into standard form:</p>` +
    `<p>${f('48c - p = 102 - 96 = 6')} &nbsp;or&nbsp; ${f('48c - p = -6')} depending on signs.</p>` +
    `<p>Specifically, ${f('48c - p = -6')} matches the form: ${f('p = 48c + 6 \\implies 48c - p = -6')}.</p>`,

  // Q16
  '6a6954dcc3d08d90637d3d45':
    `<p>Substitute the point ${f('(8, c)')} into the circle equation ${f('(x - 4)^2 + (y - 9)^2 = 16')}:</p>` +
    `<p>${f('(8 - 4)^2 + (c - 9)^2 = 16')}</p>` +
    `<p>${f('(4)^2 + (c - 9)^2 = 16')}</p>` +
    `<p>${f('16 + (c - 9)^2 = 16')}</p>` +
    `<p>${f('(c - 9)^2 = 0 \\implies c - 9 = 0 \\implies c = 9')}</p>` +
    `<p>Thus, the value of ${f('c')} is <strong>9</strong>.</p>`,

  // Q17
  '6a695567c3d08d90637d3d51':
    `<p>The inequality is ${f('y > \\frac{9}{7}x + b')}, where ${f('b > 0')}.</p>` +
    `<p>Consider the region where ${f('x > 0')} and ${f('y < 0')} (Quadrant IV):</p>` +
    `<p>For any ${f('x > 0')}, because ${f('b > 0')}, the expression ${f('\\frac{9}{7}x + b > 0')}.</p>` +
    `<p>Since ${f('y > \\frac{9}{7}x + b')}, we must have ${f('y > 0')}.</p>` +
    `<p>Therefore, it is impossible for any solution point to have a negative ${f('y')}-coordinate when ${f('x > 0')}.</p>` +
    `<p>Thus, the region where <strong>${f('x > 0')} and ${f('y < 0')}</strong> contains no solutions.</p>`,

  // Q18
  '6a6955bcc3d08d90637d3d55':
    `<p>Expand the factored form ${f('(x + n)(x + 11)')}:</p>` +
    `<p>${f('(x + n)(x + 11) = x^2 + 11x + nx + 11n = x^2 + (n + 11)x + 11n')}</p>` +
    `<p>Equate coefficients with ${f('x^2 + kx + 55')}:</p>` +
    `<p>1) Constant term: ${f('11n = 55 \\implies n = 5')}</p>` +
    `<p>2) Coefficient of ${f('x')}: ${f('k = n + 11 = 5 + 11 = 16')}</p>` +
    `<p>Thus, the value of ${f('k')} is <strong>16</strong>.</p>`,

  // Q19
  '6a6955dfc3d08d90637d3d59':
    `<p>Using the conversion factor ${f('1\\text{ kilogram} = 1,000\\text{ grams}')}:</p>` +
    `<p>${f('\\text{Mass} = 24\\text{ kg} \\times 1,000\\text{ g/kg} = 24,000\\text{ grams}')}</p>`,

  // Q20
  '6a695610c3d08d90637d3d5d':
    `<p>The equation is ${f('-3x^2 - 5x + 6 = 0')}, or equivalently ${f('3x^2 + 5x - 6 = 0')}.</p>` +
    `<p>Using the quadratic formula ${f('x = \\frac{-b \\pm \\sqrt{b^2 - 4ac}}{2a}')} with ${f('a = 3, b = 5, c = -6')}:</p>` +
    `<p>${f('x = \\frac{-5 \\pm \\sqrt{5^2 - 4(3)(-6)}}{2(3)} = \\frac{-5 \\pm \\sqrt{25 + 72}}{6} = \\frac{-5 \\pm \\sqrt{97}}{6}')}</p>` +
    `<p>The greatest solution uses the plus sign:</p>` +
    `<p>${f('x = -\\frac{5}{6} + \\frac{\\sqrt{97}}{6}')}</p>`,

  // Q21
  '6a695641c3d08d90637d3d61':
    `<p>The initial temperature corresponds to time ${f('t = 0')} minutes when the beaker was placed on the table.</p>` +
    `<p>Substitute ${f('t = 0')} into ${f('g(t)')}:</p>` +
    `<p>${f('g(0) = 297 + (363 - 297)(2.72)^{-0.103(0)}')}</p>` +
    `<p>Since ${f('(2.72)^0 = 1')}:</p>` +
    `<p>${f('g(0) = 297 + (363 - 297)(1) = 363\\text{ kelvins}')}</p>`,

  // Q22
  '6a6956d2c3d08d90637d3d65':
    `<p>Given ${f('f(x) = a^x + b')}:</p>` +
    `<p>1. The ${f('y')}-intercept is at ${f('(0, -22)')}, so ${f('f(0) = -22')}:</p>` +
    `<p>${f('a^0 + b = -22 \\implies 1 + b = -22 \\implies b = -23')}</p>` +
    `<p>2. The graph passes through ${f('(2, 26)')}, so ${f('f(2) = 26')}:</p>` +
    `<p>${f('a^2 - 23 = 26 \\implies a^2 = 49')}</p>` +
    `<p>Since ${f('a > 0')}, ${f('a = 7')}.</p>` +
    `<p>Finally, calculate ${f('a + b')}:</p>` +
    `<p>${f('a + b = 7 + (-23) = -16')}</p>`
};

async function run() {
  console.log('🚀 Injecting 22 explanations for September 2025 · US 1 (M1)...\n');
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
  console.log(`\n🎉 Injected ${count}/${ids.length} explanations for Module 1!`);
}

run().catch(console.error);
