const https = require('https');

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

const explanations = {
  // Q1
  '6a6cb237c3d08d90637d4059':
    `<p>Find the slope ${f('m')} using the first two points from the table, ${f('(1, 24)')} and ${f('(2, 21)')}:</p>` +
    `<p>${f('m = \\frac{21 - 24}{2 - 1} = \\frac{-3}{1} = -3')}</p>` +
    `<p>Use the point-slope form with ${f('g(x) = mx + b')} and the point ${f('(1, 24)')}:</p>` +
    `<p>${f('24 = -3(1) + b \\implies 24 = -3 + b \\implies b = 27')}</p>`,

  // Q2
  '6a6cb273c3d08d90637d405d':
    `<p>The formula for the area of a triangle with base ${f('b')} and height ${f('h')} is ${f('\\text{Area} = \\frac{1}{2}bh')}.</p>` +
    `<p>Comparing the given function ${f('h(x) = \\frac{1}{2}(x)(87)')} with the area formula where the base is ${f('x')}, the fixed height of the triangle is 87 inches.</p>`,

  // Q3
  '6a6cb2a3c3d08d90637d4061':
    `<p>Each correct response in the first round is worth 3 points, so ${f('f')} correct responses earn ${f('3f')} points.</p>` +
    `<p>Each correct response in the second round is worth 9 points, so ${f('s')} correct responses earn ${f('9s')} points.</p>` +
    `<p>The contestant needs to score at least 70 total points, meaning the total score must be greater than or equal to 70:</p>` +
    `<p>${f('3f + 9s \\ge 70')}</p>`,

  // Q4
  '6a6cb325c3d08d90637d4065':
    `<p>An isosceles triangle is defined as a triangle with at least two sides of equal length.</p>` +
    `<p>We are given that ${f('AB = 48')}. If the length of ${f('\\overline{BC}')} is also 48, then ${f('AB = BC = 48')}, which proves that triangle ${f('ABC')} has two congruent sides and is therefore isosceles.</p>`,

  // Q5
  '6a6cb38fc3d08d90637d406b':
    `<p>Substitute ${f('x = 14')} into the given function:</p>` +
    `<p>${f('f(14) = 8(3)^{-\\frac{14}{7}} = 8(3)^{-2}')}</p>` +
    `<p>Using the negative exponent rule ${f('a^{-n} = \\frac{1}{a^n}')}:</p>` +
    `<p>${f('f(14) = 8 \\times \\frac{1}{3^2} = 8 \\times \\frac{1}{9} = \\frac{8}{9}')}</p>`,

  // Q6
  '6a6cb3d1c3d08d90637d406f':
    `<p>In 2010, there were ${f('a')} advanced skaters and ${f('b')} intermediate skaters, with a total of ${f('a + b = 51')}.</p>` +
    `<p>An increase of 59% in advanced skaters corresponds to a multiplier of ${f('1 + 0.59 = 1.59')}, giving ${f('1.59a')} skaters in 2020.</p>` +
    `<p>An increase of 48% in intermediate skaters corresponds to a multiplier of ${f('1 + 0.48 = 1.48')}, giving ${f('1.48b')} skaters in 2020.</p>` +
    `<p>An increase of 53% in the total team of 51 skaters gives ${f('51(1 + 0.53) = 51(1.53)')} skaters in 2020.</p>` +
    `<p>Setting the sum of the groups equal to the new total yields:</p>` +
    `<p>${f('1.59a + 1.48b = 51(1.53)')}</p>`,

  // Q7
  '6a6cb3fdc3d08d90637d4073':
    `<p>The plausible values for the population proportion fall within the confidence interval defined by the point estimate plus or minus the margin of error:</p>` +
    `<p>Lower bound: ${f('84\\% - 3.94\\% = 80.06\\%')}</p>` +
    `<p>Upper bound: ${f('84\\% + 3.94\\% = 87.94\\%')}</p>` +
    `<p>Thus, plausible values for the percent of all registered voters in the county in favor of the new law are any values greater than 80.06% and less than 87.94%.</p>`,

  // Q8
  '6a6cb426c3d08d90637d4079':
    `<p>Let ${f('b')} be the number of bowls and ${f('v')} be the number of vases.</p>` +
    `<p>The total number of pieces made is 10: ${f('b + v = 10 \\implies b = 10 - v')}.</p>` +
    `<p>The total weight of clay used is 36 pounds: ${f('4b + 2v = 36')}.</p>` +
    `<p>Substitute ${f('b = 10 - v')} into the clay equation:</p>` +
    `<p>${f('4(10 - v) + 2v = 36')}</p>` +
    `<p>${f('40 - 4v + 2v = 36')}</p>` +
    `<p>${f('40 - 2v = 36 \\implies 2v = 4 \\implies v = 2')}</p>` +
    `<p>The artist made 2 vases.</p>`,

  // Q9
  '6a6cb453c3d08d90637d407d':
    `<p>Factor the expression by grouping terms in pairs:</p>` +
    `<p>${f('x^3 + x^2y + xy^8 + y^9 = x^2(x + y) + y^8(x + y)')}</p>` +
    `<p>Factor out the common binomial factor ${f('(x + y)')}:</p>` +
    `<p>${f('(x^2 + y^8)(x + y)')}</p>` +
    `<p>Therefore, ${f('x^2 + y^8')} is a factor of the expression.</p>`,

  // Q10
  '6a6cb4a3c3d08d90637d4081':
    `<p>Angle ${f('T')} has a radian measure 3 times that of angle ${f('S')}:</p>` +
    `<p>${f('\\text{Measure of } T = 3 \\times \\frac{4\\pi}{11} = \\frac{4\\pi}{11}(3)\\text{ radians}')}</p>` +
    `<p>To convert radians to degrees, multiply by ${f('\\frac{180^\\circ}{\\pi}')}:</p>` +
    `<p>${f('\\text{Measure in degrees} = \\frac{4\\pi}{11}(3) \\times \\frac{180}{\\pi} = \\frac{4}{11}(180)(3)')}</p>`,

  // Q11
  '6a6cb51ac3d08d90637d4085':
    `<p>From the first statement, 15% of ${f('h')} equals 20% of ${f('j')}:</p>` +
    `<p>${f('0.15h = 0.20j \\implies h = \\frac{0.20}{0.15}j = \\frac{4}{3}j')}</p>` +
    `<p>From the second statement, ${f('j')} is 60% of ${f('k')}:</p>` +
    `<p>${f('j = 0.60k = \\frac{3}{5}k')}</p>` +
    `<p>Substitute ${f('j')} into the equation for ${f('h')}:</p>` +
    `<p>${f('h = \\frac{4}{3}\\left(\\frac{3}{5}k\\right) = \\frac{4}{5}k = 0.80k = 80\\% \\text{ of } k')}</p>` +
    `<p>Therefore, ${f('h')} is 80% of ${f('k')}.</p>`,

  // Q12
  '6a6cddb7348fc3871167003c':
    `<p>Solve the first equation for ${f('y')}: ${f('y = x + 47')}.</p>` +
    `<p>Equate the expressions for ${f('y')}:</p>` +
    `<p>${f('x^2 - 45x = x + 47')}</p>` +
    `<p>${f('x^2 - 46x - 47 = 0')}</p>` +
    `<p>Factor the quadratic equation:</p>` +
    `<p>${f('(x - 47)(x + 1) = 0')}</p>` +
    `<p>Thus, ${f('x = 47')} or ${f('x = -1')}.</p>` +
    `<p>If ${f('x = 47')}, then ${f('y = 47 + 47 = 94')}.</p>` +
    `<p>If ${f('x = -1')}, then ${f('y = -1 + 47 = 46')}.</p>` +
    `<p>A possible value of ${f('y')} among the given options is 94.</p>`,

  // Q13
  '6a6cde05348fc38711670042':
    `<p>The speed of the object is ${f('\\text{speed} = \\frac{\\text{distance}}{\\text{time}} = \\frac{x}{y}')} inches per second.</p>` +
    `<p>To travel a distance of ${f('12x')} inches at this constant speed, the time required is:</p>` +
    `<p>${f('\\text{time} = \\frac{\\text{distance}}{\\text{speed}} = \\frac{12x}{\\frac{x}{y}} = 12x \\times \\frac{y}{x} = 12y\\text{ seconds}')}</p>`,

  // Q14
  '6a6cde3c348fc38711670046':
    `<p>The initial amount of bacteria is 7,000.</p>` +
    `<p>An increase of 150% means the population multiplies by ${f('1 + 1.50 = 2.50')} every 2 hours.</p>` +
    `<p>Over ${f('t')} hours, the number of 2-hour intervals is ${f('\\frac{t}{2}')}.</p>` +
    `<p>Therefore, the exponential model is ${f('P(t) = 7,000(2.50)^{\\frac{t}{2}}')}.</p>`,

  // Q15
  '6a6cdeb9348fc3871167004a':
    `<p>Since line ${f('p')} passes through the ${f('x')}-intercept ${f('(r, 0)')}, substitute ${f('x = r')} and ${f('y = 0')} into the equation of line ${f('p')}:</p>` +
    `<p>${f('k(r) + 7(0) = 16')}</p>` +
    `<p>${f('kr = 16')}</p>` +
    `<p>Dividing both sides by ${f('r')} gives:</p>` +
    `<p>${f('k = \\frac{16}{r}')}</p>`,

  // Q16
  '6a6cdfd3348fc38711670050':
    `<p>Rearrange the given linear equation ${f('nx + 3t = -3x + 4n')} by grouping the ${f('x')} terms:</p>` +
    `<p>${f('(n + 3)x = 4n - 3t')}</p>` +
    `<p>A linear equation in one variable has no solution if and only if the coefficient of ${f('x')} is zero while the constant term is nonzero:</p>` +
    `<p>${f('n + 3 = 0 \\implies n = -3')}</p>` +
    `<p>${f('4n - 3t \\neq 0 \\implies 4(-3) - 3t \\neq 0 \\implies -12 - 3t \\neq 0 \\implies t \\neq -4')}</p>` +
    `<p>Therefore, the sum ${f('n + t')} cannot equal:</p>` +
    `<p>${f('n + t \\neq -3 + (-4) = -7')}</p>`,

  // Q17
  '6a6ce012348fc38711670054':
    `<p>For this linear relationship between ${f('t')} and ${f('d')}, all given candidate models have a positive slope of 2.02.</p>` +
    `<p>Examining the vertical intercept (the value of ${f('d')} when ${f('t = 0')}) indicates that the line passes through a ${f('d')}-intercept of approximately 406.8.</p>` +
    `<p>Thus, the most appropriate linear model is ${f('d = 406.8 + 2.02t')}.</p>`,

  // Q18
  '6a6ce158709cb26e3aea318c':
    `<p>The volume of a cylinder is ${f('V = \\pi r^2 h')}. For cylinder A with radius ${f('r = 2')}:</p>` +
    `<p>${f('32\\pi = \\pi (2^2) h_A = 4\\pi h_A \\implies h_A = 8')}</p>` +
    `<p>The surface area of cylinder A is:</p>` +
    `<p>${f('\\text{SA}_A = 2\\pi r^2 + 2\\pi rh = 2\\pi(4) + 2\\pi(2)(8) = 8\\pi + 32\\pi = 40\\pi')}</p>` +
    `<p>Since ${f('\\text{SA}_A = k\\pi')}, we find ${f('k = 40')}.</p>` +
    `<p>Because cylinders A and B are similar solids, the ratio of their volumes is the cube of their linear scale factor ${f('c')}:</p>` +
    `<p>${f('\\frac{V_B}{V_A} = \\frac{864\\pi}{32\\pi} = 27 = c^3 \\implies c = 3')}</p>` +
    `<p>The ratio of their surface areas is the square of the linear scale factor, ${f('c^2 = 3^2 = 9')}:</p>` +
    `<p>${f('\\text{SA}_B = 9 \\times \\text{SA}_A = 9(40\\pi) = 360\\pi')}</p>` +
    `<p>Since ${f('\\text{SA}_B = n\\pi')}, we find ${f('n = 360')}.</p>` +
    `<p>Therefore, ${f('n - k = 360 - 40 = 320')}.</p>`,

  // Q19
  '6a6ce201709cb26e3aea31d0':
    `<p>Let ${f('h(t)')} be the quadratic function modeling the height. Since the object reaches a maximum height of 1,600 feet at ${f('t = 10')} seconds, the vertex form is:</p>` +
    `<p>${f('h(t) = a(t - 10)^2 + 1,600')}</p>` +
    `<p>Because the object was launched from ground level (${f('h(0) = 0')}):</p>` +
    `<p>${f('0 = a(0 - 10)^2 + 1,600 \\implies 100a + 1,600 = 0 \\implies a = -16')}</p>` +
    `<p>Thus, ${f('h(t) = -16(t - 10)^2 + 1,600')}.</p>` +
    `<p>At ${f('t = 13')} seconds:</p>` +
    `<p>${f('h(13) = -16(13 - 10)^2 + 1,600 = -16(9) + 1,600 = -144 + 1,600 = 1,456\\text{ feet}')}</p>`,

  // Q20
  '6a6ce2da709cb26e3aea3224':
    `<p>The points on the graph of ${f('y = f(x) + 6')} are ${f('(16, -7)')}, ${f('(19, 11)')}, and ${f('(22, -7)')}.</p>` +
    `<p>Because the ${f('y')}-values are equal at ${f('x = 16')} and ${f('x = 22')}, the axis of symmetry is ${f('x = \\frac{16 + 22}{2} = 19')}, and the vertex is at ${f('(19, 11)')}.</p>` +
    `<p>In vertex form: ${f('y = a(x - 19)^2 + 11')}. Using the point ${f('(16, -7)')}:</p>` +
    `<p>${f('-7 = a(16 - 19)^2 + 11 \\implies -7 = 9a + 11 \\implies 9a = -18 \\implies a = -2')}</p>` +
    `<p>Since ${f('y = f(x) + 6')}, we have:</p>` +
    `<p>${f('f(x) = y - 6 = -2(x - 19)^2 + 11 - 6 = -2(x - 19)^2 + 5')}</p>` +
    `<p>The ${f('y')}-intercept occurs at ${f('x = 0')}:</p>` +
    `<p>${f('f(0) = -2(0 - 19)^2 + 5 = -2(361) + 5 = -722 + 5 = -717')}</p>`,

  // Q21
  '6a6ce31c709cb26e3aea3228':
    `<p>The initial amount in the savings account was $900.</p>` +
    `<p>Javier deposits $55 at the end of each week. By the end of the 6th week, he has made 6 weekly deposits:</p>` +
    `<p>${f('\\text{Total} = 900 + 6(55) = 900 + 330 = 1,230\\text{ dollars}')}</p>`,

  // Q22
  '6a6ce3e4709cb26e3aea322c':
    `<p>Parallel lines ${f('q')} and ${f('r')} are intersected by transversal line ${f('s')}.</p>` +
    `<p>The marked angle of ${f('51^\\circ')} and angle ${f('y^\\circ')} are supplementary consecutive angles, so:</p>` +
    `<p>${f('y = 180 - 51 = 129')}</p>` +
    `<p>Using the given relationship ${f('y = 2x - 7')}:</p>` +
    `<p>${f('129 = 2x - 7')}</p>` +
    `<p>${f('2x = 136 \\implies x = 68')}</p>`
};

async function run() {
  console.log('Injecting explanations for August 2025 · INT 2 (M1)...');

  const ids = Object.keys(explanations);
  let count = 0;
  for (const id of ids) {
    const res = await updateQuestion(id, { explanation: explanations[id] });
    count++;
    console.log(`[${count}/${ids.length}] Updated explanation for ${id}: ${res.message === 'success' ? '✅' : JSON.stringify(res)}`);
  }

  console.log('\n🎉 Finished updating all 22 explanations for August 2025 · INT 2 (M1)!');
}

run().catch(console.error);
