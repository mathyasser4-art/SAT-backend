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
  '6a6659d1c3d08d90637d3a06':
    `<p>To find a possible value of ${f('x')}, we model the height of the object using a quadratic function in vertex form:</p>` +
    `<p>${f('h(t) = a(t - h_v)^2 + k_v')}</p>` +
    `<p>Given that the maximum height is ${f('207.36')} feet at ${f('t = 3.6')} seconds, the vertex is ${f('(3.6, 207.36)')}:</p>` +
    `<p>${f('h(t) = a(t - 3.6)^2 + 207.36')}</p>` +
    `<p>The object was launched from an initial height of ${f('0.00')} feet at ${f('t = 0')}:</p>` +
    `<p>${f('0 = a(0 - 3.6)^2 + 207.36')} &implies; ${f('12.96a = -207.36')} &implies; ${f('a = -16')}</p>` +
    `<p>Now, set ${f('h(x) = 184.32')}:</p>` +
    `<p>${f('-16(x - 3.6)^2 + 207.36 = 184.32')}</p>` +
    `<p>${f('-16(x - 3.6)^2 = -23.04')}</p>` +
    `<p>${f('(x - 3.6)^2 = 1.44')}</p>` +
    `<p>${f('x - 3.6 = \\pm 1.2')}</p>` +
    `<p>Solving for ${f('x')}:</p>` +
    `<p>${f('x = 3.6 - 1.2 = 2.4')} &nbsp;or&nbsp; ${f('x = 3.6 + 1.2 = 4.8')}</p>` +
    `<p>Therefore, a possible value of ${f('x')} is <strong>2.4</strong> (or <strong>12/5</strong>).</p>`,

  // Q2
  '6a665a6fc3d08d90637d3a0e':
    `<p>Substitute ${f('x = 10')} into the function ${f('h(x)')}:</p>` +
    `<p>${f('h(10) = 5(9(10) - 10)')}</p>` +
    `<p>${f('h(10) = 5(90 - 10) = 5(80) = 400')}</p>` +
    `<p>Thus, the value of ${f('h(10)')} is <strong>400</strong>.</p>`,

  // Q3
  '6a665ab0c3d08d90637d3a12':
    `<p>The service cares for ${f('c')} cats and ${f('d')} dogs. The total number of animals is ${f('c + d')}.</p>` +
    `<p>The phrase "at most 43 animals" means that the total number cannot exceed 43, represented by the inequality:</p>` +
    `<p>${f('c + d \\le 43')}</p>`,

  // Q4
  '6a665af1c3d08d90637d3a1e':
    `<p>The given equation is:</p>` +
    `<p>${f('9x + 17 = 9x + k')}</p>` +
    `<p>Subtracting ${f('9x')} from both sides gives:</p>` +
    `<p>${f('17 = k')}</p>` +
    `<p>For a linear equation in one variable to have infinitely many solutions, the variable coefficients and constants on both sides must be equal. Therefore, ${f('k = 17')}.</p>`,

  // Q5
  '6a665b5ac3d08d90637d3a22':
    `<p>The ${f('y')}-intercept of any function occurs where ${f('x = 0')}.</p>` +
    `<p>Substitute ${f('x = 0')} into the equation:</p>` +
    `<p>${f('y = 6(1.85)^0')}</p>` +
    `<p>Since ${f('(1.85)^0 = 1')}:</p>` +
    `<p>${f('y = 6(1) = 6')}</p>` +
    `<p>Thus, the value of ${f('y')} is <strong>6</strong>.</p>`,

  // Q6
  '6a665b96c3d08d90637d3a26':
    `<p>To find the slope of the line, select two points identified on the graph, such as ${f('(0, -7)')} and ${f('(6, -6)')}:</p>` +
    `<p>${f('\\text{slope } m = \\frac{y_2 - y_1}{x_2 - x_1} = \\frac{-6 - (-7)}{6 - 0} = \\frac{1}{6}')}</p>` +
    `<p>We can also verify with ${f('(-6, -8)')}:</p>` +
    `<p>${f('m = \\frac{-7 - (-8)}{0 - (-6)} = \\frac{1}{6}')}</p>` +
    `<p>Thus, the slope of the graph of ${f('f')} is ${f('\\frac{1}{6}')}.</p>`,

  // Q7
  '6a665bc9c3d08d90637d3a2c':
    `<p>The speed is given as ${f('17.700')} miles per hour. We are given the conversion ${f('1\\text{ mile} = 1,760\\text{ yards}')}.</p>` +
    `<p>Multiply miles per hour by the conversion factor to find yards per hour:</p>` +
    `<p>${f('\\text{Speed} = 17.700 \\times 1,760 = 31,152\\text{ yards per hour}')}</p>` +
    `<p>Thus, the participant's average speed was <strong>31152</strong> yards per hour.</p>`,

  // Q8
  '6a665c46c3d08d90637d3a30':
    `<p>Since triangle ${f('ABC')} is similar to triangle ${f('DEF')}, corresponding angles are equal, so ${f('\\angle A = \\angle D')}. Therefore, ${f('\\sin D = \\sin A')}.</p>` +
    `<p>We are given that angle ${f('C')} is a right angle and ${f('\\tan A = \\frac{612}{35}')}.</p>` +
    `<p>In right triangle ${f('ABC')}:</p>` +
    `<p>${f('\\text{opposite} = 612')}, &nbsp; ${f('\\text{adjacent} = 35')}</p>` +
    `<p>Using the Pythagorean theorem to find the hypotenuse:</p>` +
    `<p>${f('\\text{hypotenuse} = \\sqrt{612^2 + 35^2} = \\sqrt{374,544 + 1,225} = \\sqrt{375,769} = 613')}</p>` +
    `<p>Now calculate ${f('\\sin A')}:</p>` +
    `<p>${f('\\sin A = \\frac{\\text{opposite}}{\\text{hypotenuse}} = \\frac{612}{613}')}</p>` +
    `<p>Since ${f('\\sin D = \\sin A')}, the value of ${f('\\sin D')} is ${f('\\frac{612}{613}')}.</p>`,

  // Q9
  '6a665caac3d08d90637d3a34':
    `<p>In the function ${f('A(b) = 7b^2')}, the input variable ${f('b')} represents the length of the base of the right triangle in centimeters, and the output ${f('A(b)')} represents the area of the triangle in square centimeters.</p>` +
    `<p>Therefore, the statement ${f('A(18) = 2,268')} means that when the length of the base is 18 cm, the area of the triangle is 2,268 ${f('\\text{cm}^2')}.</p>`,

  // Q10
  '6a665cd8c3d08d90637d3a38':
    `<p>Set each factor equal to zero using the zero product property:</p>` +
    `<p>${f('v - 9 = 0 \\implies v = 9')}</p>` +
    `<p>${f('v - 2 = 0 \\implies v = 2')}</p>` +
    `<p>${f('v + 7 = 0 \\implies v = -7')}</p>` +
    `<p>Among the given answer choices, <strong>9</strong> is a solution to the equation.</p>`,

  // Q11
  '6a665d29c3d08d90637d3a3c':
    `<p>The area of a circle is given by ${f('\\text{Area} = \\pi r^2')}.</p>` +
    `<p>For circle ${f('K')} with radius ${f('r = 8\\text{ mm}')}:</p>` +
    `<p>${f('\\text{Area}_K = \\pi (8)^2 = 64\\pi\\text{ mm}^2')}</p>` +
    `<p>Circle ${f('L')} has an area of ${f('144\\pi\\text{ mm}^2')}.</p>` +
    `<p>The total area of circles ${f('K')} and ${f('L')} is:</p>` +
    `<p>${f('\\text{Total Area} = 64\\pi + 144\\pi = 208\\pi\\text{ mm}^2')}</p>`,

  // Q12
  '6a665d60c3d08d90637d3a42':
    `<p>For a quadratic equation in standard form ${f('ax^2 + bx + c = 0')}, the solutions are given by the quadratic formula:</p>` +
    `<p>${f('x = \\frac{-b \\pm \\sqrt{b^2 - 4ac}}{2a}')}</p>` +
    `<p>Here, ${f('a = 1')}, ${f('b = 49')}, and ${f('c = 1')}. Substituting these values into the formula gives:</p>` +
    `<p>${f('x = \\frac{-49 \\pm \\sqrt{(49)^2 - 4(1)(1)}}{2(1)}')}</p>` +
    `<p>Taking the plus sign yields the solution shown in the correct option.</p>`,

  // Q13
  '6a665da1c3d08d90637d3a46':
    `<p>An exponential decay model takes the form:</p>` +
    `<p>${f('I = I_0(1 - r)^{x / d}')}</p>` +
    `<p>Here, the initial number of photons is ${f('I_0 = 800')}, the rate of decrease is ${f('r = 50\\% = 0.50')} (so the remaining factor is ${f('1 - 0.50 = 0.5')}), and this reduction occurs every ${f('d = 7\\text{ mm}')}.</p>` +
    `<p>Substituting these parameters yields:</p>` +
    `<p>${f('I = 800(0.5)^{\\frac{x}{7}}')}</p>`,

  // Q14
  '6a665de2c3d08d90637d3a4a':
    `<p>First, find the slope of line ${f('k')} using points ${f('(3, 0)')} and ${f('(0, 5)')}:</p>` +
    `<p>${f('m = \\frac{5 - 0}{0 - 3} = -\\frac{5}{3}')}</p>` +
    `<p>Since the ${f('y')}-intercept is ${f('(0, 5)')}, the slope-intercept form is:</p>` +
    `<p>${f('y = -\\frac{5}{3}x + 5')}</p>` +
    `<p>Multiply both sides by 3 to clear the denominator:</p>` +
    `<p>${f('3y = -5x + 15')}</p>` +
    `<p>Add ${f('5x')} to both sides to write in standard form:</p>` +
    `<p>${f('5x + 3y = 15')}</p>`,

  // Q15
  '6a665e3dc3d08d90637d3a4e':
    `<p>In right triangle ${f('ABC')}, angle ${f('B')} is a right angle (${f('90^\\circ')}).</p>` +
    `<p>The sum of the acute angles in a right triangle is ${f('90^\\circ')}:</p>` +
    `<p>${f('\\angle A + \\angle C = 90^\\circ')}</p>` +
    `<p>Given ${f('\\angle A = 56^\\circ')}:</p>` +
    `<p>${f('\\angle C = 90^\\circ - 56^\\circ = 34^\\circ')}</p>`,

  // Q16
  '6a665e73c3d08d90637d3a52':
    `<p>We are given the system of linear equations:</p>` +
    `<p>1) ${f('x + 4y = -3')}</p>` +
    `<p>2) ${f('4x - y = 22')}</p>` +
    `<p>From equation 2, express ${f('y')} in terms of ${f('x')}:</p>` +
    `<p>${f('y = 4x - 22')}</p>` +
    `<p>Substitute this into equation 1:</p>` +
    `<p>${f('x + 4(4x - 22) = -3')}</p>` +
    `<p>${f('x + 16x - 88 = -3')} &implies; ${f('17x = 85')} &implies; ${f('x = 5')}</p>` +
    `<p>Now find ${f('y')}:</p>` +
    `<p>${f('y = 4(5) - 22 = 20 - 22 = -2')}</p>` +
    `<p>Finally, evaluate ${f('3x - 5y')}:</p>` +
    `<p>${f('3(5) - 5(-2) = 15 + 10 = 25')}</p>`,

  // Q17
  '6a665eb7c3d08d90637d3a5e':
    `<p>The standard equation of a circle is ${f('(x - h)^2 + (y - k)^2 = r^2')}, where ${f('(h, k)')} is the center and ${f('r')} is the radius.</p>` +
    `<p>With center ${f('(-4, 1)')}:</p>` +
    `<p>${f('(x - (-4))^2 + (y - 1)^2 = r^2')} &implies; ${f('(x + 4)^2 + (y - 1)^2 = r^2')}</p>` +
    `<p>Since ${f('(-8, 4)')} lies on the circle, compute ${f('r^2')} using the distance formula:</p>` +
    `<p>${f('r^2 = (-8 - (-4))^2 + (4 - 1)^2 = (-4)^2 + 3^2 = 16 + 9 = 25')}</p>` +
    `<p>Thus, the equation representing this circle is:</p>` +
    `<p>${f('(x + 4)^2 + (y - 1)^2 = 25')}</p>`,

  // Q18
  '6a665f19c3d08d90637d3a62':
    `<p>In the figure, parallel lines ${f('r')} and ${f('s')} are intersected by transversal line ${f('t')}.</p>` +
    `<p>Angles ${f('a^\\circ')} and ${f('b^\\circ')} are consecutive interior angles on the same side of transversal ${f('t')}, so they are supplementary:</p>` +
    `<p>${f('a + b = 180^\\circ')}</p>` +
    `<p>Substitute the given expressions for ${f('a')} and ${f('b')}:</p>` +
    `<p>${f('(4k + 57) + \\left(\\frac{k}{4} + 55\\right) = 180')}</p>` +
    `<p>${f('4.25k + 112 = 180')} &implies; ${f('4.25k = 68')} &implies; ${f('k = 16')}</p>` +
    `<p>Now find the measure of angle ${f('b')}:</p>` +
    `<p>${f('b = \\frac{16}{4} + 55 = 4 + 55 = 59^\\circ')}</p>` +
    `<p>Angles ${f('b^\\circ')} and ${f('c^\\circ')} lie along line ${f('s')} and form a linear pair, so they are supplementary:</p>` +
    `<p>${f('c = 180^\\circ - b = 180^\\circ - 59^\\circ = 121^\\circ')}</p>` +
    `<p>Thus, the value of ${f('c')} is <strong>121</strong>.</p>`,

  // Q19
  '6a665f50c3d08d90637d3a66':
    `<p>We are given the system of equations:</p>` +
    `<p>1) ${f('0.5x + 1.2y = 9')}</p>` +
    `<p>2) ${f('1.5x + 3.6y = 27')}</p>` +
    `<p>Multiply equation 1 by 3:</p>` +
    `<p>${f('3(0.5x + 1.2y) = 3(9)')} &implies; ${f('1.5x + 3.6y = 27')}</p>` +
    `<p>Notice that this is identical to equation 2. Since both equations represent the exact same line, every point on the line is a solution.</p>` +
    `<p>Therefore, the system has <strong>infinitely many</strong> solutions.</p>`,

  // Q20
  '6a6660c6c3d08d90637d3a6c':
    `<p>To find the overall mean height of all 570 king penguins, compute the total sum of heights divided by the total number of penguins:</p>` +
    `<p>${f('\\text{Total height} = (380 \\times 87) + (190 \\times 93)')}</p>` +
    `<p>${f('380 \\times 87 = 33,060')}</p>` +
    `<p>${f('190 \\times 93 = 17,670')}</p>` +
    `<p>${f('\\text{Total height} = 33,060 + 17,670 = 50,730\\text{ cm}')}</p>` +
    `<p>Divide by the total number of penguins (${f('570')}):</p>` +
    `<p>${f('\\text{Mean height} = \\frac{50,730}{570} = 89\\text{ cm}')}</p>`,

  // Q21
  '6a6660f6c3d08d90637d3a70':
    `<p>Examine the characteristics of the scatterplot:</p>` +
    `<p>1. <strong>Horizontal Asymptote:</strong> As ${f('x')} decreases into negative values, the points level off near ${f('y = 18')}. This indicates a vertical shift of ${f('+18')}.</p>` +
    `<p>2. <strong>${f('y')}-intercept:</strong> When ${f('x = 0')}, the data point is located at approximately ${f('y = 24')}.</p>` +
    `<p>Testing ${f('y = 6(1.55)^x + 18')} at ${f('x = 0')}:</p>` +
    `<p>${f('y = 6(1.55)^0 + 18 = 6(1) + 18 = 24')}</p>` +
    `<p>This matches the scatterplot data precisely. Therefore, ${f('y = 6(1.55)^x + 18')} is the most appropriate model.</p>`,

  // Q22
  '6a666167c3d08d90637d3a74':
    `<p>The given equation is:</p>` +
    `<p>${f('18qrt - 2qrs + 10rst = 0')}</p>` +
    `<p>Since ${f('r')} is positive (${f('r > 0')}), divide the entire equation by ${f('r')}:</p>` +
    `<p>${f('18qt - 2qs + 10st = 0')}</p>` +
    `<p>Isolate terms containing ${f('s')} on one side:</p>` +
    `<p>${f('18qt = 2qs - 10st')}</p>` +
    `<p>Divide both sides by 2:</p>` +
    `<p>${f('9qt = qs - 5st')}</p>` +
    `<p>Factor out ${f('s')}:</p>` +
    `<p>${f('9qt = s(q - 5t)')}</p>` +
    `<p>Divide by ${f('q - 5t')}:</p>` +
    `<p>${f('s = \\frac{9qt}{q - 5t}')}</p>`
};

async function run() {
  console.log('🚀 Injecting 22 explanations for October 2025 · US 1 (M1)...\n');
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
