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
  '6a6a6c54c3d08d90637d3e1e':
    `<p>Factor out the greatest common monomial factor, ${f('v^3')}, from both terms:</p>` +
    `<p>${f('v^4 - 590v^3 = v^3(v - 590)')}</p>`,

  // Q2
  '6a6b67aec3d08d90637d3e40':
    `<p>Lines ${f('r')} and ${f('s')} are parallel, cut by transversal line ${f('t')}.</p>` +
    `<p>The angle measuring ${f('107^\\circ')} and angle ${f('x^\\circ')} are corresponding angles lying in the same relative position at each intersection.</p>` +
    `<p>Because parallel lines cut by a transversal have equal corresponding angles, ${f('x = 107')}.</p>`,

  // Q3
  '6a6b67f0c3d08d90637d3e52':
    `<p>The width of the rectangle is ${f('w = 9\\text{ cm}')}.</p>` +
    `<p>The length is 50 cm longer than the width:</p>` +
    `<p>${f('l = 9 + 50 = 59\\text{ cm}')}</p>` +
    `<p>The area of the rectangle is:</p>` +
    `<p>${f('\\text{Area} = l \\times w = 59 \\times 9 = 531\\text{ cm}^2')}</p>`,

  // Q4
  '6a6b68cac3d08d90637d3e58':
    `<p>The slope of a line of best fit represents the average rate of change of the dependent variable (${f('y')}, temperature in °F) per unit change of the independent variable (${f('x')}, time in hours).</p>` +
    `<p>Looking at the line of best fit, at ${f('x = 0')} hours the temperature is approximately ${f('170^\\circ\\text{F}')}, and at ${f('x = 10')} hours it is approximately ${f('570^\\circ\\text{F}')}:</p>` +
    `<p>${f('\\text{slope} \\approx \\frac{570 - 170}{10 - 0} = \\frac{400}{10} = 40^\\circ\\text{F per hour}')}</p>` +
    `<p>Because the slope is positive, the predicted temperature increases at a constant rate of approximately 40°F per hour over the 10-hour period.</p>`,

  // Q5
  '6a6b690ec3d08d90637d3e5e':
    `<p>The initial deposit is the account balance at the moment the account was opened, which corresponds to ${f('x = 0')} months since the initial deposit (the ${f('y')}-intercept of the graph).</p>` +
    `<p>Looking at the vertical axis at ${f('x = 0')}, the line crosses the axis at ${f('(0, 30)')}.</p>` +
    `<p>Thus, the amount of the initial deposit estimated by the graph is <strong>30</strong> (or <strong>40</strong>).</p>`,

  // Q6
  '6a6b696bc3d08d90637d3e64':
    `<p>Set the two expressions for ${f('y')} equal to each other:</p>` +
    `<p>${f('-10x + 13 = -12x + 15')}</p>` +
    `<p>Add ${f('12x')} to both sides:</p>` +
    `<p>${f('2x + 13 = 15')} &implies; ${f('2x = 2')} &implies; ${f('x = 1')}</p>` +
    `<p>Substitute ${f('x = 1')} into either equation to find ${f('y')}:</p>` +
    `<p>${f('y = -10(1) + 13 = 3')}</p>` +
    `<p>Therefore, the solution to the system is <strong>(1, 3)</strong>.</p>`,

  // Q7
  '6a6b69b2c3d08d90637d3e68':
    `<p>Before the acorn fell from the tree, the time elapsed was ${f('x = 0')} seconds.</p>` +
    `<p>Substitute ${f('x = 0')} into the height function ${f('f(x)')}:</p>` +
    `<p>${f('f(0) = -16(0)^2 + 76 = 76\\text{ feet}')}</p>`,

  // Q8
  '6a6b69d7c3d08d90637d3e6c':
    `<p>Calculate the total weight the bear needs to lose:</p>` +
    `<p>${f('\\Delta W = 515 - 490 = 25\\text{ pounds}')}</p>` +
    `<p>Since the bear loses 0.5 pound per day, divide the total weight loss by the daily rate:</p>` +
    `<p>${f('\\text{Days} = \\frac{25}{0.5} = 50\\text{ days}')}</p>`,

  // Q9
  '6a6b6a04c3d08d90637d3e72':
    `<p>We are given that ${f('x + 1 = 3')}.</p>` +
    `<p>Multiply both sides of the equation by 2:</p>` +
    `<p>${f('2(x + 1) = 2(3) = 6')}</p>`,

  // Q10
  '6a6b6a42c3d08d90637d3e76':
    `<p>The value of ${f('f(5)')} corresponds to the ${f('y')}-coordinate of the point on the graph where ${f('x = 5')}.</p>` +
    `<p>Observing the graph, the curve passes through the ${f('x')}-axis at ${f('(5, 0)')}.</p>` +
    `<p>Therefore, ${f('f(5) = 0')}.</p>`,

  // Q11
  '6a6b6a93c3d08d90637d3e7a':
    `<p>The maximum weight the freight elevator can carry is 5,450 pounds.</p>` +
    `<p>The person weighs 190 pounds, so the remaining capacity for the boxes is:</p>` +
    `<p>${f('5,450 - 190 = 5,260\\text{ pounds}')}</p>` +
    `<p>The total weight of ${f('x')} 23-pound boxes and ${f('y')} 60-pound boxes is ${f('23x + 60y')}.</p>` +
    `<p>Since this combined weight cannot exceed 5,260 pounds:</p>` +
    `<p>${f('23x + 60y \\le 5,260')}</p>`,

  // Q12
  '6a6b6ad8c3d08d90637d3e7e':
    `<p>In right triangle ${f('JKL')} with right angle at ${f('K')}:</p>` +
    `<p>By definition of cosine for angle ${f('y^\\circ')} at vertex ${f('L')}:</p>` +
    `<p>${f('\\cos y^\\circ = \\frac{\\text{adjacent}}{\\text{hypotenuse}} = \\frac{KL}{JL}')}</p>` +
    `<p>We are given ${f('JL = 59')} and ${f('\\cos y^\\circ = \\frac{58}{59}')}:</p>` +
    `<p>${f('\\frac{KL}{59} = \\frac{58}{59} \\implies KL = 58')}</p>`,

  // Q13
  '6a6b728ac3d08d90637d3e84':
    `<p>Given the equation:</p>` +
    `<p>${f('b - \\frac{19}{y} = x')}</p>` +
    `<p>To express the left-hand side as a single rational expression, find a common denominator of ${f('y')}:</p>` +
    `<p>${f('b = \\frac{by}{y}')}</p>` +
    `<p>Subtract the fractions:</p>` +
    `<p>${f('x = \\frac{by}{y} - \\frac{19}{y} = \\frac{by - 19}{y}')}</p>`,

  // Q14
  '6a6b735ec3d08d90637d3e8a':
    `<p>The line passes through ${f('(0, 0)')}, so the ${f('y')}-intercept is ${f('b = 0')}.</p>` +
    `<p>Calculate the slope using points ${f('(0, 0)')} and ${f('(1, 10)')}:</p>` +
    `<p>${f('m = \\frac{10 - 0}{1 - 0} = 10')}</p>` +
    `<p>Therefore, the equation defining ${f('h(x)')} is:</p>` +
    `<p>${f('h(x) = 10x')}</p>`,

  // Q15
  '6a6b738ec3d08d90637d3e8e':
    `<p>Write each equation in slope-intercept form ${f('y = mx + b')}:</p>` +
    `<p>1) ${f('3x + y = 21 \\implies y = -3x + 21')} (slope ${f('m_1 = -3')})</p>` +
    `<p>2) ${f('9x - y = 3 \\implies y = 9x - 3')} (slope ${f('m_2 = 9')})</p>` +
    `<p>Because the two lines have different slopes (${f('-3 \\ne 9')}), they intersect at <strong>exactly one</strong> point.</p>`,

  // Q16
  '6a6b73ccc3d08d90637d3e92':
    `<p>The width of the rectangle is ${f('w')}.</p>` +
    `<p>The length is 35 cm greater than the width, so ${f('l = w + 35')}.</p>` +
    `<p>The area ${f('A')} of a rectangle is the product of its length and width:</p>` +
    `<p>${f('A = (w)(w + 35)')}</p>`,

  // Q17
  '6a6b7447c3d08d90637d3e96':
    `<p>Angle ${f('K')} measures ${f('\\frac{\\pi}{2(12)} = \\frac{\\pi}{24}')} radians.</p>` +
    `<p>The measure of angle ${f('L')} is 12 times the measure of angle ${f('K')}:</p>` +
    `<p>${f('\\text{Angle } L = 12 \\times \\frac{\\pi}{24} = \\frac{\\pi}{2}\\text{ radians}')}</p>` +
    `<p>Convert ${f('\\frac{\\pi}{2}')} radians to degrees:</p>` +
    `<p>${f('\\frac{\\pi}{2} \\times \\frac{180^\\circ}{\\pi} = 90^\\circ')}</p>`,

  // Q18
  '6a6b7482c3d08d90637d3e9a':
    `<p>A fraction equals zero when its numerator is zero and its denominator is nonzero:</p>` +
    `<p>${f('(x - 7)(x - 8) = 0')} with ${f('x - 3 \\ne 0')}</p>` +
    `<p>This yields solutions ${f('x = 7')} and ${f('x = 8')}, both of which are valid since neither equals 3.</p>` +
    `<p>The sum of the solutions is:</p>` +
    `<p>${f('7 + 8 = 15')}</p>`,

  // Q19
  '6a6b7506c3d08d90637d3ea0':
    `<p>The ${f('y')}-intercept occurs where ${f('x = 0')}.</p>` +
    `<p>Substitute ${f('x = 0')} into the equation:</p>` +
    `<p>${f('y = 6^0 + 12 = 1 + 12 = 13')}</p>` +
    `<p>Thus, the ${f('y')}-intercept is <strong>(0, 13)</strong>.</p>`,

  // Q20
  '6a6b759cc3d08d90637d3ea4':
    `<p>Rewrite the linear equation in standard form by combining the ${f('x')} terms:</p>` +
    `<p>${f('-6x + 42px = 84')}</p>` +
    `<p>${f('(-6 + 42p)x = 84')}</p>` +
    `<p>A linear equation of the form ${f('Ax = B')} has no solution if and only if ${f('A = 0')} and ${f('B \\ne 0')}.</p>` +
    `<p>Set the coefficient of ${f('x')} to 0:</p>` +
    `<p>${f('-6 + 42p = 0 \\implies 42p = 6 \\implies p = \\frac{6}{42} = \\frac{1}{7}')}</p>`,

  // Q21
  '6a6b75c5c3d08d90637d3ea8':
    `<p>The sphere has a diameter of 31.000 cm, so its radius is ${f('r = \\frac{31}{2} = 15.5\\text{ cm}')}.</p>` +
    `<p>The volume of a sphere is given by ${f('V = \\frac{4}{3}\\pi r^3')}:</p>` +
    `<p>${f('V = \\frac{4}{3}(3.14159)(15.5)^3 = \\frac{4}{3}(3.14159)(3,723.875) \\approx 15,598.41\\text{ cm}^3')}</p>` +
    `<p>Now calculate the mass using ${f('\\text{Mass} = \\text{density} \\times \\text{volume}')}:</p>` +
    `<p>${f('\\text{Mass} = 2.6000 \\times 15,598.41 \\approx 40,555.87\\text{ grams}')}</p>` +
    `<p>Rounded to the nearest whole number, the mass is <strong>40556</strong>.</p>`,

  // Q22
  '6a6b7622c3d08d90637d3eac':
    `<p>Set ${f('w(r) = 0')}:</p>` +
    `<p>${f('\\frac{1}{r - 8} - \\frac{r - 5}{r + 4.25} = 0 \\implies \\frac{1}{r - 8} = \\frac{r - 5}{r + 4.25}')}</p>` +
    `<p>Cross-multiply:</p>` +
    `<p>${f('r + 4.25 = (r - 8)(r - 5)')}</p>` +
    `<p>${f('r + 4.25 = r^2 - 13r + 40')}</p>` +
    `<p>Rearrange into a quadratic equation:</p>` +
    `<p>${f('r^2 - 14r + 35.75 = 0')}</p>` +
    `<p>Apply the quadratic formula:</p>` +
    `<p>${f('r = \\frac{14 \\pm \\sqrt{(-14)^2 - 4(1)(35.75)}}{2} = \\frac{14 \\pm \\sqrt{196 - 143}}{2} = \\frac{14 \\pm \\sqrt{53}}{2}')}</p>` +
    `<p>Since ${f('\\sqrt{53} \\approx 7.2801')}, the greatest solution is:</p>` +
    `<p>${f('r = \\frac{14 + 7.2801}{2} = \\frac{21.2801}{2} = 10.64')}</p>`
};

async function run() {
  console.log('🚀 Injecting 22 explanations for September 2025 · US 2 (M1)...\n');
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
