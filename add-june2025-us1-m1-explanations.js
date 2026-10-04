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
  '6a6d683907c5da645a88cb08':
    `<p>Distribute ${f('6xy')} across the binomial inside parentheses:</p>` +
    `<p>${f('6xy(2x^2 + 5y) = (6xy)(2x^2) + (6xy)(5y)')}</p>` +
    `<p>${f('= 12x^3y + 30xy^2')}.</p>`,

  // Q2
  '6a6d687507c5da645a88cb34':
    `<p>Given expression: ${f('7x^6 - 2x^5 + 9x^4')}.</p>` +
    `<p>Identify the greatest common factor of the three terms, which is ${f('x^4')}:</p>` +
    `<p>${f('7x^6 = x^4(7x^2)')}</p>` +
    `<p>${f('-2x^5 = x^4(-2x)')}</p>` +
    `<p>${f('9x^4 = x^4(9)')}</p>` +
    `<p>Factoring out ${f('x^4')} gives:</p>` +
    `<p>${f('x^4(7x^2 - 2x + 9)')}.</p>`,

  // Q3
  '6a6dff8cf37fd34c9d2ad05d':
    `<p>Let ${f('x')} be the length of the vehicle in inches, and ${f('y')} be the height in inches.</p>` +
    `<ul>` +
    `<li>The height of the vehicle is 61 inches: ${f('y = 61')}</li>` +
    `<li>The length is 3 times the height: ${f('x = 3y')}</li>` +
    `</ul>` +
    `<p>Therefore, the system representing this situation is ${f('x = 3y, y = 61')}.</p>`,

  // Q4
  '6a6dfffaf37fd34c9d2ad061':
    `<p>A linear function in slope-intercept form is defined as ${f('f(x) = mx + b')}, where ${f('m')} is the slope and ${f('b')} is the y-intercept.</p>` +
    `<p>We are given that the slope is ${f('m = -54')} and the line passes through ${f('(0, 0)')}, so ${f('b = 0')}:</p>` +
    `<p>${f('f(x) = -54x + 0 = -54x')}.</p>`,

  // Q5
  '6a6e021bf37fd34c9d2ad067':
    `<p>The function is defined as ${f('g(x) = \\frac{5}{9}x - \\frac{7}{9}')}.</p>` +
    `<p>Substitute ${f('x = 18')}:</p>` +
    `<p>${f('g(18) = \\frac{5}{9}(18) - \\frac{7}{9} = 5(2) - \\frac{7}{9} = 10 - \\frac{7}{9}')}</p>` +
    `<p>Convert 10 to a fraction with a common denominator of 9:</p>` +
    `<p>${f('10 - \\frac{7}{9} = \\frac{90}{9} - \\frac{7}{9} = \\frac{83}{9}')}.</p>`,

  // Q6
  '6a6e0282f37fd34c9d2ad06d':
    `<p>The function is defined as ${f('f(x) = x^2 + x + 61')}.</p>` +
    `<p>Evaluate at ${f('x = 2')}:</p>` +
    `<p>${f('f(2) = 2^2 + 2 + 61 = 4 + 2 + 61 = 67')}.</p>`,

  // Q7
  '6a6e02c9f37fd34c9d2ad071':
    `<p>In the linear function ${f('f(x) = 5x + 7')}, ${f('x')} represents the number of years after the height was first measured.</p>` +
    `<p>When ${f('x = 0')} (at the initial measurement), ${f('f(0) = 5(0) + 7 = 7\\text{ feet}')}.</p>` +
    `<p>Therefore, 7 represents the estimated height of the tree when it was first measured.</p>`,

  // Q8
  '6a6e0321f37fd34c9d2ad077':
    `<p>Line ${f('k')} has a slope of ${f('m = 5')} and a y-intercept of ${f('(0, -35)')}, giving the equation:</p>` +
    `<p>${f('y = 5x - 35')}</p>` +
    `<p>The x-intercept occurs where ${f('y = 0')}:</p>` +
    `<p>${f('0 = 5x - 35 \\implies 5x = 35 \\implies x = 7')}.</p>`,

  // Q9
  '6a6e05fff37fd34c9d2ad07b':
    `<p>Given expression: ${f('\\frac{27(k + 6)}{3(k + 6)}')}.</p>` +
    `<p>Since ${f('k > -6')}, the term ${f('(k + 6) \\neq 0')}, so we can cancel it from the numerator and denominator:</p>` +
    `<p>${f('\\frac{27(k + 6)}{3(k + 6)} = \\frac{27}{3} = 9')}.</p>` +
    `<p>Thus, ${f('c = 9')}.</p>`,

  // Q10
  '6a6e0669f37fd34c9d2ad07f':
    `<p>For similar triangles, the ratio of any two corresponding side lengths is equal to the ratio of their perimeters:</p>` +
    `<p>${f('\\frac{XY}{TU} = \\frac{\\text{Perimeter of } XYZ}{\\text{Perimeter of } TUV}')}</p>` +
    `<p>Substitute the given values:</p>` +
    `<p>${f('\\frac{XY}{6} = \\frac{150}{50} = 3 \\implies XY = 6 \\times 3 = 18')}.</p>`,

  // Q11
  '6a6e06a2f37fd34c9d2ad085':
    `<p>The given equation is ${f('9(7 - 8x) + 2 = 8(7 - 8x) + 17')}.</p>` +
    `<p>Let ${f('u = 7 - 8x')}. The equation becomes:</p>` +
    `<p>${f('9u + 2 = 8u + 17')}</p>` +
    `<p>Subtract ${f('8u')} and 2 from both sides:</p>` +
    `<p>${f('u = 17 - 2 = 15')}.</p>` +
    `<p>Therefore, ${f('7 - 8x = 15')}.</p>`,

  // Q12
  '6a6e06e0f37fd34c9d2ad089':
    `<p>We are given the system:</p>` +
    `<p>${f('x + 33 = y')} and ${f('(x + 33)^2 = y')}</p>` +
    `<p>Substitute ${f('y = x + 33')} into the second equation:</p>` +
    `<p>${f('(x + 33)^2 = x + 33')}</p>` +
    `<p>Subtract ${f('(x + 33)')} from both sides:</p>` +
    `<p>${f('(x + 33)^2 - (x + 33) = 0 \\implies (x + 33)(x + 33 - 1) = 0 \\implies (x + 33)(x + 32) = 0')}</p>` +
    `<p>Thus, ${f('x = -33')} or ${f('x = -32')}.</p>` +
    `<p>Among the given answer choices, ${f('-32')} is a possible value of ${f('x')}.</p>`,

  // Q13
  '6a6e0799f37fd34c9d2ad08f':
    `<p>The standard equation of a circle in the xy-plane is ${f('(x - h)^2 + (y - k)^2 = r^2')}, where ${f('(h, k)')} is the center and ${f('r')} is the radius.</p>` +
    `<p>Comparing ${f('(x - 14)^2 + (y - k)^2 = 36')}:</p>` +
    `<ul>` +
    `<li>The center is at ${f('(14, k)')}.</li>` +
    `<li>The radius is ${f('r = \\sqrt{36} = 6')}.</li>` +
    `</ul>`,

  // Q14
  '6a6e07e8f37fd34c9d2ad093':
    `<p>The height function ${f('y = -16(x - 6.8)^2 + 740')} is a downward-opening parabola written in vertex form ${f('y = a(x - h)^2 + k')}.</p>` +
    `<p>The vertex occurs at ${f('(h, k) = (6.8, 740)')}.</p>` +
    `<p>Because the coefficient ${f('-16 < 0')}, this vertex represents the absolute maximum of the function.</p>` +
    `<p>Therefore, the firework reaches an estimated maximum height of 740 feet 6.8 seconds after it is launched into the air.</p>`,

  // Q15
  '6a6e0849f37fd34c9d2ad097':
    `<p>The values of ${f('x')} for which ${f('f(x) = 0')} correspond to the x-intercepts of the graph of ${f('y = f(x)')}.</p>` +
    `<p>Examining the graph:</p>` +
    `<ul>` +
    `<li>The graph crosses the x-axis at ${f('x = -3')}.</li>` +
    `<li>The graph touches the x-axis and turns around (tangent) at ${f('x = 1')}.</li>` +
    `</ul>` +
    `<p>These are the only points where the graph intersects the x-axis, so there are exactly Two distinct values of ${f('x')} where ${f('f(x) = 0')}.</p>`,

  // Q16
  '6a6e0945f37fd34c9d2ad0ae':
    `<p>The equation of circle ${f('M')} is ${f('(x - 3)^2 + (y - 6)^2 = 4')}.</p>` +
    `<p>Its center is ${f('(3, 6)')} and its radius is ${f('r_M = \\sqrt{4} = 2')}.</p>` +
    `<p>Circle ${f('P')} has the same center ${f('(3, 6)')} and twice the radius of ${f('M')}:</p>` +
    `<p>${f('r_P = 2 \\times 2 = 4')}</p>` +
    `<p>The equation of circle ${f('P')} is:</p>` +
    `<p>${f('(x - 3)^2 + (y - 6)^2 = 4^2 = 16')}.</p>`,

  // Q17
  '6a6e0982f37fd34c9d2ad0b2':
    `<p>In right triangle ${f('ABC')} with right angle at ${f('B')}, hypotenuse ${f('AC = 14')}, and acute angle ${f('C = 58^\\circ')}:</p>` +
    `<p>Side ${f('AB')} is opposite to angle ${f('C')}. By definition of the sine ratio:</p>` +
    `<p>${f('\\sin 58^\\circ = \\frac{\\text{Opposite}}{\\text{Hypotenuse}} = \\frac{AB}{14}')}</p>` +
    `<p>Multiplying both sides by 14 gives:</p>` +
    `<p>${f('AB = 14 \\sin 58^\\circ')}.</p>`,

  // Q18
  '6a6e09eff37fd34c9d2ad0b6':
    `<p>The number 15 less than ${f('x')} is ${f('x - 15')}.</p>` +
    `<p>Their product is 286:</p>` +
    `<p>${f('x(x - 15) = 286 \\implies x^2 - 15x - 286 = 0')}</p>` +
    `<p>Factor the quadratic equation:</p>` +
    `<p>${f('(x - 26)(x + 11) = 0')}</p>` +
    `<p>Since ${f('x')} is a positive number, ${f('x = 26')}.</p>`,

  // Q19
  '6a6e0a33f37fd34c9d2ad0ba':
    `<p>In ${f('\\triangle ACD')}, we are given that ${f('AC = CD')}, which means ${f('\\triangle ACD')} is an isosceles triangle with base ${f('AD')}.</p>` +
    `<p>The vertex angle is ${f('\\angle ACD = 108^\\circ')}. Therefore, the two base angles are equal:</p>` +
    `<p>${f('\\angle CAD = \\angle CDA = \\frac{180^\\circ - 108^\\circ}{2} = \\frac{72^\\circ}{2} = 36^\\circ')}</p>` +
    `<p>Now consider ${f('\\triangle BDE')}:</p>` +
    `<ul>` +
    `<li>${f('\\angle D = 36^\\circ')}</li>` +
    `<li>${f('\\angle B = \\angle EBC = 29^\\circ')}</li>` +
    `</ul>` +
    `<p>Angle ${f('\\angle BEA')} (${f('x^\\circ')}) is an exterior angle to ${f('\\triangle BDE')} at vertex ${f('E')}.</p>` +
    `<p>By the exterior angle theorem, the exterior angle equals the sum of the two remote interior angles:</p>` +
    `<p>${f('x = \\angle D + \\angle B = 36 + 29 = 65')}.</p>`,

  // Q20
  '6a6e0a86f37fd34c9d2ad0be':
    `<p>We are given that:</p>` +
    `<p>${f('a = 2800\\% \\text{ of } c = 28c')}</p>` +
    `<p>${f('c = 25\\% \\text{ of } b = 0.25b \\implies b = 4c')}</p>` +
    `<p>Now evaluate ${f('a - b')}:</p>` +
    `<p>${f('a - b = 28c - 4c = 24c')}</p>` +
    `<p>Since ${f('a - b = wc')}, we have ${f('w = 24')}.</p>`,

  // Q21
  '6a6e0dfdf37fd34c9d2ad0cc':
    `<p>First, find the slope of line ${f('j')}:</p>` +
    `<p>${f('4x + 5y = 55 \\implies 5y = -4x + 55 \\implies y = -\\frac{4}{5}x + 11')}</p>` +
    `<p>The slope of line ${f('j')} is ${f('-\\frac{4}{5}')}.</p>` +
    `<p>Line ${f('k')} is parallel to line ${f('j')}, so it has the same slope:</p>` +
    `<p>${f('24x + ry = 15 \\implies ry = -24x + 15 \\implies y = -\\frac{24}{r}x + \\frac{15}{r}')}</p>` +
    `<p>Set the slopes equal:</p>` +
    `<p>${f('-\\frac{24}{r} = -\\frac{4}{5} \\implies \\frac{24}{r} = \\frac{4}{5} \\implies 4r = 120 \\implies r = 30')}</p>` +
    `<p>Line ${f('k')} passes through ${f('(0, b)')}, which is its y-intercept:</p>` +
    `<p>${f('b = \\frac{15}{r} = \\frac{15}{30} = 0.5')} (or ${f('\\frac{1}{2}')}).</p>`,

  // Q22
  '6a6e0f02f37fd34c9d2ad0d4':
    `<p>First, analyze Set A from the dot plot:</p>` +
    `<ul>` +
    `<li>Values and counts: 2 (7 dots), 5 (6 dots), 8 (4 dots), 11 (6 dots), 14 (7 dots).</li>` +
    `<li>The distribution is symmetric about 8, so the mean of Set A is ${f('8\\ \\mu\\text{F}')}.</li>` +
    `<li>The range of Set A is ${f('14 - 2 = 12\\ \\mu\\text{F}')}.</li>` +
    `</ul>` +
    `<p>For Set B, each capacitor has a capacity ${f('17\\ \\mu\\text{F}')} greater than each corresponding capacitor in Set A:</p>` +
    `<ul>` +
    `<li>Adding a constant to every data value shifts the mean by that constant: ${f('\\text{Mean of B} = 8 + 17 = 25\\ \\mu\\text{F}')}.</li>` +
    `<li>Adding a constant to every data value does not change the range: ${f('\\text{Range of B} = 12\\ \\mu\\text{F}')}.</li>` +
    `</ul>` +
    `<p>Therefore, the mean capacity is ${f('25\\ \\mu\\text{F}')}, and the range of capacities is ${f('12\\ \\mu\\text{F}')}.</p>`
};

async function main() {
  console.log('Injecting June 2025 · US 1 M1 Explanations...');
  for (const [id, expl] of Object.entries(explanations)) {
    const res = await updateQuestion(id, { explanation: expl });
    console.log(`Updated ${id}:`, res.message || res);
  }
  console.log('Finished June 2025 · US 1 M1!');
}

main().catch(console.error);
