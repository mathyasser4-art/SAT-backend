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
  '6a6b782cc3d08d90637d3ecf':
    `<p>Substitute ${f('d = 36')} into the given equation:</p>` +
    `<p>${f('1.5c + 3(36) = 108')}</p>` +
    `<p>${f('1.5c + 108 = 108')}</p>` +
    `<p>Subtract 108 from both sides:</p>` +
    `<p>${f('1.5c = 0 \\implies c = 0')}</p>` +
    `<p>Therefore, the business can care for 0 cats during this week.</p>`,

  // Q2
  '6a6b788ec3d08d90637d3ed5':
    `<p>To find 80% of 500 feet of fencing, multiply the total length by 0.80:</p>` +
    `<p>${f('0.80 \\times 500 = 400\\text{ feet}')}</p>`,

  // Q3
  '6a6b78d6c3d08d90637d3edb':
    `<p>First, solve the first equation for ${f('x')}:</p>` +
    `<p>${f('x + 5 = 14 \\implies x = 9')}</p>` +
    `<p>Now substitute ${f('x = 9')} into the second equation to find ${f('y')}:</p>` +
    `<p>${f('y = 3(9)^2 + 3 = 3(81) + 3 = 243 + 3 = 246')}</p>` +
    `<p>Thus, the graphs intersect at the point ${f('(9, 246)')}.</p>`,

  // Q4
  '6a6b790dc3d08d90637d3edf':
    `<p>Expand the left side of the given equation ${f('(x + 2)^2 = 18')}:</p>` +
    `<p>${f('x^2 + 4x + 4 = 18')}</p>` +
    `<p>Subtract 4 from both sides to isolate ${f('x^2 + 4x')}:</p>` +
    `<p>${f('x^2 + 4x = 18 - 4 = 14')}</p>`,

  // Q5
  '6a6b7953c3d08d90637d3ee3':
    `<p>Combine like terms with respect to ${f('(t + 7)')}:</p>` +
    `<p>${f('6(t + 7) - 8(t + 7) = 38')}</p>` +
    `<p>${f('-2(t + 7) = 38')}</p>` +
    `<p>Divide both sides by ${f('-2')}:</p>` +
    `<p>${f('t + 7 = -19')}</p>` +
    `<p>Subtract 7 from both sides:</p>` +
    `<p>${f('t = -19 - 7 = -26')}</p>`,

  // Q6
  '6a6b79a1c3d08d90637d3ee9':
    `<p>Distribute ${f('(x^{-9}y^6z^5)')} across each term inside the parentheses:</p>` +
    `<p>${f('(x^{-9}y^6z^5)(x^4z^5 + y^8z^{-7}) = (x^{-9}y^6z^5)(x^4z^5) + (x^{-9}y^6z^5)(y^8z^{-7})')}</p>` +
    `<p>Apply the product rule of exponents (${f('a^m \\cdot a^n = a^{m+n}')}) to each variable:</p>` +
    `<p>For the first term: ${f('x^{-9+4}y^6z^{5+5} = x^{-5}y^6z^{10}')}</p>` +
    `<p>For the second term: ${f('x^{-9}y^{6+8}z^{5+(-7)} = x^{-9}y^{14}z^{-2}')}</p>` +
    `<p>Combining these gives:</p>` +
    `<p>${f('x^{-5}y^6z^{10} + x^{-9}y^{14}z^{-2}')}</p>`,

  // Q7
  '6a6b8f1fc3d08d90637d3ef5':
    `<p>The equation is ${f('10x + 26,255 = 26,956')}.</p>` +
    `<p>Here, 26,255 is the initial population in the year 2000, and 26,956 is the population 10 years later in 2010.</p>` +
    `<p>The quantity ${f('10x')} represents the total increase in population over the 10-year span. Therefore, dividing by 10 shows that ${f('x')} represents the average increase per year of the population between 2000 and 2010.</p>`,

  // Q8
  '6a6b8f61c3d08d90637d3ef9':
    `<p>For any two similar three-dimensional solids, the ratio of their volumes is the cube of the ratio of their linear dimensions (scale factor ${f('k')}):</p>` +
    `<p>${f('\\frac{\\text{Volume of cube A}}{\\text{Volume of cube B}} = k^3')}</p>` +
    `<p>Substitute the given volumes:</p>` +
    `<p>${f('\\frac{3,375}{125} = k^3')}</p>` +
    `<p>${f('27 = k^3 \\implies k = 3')}</p>`,

  // Q9
  '6a6b8f8ac3d08d90637d3eff':
    `<p>The volume of a pyramid is given by ${f('V = \\frac{1}{3}Bh')}, where ${f('B')} is the area of the base and ${f('h')} is the height.</p>` +
    `<p>Since the base is a square with side length ${f('s')}, ${f('B = s^2')}:</p>` +
    `<p>${f('128 = \\frac{1}{3}s^2(6)')}</p>` +
    `<p>${f('128 = 2s^2')}</p>` +
    `<p>${f('s^2 = 64 \\implies s = 8')}</p>`,

  // Q10
  '6a6b8fc9c3d08d90637d3f03':
    `<p>When a quantity decreases by 27% over a fixed interval, the remaining portion after each interval is:</p>` +
    `<p>${f('1 - 0.27 = 0.73')}</p>` +
    `<p>Since this decrease occurs every 14.07 minutes, the number of decay periods in ${f('t')} minutes is ${f('\\frac{t}{14.07}')}.</p>` +
    `<p>With an initial mass of 100 grams, the model is:</p>` +
    `<p>${f('M = 100(0.73)^{\\frac{t}{14.07}}')}</p>`,

  // Q11
  '6a6b9045c3d08d90637d3f07':
    `<p>This is a conditional probability problem: find ${f('P(\\text{Brown} \\mid \\text{Regular})')}.</p>` +
    `<p>From the table, the total number of regular length pants is 60.</p>` +
    `<p>Among these 60 regular pants, 15 are brown.</p>` +
    `<p>${f('P(\\text{Brown} \\mid \\text{Regular}) = \\frac{15}{60} = \\frac{1}{4} = 0.25')}</p>`,

  // Q12
  '6a6b909cc3d08d90637d3f0b':
    `<p>First, find the slope of the line passing through ${f('(0, -8)')} and ${f('(-2, 0)')}:</p>` +
    `<p>${f('m = \\frac{0 - (-8)}{-2 - 0} = \\frac{8}{-2} = -4')}</p>` +
    `<p>Using the ${f('y')}-intercept ${f('(0, -8)')}, the slope-intercept form is:</p>` +
    `<p>${f('y = -4x - 8 \\implies 4x + y = -8')}</p>` +
    `<p>We need the equation in the form ${f('Ax + By = 9')}. Multiply both sides by ${f('-\\frac{9}{8}')}:</p>` +
    `<p>${f('-\\frac{9}{8}(4x + y) = -\\frac{9}{8}(-8)')}</p>` +
    `<p>${f('-\\frac{9}{2}x - \\frac{9}{8}y = 9')}</p>` +
    `<p>Comparing coefficients with ${f('Ax + By = 9')} gives ${f('B = -\\frac{9}{8}')}.</p>`,

  // Q13
  '6a6b937dc3d08d90637d3f11':
    `<p>Subtract the second equation from the first equation:</p>` +
    `<p>${f('\\left[(x + k) + \\frac{9}{2}(y + t) + 19\\right] - \\left[(x + k) - \\frac{9}{2}(y + t) - 19\\right] = 0')}</p>` +
    `<p>The ${f('(x + k)')} terms cancel out:</p>` +
    `<p>${f('2\\left(\\frac{9}{2}(y + t) + 19\\right) = 0')}</p>` +
    `<p>${f('9(y + t) + 38 = 0')}</p>` +
    `<p>${f('9(y + t) = -38')}</p>` +
    `<p>Multiply both sides by 2 to obtain ${f('18(y + t)')}:</p>` +
    `<p>${f('18(y + t) = 2(-38) = -76')}</p>`,

  // Q14
  '6a6caaf0c3d08d90637d3f9b':
    `<p>Test the pairs of values in the correct table with the system of inequalities:</p>` +
    `<p>1. For ${f('(12, -14)')}:</p>` +
    `<p>${f('-14 > 2(12) - 72 = -48')} (True) and ${f('-14 < -\\frac{1}{6}(12) - 9 = -11')} (True).</p>` +
    `<p>2. For ${f('(18, -15)')}:</p>` +
    `<p>${f('-15 > 2(18) - 72 = -36')} (True) and ${f('-15 < -\\frac{1}{6}(18) - 9 = -12')} (True).</p>` +
    `<p>3. For ${f('(24, -16)')}:</p>` +
    `<p>${f('-16 > 2(24) - 72 = -24')} (True) and ${f('-16 < -\\frac{1}{6}(24) - 9 = -13')} (True).</p>` +
    `<p>All three data points satisfy both inequalities.</p>`,

  // Q15
  '6a6cab75c3d08d90637d3f9f':
    `<p>The exponential expression ${f('2^x > 0')} for all real values of ${f('x')}.</p>` +
    `<p>Therefore, ${f('6(2)^x > 0')}, which implies:</p>` +
    `<p>${f('6(2)^x + 7 > 7')}</p>` +
    `<p>Multiplying by ${f('\\frac{1}{11}')}:</p>` +
    `<p>${f('g(x) = \\frac{1}{11}(6(2)^x + 7) > \\frac{7}{11}')}</p>` +
    `<p>As ${f('x \\to -\\infty')}, ${f('2^x \\to 0')}, so ${f('g(x)')} approaches ${f('\\frac{7}{11}')} asymptotically from above, but is always strictly greater than ${f('\\frac{7}{11}')}.</p>` +
    `<p>Thus, the greatest possible constant ${f('k')} such that ${f('g(x) > k')} for all ${f('x')} is ${f('\\frac{7}{11}')}.</p>`,

  // Q16
  '6a6cabb6c3d08d90637d3fa3':
    `<p>Data set A consists of 41 observations. The median is the ${f('\\frac{41+1}{2} = 21')}\\text{st} value when ordered.</p>` +
    `<p>Computing cumulative frequencies:</p>` +
    `<p>0 ducks: 1 day</p>` +
    `<p>1 duck: 1 + 7 = 8 days</p>` +
    `<p>2 ducks: 8 + 8 = 16 days</p>` +
    `<p>3 ducks: 16 + 9 = 25 days</p>` +
    `<p>Since the 21st value falls into the 3 ducks category, the median of data set A is 3.</p>` +
    `<p>Data set B removes the erroneous value 13 (which is greater than 3), leaving 40 observations. The median of 40 observations is the average of the 20th and 21st values.</p>` +
    `<p>Both the 20th and 21st values still fall into the 3 ducks category, so the median of data set B is ${f('\\frac{3 + 3}{2} = 3')}.</p>` +
    `<p>Therefore, the median of data set B is equal to the median of data set A.</p>`,

  // Q17
  '6a6cabf2c3d08d90637d3fa7':
    `<p>A 3.0-ounce serving of cheddar cheese provides 1 microgram of vitamin B12, so cheese provides ${f('\\frac{1}{3.0} \\approx 0.33')} micrograms per ounce.</p>` +
    `<p>A 1.2-ounce serving of tuna provides 1 microgram of vitamin B12, so tuna provides ${f('\\frac{1}{1.2} \\approx 0.83')} micrograms per ounce.</p>` +
    `<p>For ${f('x')} ounces of cheese and ${f('y')} ounces of tuna providing a total of 1.7 micrograms, the equation is:</p>` +
    `<p>${f('0.33x + 0.83y = 1.7')}</p>`,

  // Q18
  '6a6cac4cc3d08d90637d3fab':
    `<p>Given that ${f('1\\text{ mile} = 1,760\\text{ yards}')}, square both sides to find the conversion factor for area:</p>` +
    `<p>${f('1\\text{ square mile} = 1,760^2 = 3,097,600\\text{ square yards}')}</p>` +
    `<p>Convert the town's area to square miles:</p>` +
    `<p>${f('\\text{Area} = \\frac{12,669,184}{3,097,600} \\approx 4.09\\text{ square miles}')}</p>`,

  // Q19
  '6a6cad09c3d08d90637d3fb3':
    `<p>To find the ${f('x')}-intercept of the graph of ${f('y = f(x)')}, set ${f('y = 0')}:</p>` +
    `<p>${f('3d(26x + 27) + 18 = 0')}</p>` +
    `<p>${f('3d(26x + 27) = -18')}</p>` +
    `<p>Divide both sides by ${f('3d')}:</p>` +
    `<p>${f('26x + 27 = -\\frac{6}{d}')}</p>` +
    `<p>Subtract 27 from both sides:</p>` +
    `<p>${f('26x = -27 - \\frac{6}{d} = \\frac{-27d - 6}{d}')}</p>` +
    `<p>Divide by 26:</p>` +
    `<p>${f('x = \\frac{-27d - 6}{26d}')}</p>` +
    `<p>Thus, the ${f('x')}-intercept is ${f('\\left(\\frac{-27d - 6}{26d}, 0\\right)')}.</p>`,

  // Q20
  '6a6cadd0c3d08d90637d3fb7':
    `<p>In triangle ${f('ABC')}, the sum of interior angles is ${f('180^\\circ')}. If angle ${f('B = 40^\\circ')}:</p>` +
    `<p>${f('\\text{Angle } C = 180^\\circ - (52^\\circ + 40^\\circ) = 88^\\circ')}</p>` +
    `<p>In triangle ${f('PQR')}, if angle ${f('R = 88^\\circ')}:</p>` +
    `<p>${f('\\text{Angle } Q = 180^\\circ - (52^\\circ + 88^\\circ) = 40^\\circ')}</p>` +
    `<p>Both triangles have interior angles measuring ${f('52^\\circ')}, ${f('40^\\circ')}, and ${f('88^\\circ')}.</p>` +
    `<p>By the Angle-Angle (AA) similarity criterion, having two (and thus all three) corresponding congruent angles is sufficient to prove that triangle ${f('ABC')} is similar to triangle ${f('PQR')}.</p>`,

  // Q21
  '6a6cae1bc3d08d90637d3fbb':
    `<p>A quadratic function with maximum vertex at ${f('(3.5, 13.91)')} can be written in vertex form as:</p>` +
    `<p>${f('d(t) = a(t - 3.5)^2 + 13.91')}</p>` +
    `<p>Using the given point 6 months after March 1 (${f('t = 6')}, ${f('d(6) = 12.66')}):</p>` +
    `<p>${f('a(6 - 3.5)^2 + 13.91 = 12.66')}</p>` +
    `<p>${f('a(2.5)^2 + 13.91 = 12.66')}</p>` +
    `<p>${f('6.25a = 12.66 - 13.91 = -1.25 \\implies a = -0.2')}</p>` +
    `<p>On March 1 (${f('t = 0')}):</p>` +
    `<p>${f('d(0) = -0.2(0 - 3.5)^2 + 13.91 = -0.2(12.25) + 13.91 = -2.45 + 13.91 = 11.46\\text{ hours}')}</p>`,

  // Q22
  '6a6cafaac3d08d90637d3fee':
    `<p>Rearrange the given equation into standard quadratic form ${f('ax^2 + bx + c = 0')}:</p>` +
    `<p>${f('nx^2 - 16x = 26x^2 - 8')}</p>` +
    `<p>${f('(n - 26)x^2 - 16x + 8 = 0')}</p>` +
    `<p>For this quadratic equation to have two distinct real solutions, the leading coefficient must be nonzero (${f('n \\neq 26')}) and the discriminant must be strictly positive (${f('b^2 - 4ac > 0')}):</p>` +
    `<p>${f('(-16)^2 - 4(n - 26)(8) > 0')}</p>` +
    `<p>${f('256 - 32(n - 26) > 0')}</p>` +
    `<p>${f('32(n - 26) < 256')}</p>` +
    `<p>${f('n - 26 < 8 \\implies n < 34')}</p>` +
    `<p>Since ${f('n')} must be an integer, the greatest integer strictly less than 34 is 33.</p>`
};

async function run() {
  console.log('Injecting explanations for September 2025 · US 2 (M2)...');

  // Also fix Q19 question stem to y = f(x)
  console.log('Fixing Q19 question stem...');
  await updateQuestion('6a6cad09c3d08d90637d3fb3', {
    question: `<p>Which of the following represents the ${f('x')}-intercept of the graph of ${f('y = f(x)')} in the ${f('xy')}-plane, where ${f('d')} is a constant?</p><p>${f('f(x) = 3d(26x + 27) + 18')}</p>`
  });

  const ids = Object.keys(explanations);
  let count = 0;
  for (const id of ids) {
    const res = await updateQuestion(id, { explanation: explanations[id] });
    count++;
    console.log(`[${count}/${ids.length}] Updated explanation for ${id}: ${res.message === 'success' ? '✅' : JSON.stringify(res)}`);
  }

  console.log('\n🎉 Finished updating all 22 explanations for September 2025 · US 2 (M2)!');
}

run().catch(console.error);
