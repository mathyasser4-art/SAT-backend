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
  '6a6d2afe14cab24f9785a717':
    `<p>Lines ${f('r')} and ${f('s')} are parallel, intersected by transversal line ${f('n')}.</p>` +
    `<p>The angle measuring ${f('152^\\circ')} and the angle measuring ${f('x^\\circ')} are corresponding angles lying in the same relative position at each intersection.</p>` +
    `<p>Since corresponding angles are equal when parallel lines are cut by a transversal, ${f('x = 152')}.</p>`,

  // Q2
  '6a6d2d1f14cab24f9785a721':
    `<p>The exponential function ${f('f(x) = 3^x')} is strictly convex (curving upward) and ${f('g(x)')} is an increasing linear function (a straight line).</p>` +
    `<p>They intersect at two points ${f('(a, j)')} and ${f('(b, k)')}, with ${f('j < k')}, which implies ${f('a < b')}.</p>` +
    `<p>Between the two intersection points, the secant line ${f('g(x)')} lies above the curve ${f('f(x)')}. Thus, ${f('g(x) > f(x)')} is true when ${f('a < x < b')}.</p>`,

  // Q3
  '6a6d2d6314cab24f9785a727':
    `<p>We are given that ${f('4x = 7')}.</p>` +
    `<p>Multiply both sides by 6 to find the value of ${f('24x')}:</p>` +
    `<p>${f('24x = 6(4x) = 6(7) = 42')}</p>`,

  // Q4
  '6a6d2d9914cab24f9785a72b':
    `<p>Distribute 6 through the second term:</p>` +
    `<p>${f('6(x^2 + 5) = 6x^2 + 30')}</p>` +
    `<p>Now combine with the first polynomial:</p>` +
    `<p>${f('(x^3 + 8x^2 - 7x) + (6x^2 + 30) = x^3 + (8x^2 + 6x^2) - 7x + 30')}</p>` +
    `<p>${f('= x^3 + 14x^2 - 7x + 30')}</p>`,

  // Q5
  '6a6d2df914cab24f9785a72f':
    `<p>Substitute ${f('x = 2')} into the function definition:</p>` +
    `<p>${f('f(2) = 2^3 + 19 = 8 + 19 = 27')}</p>`,

  // Q6
  '6a6d2e5414cab24f9785a733':
    `<p>Set ${f('g(x) = 224')} in the given function ${f('g(x) = \\frac{x}{2}')}:</p>` +
    `<p>${f('\\frac{x}{2} = 224')}</p>` +
    `<p>Multiply both sides by 2:</p>` +
    `<p>${f('x = 2 \\times 224 = 448')}</p>`,

  // Q7
  '6a6d2e8e14cab24f9785a737':
    `<p>Looking at the scatterplot, the data displays a clear negative linear association.</p>` +
    `<p>At ${f('x = 0')}, the ${f('y')}-intercept is approximately 8.5. As ${f('x')} increases to 10, ${f('y')} drops to approximately 0.5:</p>` +
    `<p>${f('\\text{slope} \\approx \\frac{0.5 - 8.5}{10 - 0} = \\frac{-8.0}{10} = -0.8')}</p>` +
    `<p>Therefore, the most appropriate linear model is ${f('y = 8.5 - 0.8x')}.</p>`,

  // Q8
  '6a6d2ed514cab24f9785a73b':
    `<p>The ${f('y')}-intercept of a graph is the point where ${f('x = 0')}.</p>` +
    `<p>Substitute ${f('x = 0')} into ${f('y = x^2 + 15')}:</p>` +
    `<p>${f('y = 0^2 + 15 = 15')}</p>` +
    `<p>Thus, the ${f('y')}-intercept is ${f('(0, 15)')}, and the value of ${f('y')} is 15.</p>`,

  // Q9
  '6a6d2f1814cab24f9785a73f':
    `<p>Solve the given equation ${f('4x - 3y = -24')} for ${f('y')}:</p>` +
    `<p>${f('3y = 4x + 24 \\implies y = \\frac{4}{3}x + 8')}</p>` +
    `<p>Evaluate for ${f('x = 0, 3, 6')}:</p>` +
    `<p>For ${f('x = 0')}: ${f('y = \\frac{4}{3}(0) + 8 = 8')}</p>` +
    `<p>For ${f('x = 3')}: ${f('y = \\frac{4}{3}(3) + 8 = 12')}</p>` +
    `<p>For ${f('x = 6')}: ${f('y = \\frac{4}{3}(6) + 8 = 16')}</p>` +
    `<p>The table with values ${f('(0, 8), (3, 12), (6, 16)')} correctly represents the equation.</p>`,

  // Q10
  '6a6d2f3714cab24f9785a743':
    `<p>The total volume of the mixture is 38 mL, which is the sum of the volumes of water and isopropanol:</p>` +
    `<p>${f('\\text{Volume of water} + \\text{Volume of isopropanol} = 38')}</p>` +
    `<p>${f('\\text{Volume of water} + 10 = 38')}</p>` +
    `<p>${f('\\text{Volume of water} = 38 - 10 = 28\\text{ mL}')}</p>`,

  // Q11
  '6a6d2fc214cab24f9785a747':
    `<p>Set the two expressions for ${f('y')} equal to each other:</p>` +
    `<p>${f('-\\frac{1}{8}x = \\frac{1}{10}x')}</p>` +
    `<p>Add ${f('\\frac{1}{8}x')} to both sides:</p>` +
    `<p>${f('\\left(\\frac{1}{10} + \\frac{1}{8}\\right)x = 0')}</p>` +
    `<p>${f('\\frac{9}{40}x = 0 \\implies x = 0')}</p>`,

  // Q12
  '6a6d301314cab24f9785a74b':
    `<p>The initial number of enrolled customers in January 2018 is 800.</p>` +
    `<p>A monthly increase of 5% corresponds to a growth factor of ${f('1 + 0.05 = 1.05')}.</p>` +
    `<p>Therefore, the number of customers ${f('c')} enrolled ${f('m')} months after January 2018 is given by:</p>` +
    `<p>${f('c = 800(1.05)^m')}</p>`,

  // Q13
  '6a6d38fd14cab24f9785a751':
    `<p>In the exponential model ${f('f(t) = 60,000(2)^{\\frac{t}{580}}')}, the base 2 represents doubling.</p>` +
    `<p>The initial population is 60,000. It doubles to 120,000 when the exponent is equal to 1:</p>` +
    `<p>${f('\\frac{t}{580} = 1 \\implies t = 580\\text{ minutes}')}</p>`,

  // Q14
  '6a6d399714cab24f9785a755':
    `<p>Since ${f('f(x)')} equals 293% of ${f('x')}, the function can be written as:</p>` +
    `<p>${f('f(x) = 2.93x')}</p>` +
    `<p>This is a linear equation of the form ${f('f(x) = mx + b')} with slope ${f('m = 2.93 > 0')} and ${f('y')}-intercept 0.</p>` +
    `<p>Because the rate of change is constant and positive, the function is increasing linear.</p>`,

  // Q15
  '6a6d39bd14cab24f9785a759':
    `<p>A system of linear equations in two variables has infinitely many solutions if and only if both equations represent the exact same line.</p>` +
    `<p>Therefore, the graph of the second equation must have the exact same slope as the first equation, which is ${f('\\frac{3}{8}')}.</p>`,

  // Q16
  '6a6d3a3114cab24f9785a75d':
    `<p>Divide each term of the given equation ${f('4x^2 - 32x - 40 = 0')} by 4:</p>` +
    `<p>${f('x^2 - 8x - 10 = 0')}</p>` +
    `<p>Add 10 to both sides to isolate ${f('x^2 - 8x')}:</p>` +
    `<p>${f('x^2 - 8x = 10')}</p>`,

  // Q17
  '6a6d3ab914cab24f9785a761':
    `<p>Since the graph of ${f('y = f(x)')} passes through ${f('(-3, 0)')}, we know ${f('f(-3) = 0')}:</p>` +
    `<p>${f('(-3 - 5)(-3 - 9)(-3 + k) = 0')}</p>` +
    `<p>${f('(-8)(-12)(-3 + k) = 0 \\implies 96(-3 + k) = 0 \\implies k = 3')}</p>` +
    `<p>Now evaluate ${f('f(0)')}:</p>` +
    `<p>${f('f(0) = (0 - 5)(0 - 9)(0 + 3) = (-5)(-9)(3) = 135')}</p>`,

  // Q18
  '6a6d3d3a14cab24f9785a767':
    `<p>From the graph, line ${f('k')} passes through ${f('(0, 4)')} and ${f('(3, 0)')}. Its slope is:</p>` +
    `<p>${f('m_k = \\frac{0 - 4}{3 - 0} = -\\frac{4}{3}')}</p>` +
    `<p>Line ${f('j')} is perpendicular to line ${f('k')}, so its slope is the negative reciprocal:</p>` +
    `<p>${f('m_j = -\\frac{1}{-\\frac{4}{3}} = \\frac{3}{4}')}</p>` +
    `<p>Using point-slope form with ${f('(-20, -23)')}:</p>` +
    `<p>${f('y - (-23) = \\frac{3}{4}(x - (-20))')}</p>` +
    `<p>${f('y + 23 = \\frac{3}{4}x + 15 \\implies y = \\frac{3}{4}x - 8')}</p>`,

  // Q19
  '6a6d3db414cab24f9785a76b':
    `<p>In right triangle ${f('ABC')} with acute angles ${f('A')} and ${f('B')}, the right angle is at ${f('C')}.</p>` +
    `<p>By definition of tangent: ${f('\\tan B = \\frac{\\text{opposite}}{\\text{adjacent}} = \\frac{AC}{BC}')}.</p>` +
    `<p>Substitute ${f('\\tan B = \\frac{1}{9}')} and ${f('AC = 29.5')}:</p>` +
    `<p>${f('\\frac{1}{9} = \\frac{29.5}{BC} \\implies BC = 9 \\times 29.5 = 265.5')}</p>`,

  // Q20
  '6a6d3dd914cab24f9785a76f':
    `<p>The original area of the banner is ${f('A_1 = l \\times w = 3,200')} square inches.</p>` +
    `<p>When the length and width are each increased by 20%, the new dimensions are ${f('l\' = 1.20l')} and ${f('w\' = 1.20w')}.</p>` +
    `<p>The area of the copy is:</p>` +
    `<p>${f('A_2 = (1.20l)(1.20w) = 1.44(lw) = 1.44 \\times 3,200 = 4,608\\text{ square inches}')}</p>`,

  // Q21
  '6a6d3e0014cab24f9785a773':
    `<p>The function is given in vertex form: ${f('f(x) = (x - 4)^2 + 6')}.</p>` +
    `<p>Since the squared term ${f('(x - 4)^2 \\ge 0')} for all real ${f('x')}, its minimum value is 0, occurring at ${f('x = 4')}.</p>` +
    `<p>Therefore, the minimum value of ${f('f(x)')} is ${f('0 + 6 = 6')}.</p>`,

  // Q22
  '6a6d3e9814cab24f9785a777':
    `<p>Point ${f('F(1, 0)')} lies on the positive ${f('x')}-axis at an angle of 0 radians.</p>` +
    `<p>Point ${f('H(-1, y)')} lies on the unit circle ${f('x^2 + y^2 = 1')}. Substituting ${f('x = -1')} gives ${f('(-1)^2 + y^2 = 1 \\implies y = 0')}, so ${f('H')} is ${f('(-1, 0)')}, which lies on the negative ${f('x')}-axis.</p>` +
    `<p>Any angle in standard position with its terminal side along the negative ${f('x')}-axis has a measure of ${f('\\pi + 2\\pi k = (2k + 1)\\pi')} radians (an odd multiple of ${f('\\pi')}).</p>` +
    `<p>Among the given options, only ${f('35\\pi')} is an odd integer multiple of ${f('\\pi')}.</p>`
};

async function run() {
  console.log('Injecting explanations for June 2025 · INT 1 (M1)...');

  const ids = Object.keys(explanations);
  let count = 0;
  for (const id of ids) {
    const res = await updateQuestion(id, { explanation: explanations[id] });
    count++;
    console.log(`[${count}/${ids.length}] Updated explanation for ${id}: ${res.message === 'success' ? '✅' : JSON.stringify(res)}`);
  }

  console.log('\n🎉 Finished updating all 22 explanations for June 2025 · INT 1 (M1)!');
}

run().catch(console.error);
