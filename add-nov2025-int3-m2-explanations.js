const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';

function updateQuestionExplanation(questionId, explanationHtml) {
    return new Promise((resolve, reject) => {
        const payload = JSON.stringify({ explanation: explanationHtml });
        const req = https.request(`${API_BASE}/question/updateQuestion/${questionId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload)
            }
        }, (res) => {
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

function f(formula) {
  return `<span class="ql-formula" data-value="${formula}"></span>`;
}

const explanations = {
  // Q1
  '6a62427dc3d08d90637d3557': `<p><strong>The correct answer is 300.</strong></p>
<p>The total amount saved after ${f('w')} weeks is modeled by the equation ${f('d = 20w + 100')}.</p>
<p>To find the total amount saved in 10 weeks, substitute ${f('w = 10')}:</p>
<p>${f('d = 20(10) + 100 = 200 + 100 = 300')}</p>
<p>Thus, Janna plans to save <strong>$300</strong> in 10 weeks.</p>`,

  // Q2
  '6a6242afc3d08d90637d355b': `<p><strong>The correct answer is 13.</strong></p>
<p>We are given the system of equations:</p>
<p>1) ${f('x + 2y = 28')}</p>
<p>2) ${f('2y = 15')}</p>
<p>Substitute ${f('2y = 15')} directly into the first equation:</p>
<p>${f('x + 15 = 28')}</p>
<p>Subtract 15 from both sides:</p>
<p>${f('x = 28 - 15 = 13')}</p>`,

  // Q3
  '6a6243b2c3d08d90637d3572': `<p><strong>The correct answer is ${f('b = \\pm\\sqrt{6d - 5c}')}.</strong></p>
<p>Start with the given equation:</p>
<p>${f('b^2 + 5c = 6d')}</p>
<p>Subtract ${f('5c')} from both sides to isolate ${f('b^2')}:</p>
<p>${f('b^2 = 6d - 5c')}</p>
<p>Take the square root of both sides, remembering to include both positive and negative roots:</p>
<p>${f('b = \\pm\\sqrt{6d - 5c}')}</p>`,

  // Q4
  '6a624414c3d08d90637d359a': `<p><strong>The correct answer is 42.</strong></p>
<p>The formula for the area of a triangle is:</p>
<p>${f('\\text{Area} = \\frac{1}{2} \\times \\text{base} \\times \\text{height}')}</p>
<p>From the figure, the base is ${f('AC = 10\\text{ cm}')}, and the height is ${f('h')}. We are given that the area is 210 square centimeters:</p>
<p>${f('210 = \\frac{1}{2}(10)(h)')}</p>
<p>${f('210 = 5h')}</p>
<p>Divide both sides by 5:</p>
<p>${f('h = \\frac{210}{5} = 42\\text{ cm}')}</p>`,

  // Q5
  '6a624464c3d08d90637d35a6': `<p><strong>The correct answer is -35.</strong></p>
<p>The function ${f('g')} is defined as ${f('g(x) = 2(14x - 15) = 28x - 30')}.</p>
<p>The equation of the graph is ${f('y = g(x) - 5')}:</p>
<p>${f('y = (28x - 30) - 5 = 28x - 35')}</p>
<p>The ${f('y')}-intercept of a graph in the ${f('xy')}-plane is the point where ${f('x = 0')}:</p>
<p>${f('y = 28(0) - 35 = -35')}</p>
<p>Thus, the ${f('y')}-coordinate of the ${f('y')}-intercept is <strong>-35</strong>.</p>`,

  // Q6
  '6a624492c3d08d90637d35aa': `<p><strong>The correct answer is 0.36.</strong></p>
<p>We are asked to find the conditional probability of selecting a person who is greater than 65 years old, <em>given</em> that the person is at least 18 years old:</p>
<p>${f('P(> 65 \\mid \\ge 18) = \\frac{P(> 65)}{P(\\ge 18)}')}</p>
<p>From the table, the proportion of people at least 18 years old includes the groups:</p>
<p>• 18–40 years old: 24%</p>
<p>• 41–65 years old: 22%</p>
<p>• Greater than 65 years old: 26%</p>
<p>${f('P(\\ge 18) = 24\\% + 22\\% + 26\\% = 72\\%')}</p>
<p>Now calculate the conditional probability:</p>
<p>${f('P(> 65 \\mid \\ge 18) = \\frac{26\\%}{72\\%} = \\frac{26}{72} = \\frac{13}{36} \\approx 0.3611')}</p>
<p>The closest value among the choices is <strong>0.36</strong>.</p>`,

  // Q7
  '6a6244e1c3d08d90637d35ae': `<p><strong>The correct answer is 1.2 (or 6/5).</strong></p>
<p>The height of the object above the ground is given by ${f('h(t) = -16t^2 + b')}.</p>
<p>At time ${f('t = 0')}, the height is 23.04 feet:</p>
<p>${f('h(0) = -16(0)^2 + b = 23.04 \\implies b = 23.04')}</p>
<p>The object hits the ground when ${f('h(t) = 0')}:</p>
<p>${f('-16t^2 + 23.04 = 0')}</p>
<p>${f('16t^2 = 23.04')}</p>
<p>Divide by 16:</p>
<p>${f('t^2 = \\frac{23.04}{16} = 1.44')}</p>
<p>Take the positive square root since time ${f('t \\ge 0')}:</p>
<p>${f('t = \\sqrt{1.44} = 1.2\\text{ seconds}')}</p>`,

  // Q8
  '6a62451ac3d08d90637d35b2': `<p><strong>The correct answer is 28.</strong></p>
<p>In a rectangle with side lengths ${f('a')} and ${f('b')} and diagonal ${f('d')}, by the Pythagorean theorem:</p>
<p>${f('a^2 + b^2 = d^2')}</p>
<p>Given ${f('d = \\sqrt{106}')} and ${f('a = 9')}:</p>
<p>${f('9^2 + b^2 = (\\sqrt{106})^2')}</p>
<p>${f('81 + b^2 = 106')}</p>
<p>${f('b^2 = 106 - 81 = 25 \\implies b = 5')}</p>
<p>The perimeter of the rectangle is:</p>
<p>${f('P = 2(a + b) = 2(9 + 5) = 2(14) = 28')}</p>`,

  // Q9
  '6a6245cec3d08d90637d35b6': `<p><strong>The correct answer is "Circle B is the reflection of circle A across the ${f('y')}-axis."</strong></p>
<p>The standard equation of a circle is ${f('(x - h)^2 + (y - k)^2 = r^2')}, where ${f('(h, k)')} is the center.</p>
<p>• Circle A has equation ${f('(x - 7)^2 + (y - p)^2 = 21')}, so its center is ${f('(7, p)')} and its radius is ${f('\\sqrt{21}')}.</p>
<p>• Circle B has equation ${f('(x + 7)^2 + (y - p)^2 = 21')}, so its center is ${f('(-7, p)')} and its radius is ${f('\\sqrt{21}')}.</p>
<p>Both circles have the same radius. Reflecting a point ${f('(x, y)')} across the ${f('y')}-axis negates the ${f('x')}-coordinate while leaving the ${f('y')}-coordinate unchanged, mapping ${f('(7, p)')} to ${f('(-7, p)')}.</p>
<p>Therefore, Circle B is the reflection of Circle A across the ${f('y')}-axis.</p>`,

  // Q10
  '6a624665c3d08d90637d35cc': `<p><strong>The correct answer is 4.</strong></p>
<p>Expand both sides of the given equation:</p>
<p>${f('a(9 - x) = 36 - 4x')}</p>
<p>${f('9a - ax = 36 - 4x')}</p>
<p>Rearrange all terms with ${f('x')} on one side:</p>
<p>${f('4x - ax = 36 - 9a')}</p>
<p>${f('(4 - a)x = 36 - 9a')}</p>
<p>A linear equation in one variable of the form ${f('Ax = B')} has:</p>
<p>• Exactly one solution if ${f('A \\ne 0')}.</p>
<p>• Infinitely many solutions if ${f('A = 0')} and ${f('B = 0')}.</p>
<p>• Zero solutions if ${f('A = 0')} and ${f('B \\ne 0')}.</p>
<p>For the equation to have exactly one solution, the coefficient ${f('4 - a')} must not be 0. If ${f('a = 4')}:</p>
<p>${f('(4 - 4)x = 36 - 9(4) \\implies 0x = 0')}</p>
<p>which has infinitely many solutions, not exactly one. Therefore, ${f('a')} <strong>CANNOT be 4</strong>.</p>`,

  // Q11
  '6a6246b8c3d08d90637d35d0': `<p><strong>The correct answer is 79.</strong></p>
<p>The 7 data values in ascending order are:</p>
<p>${f('a, 26, 29, b, 33, 49, c')}</p>
<p>1) <strong>Median:</strong> For 7 ordered values, the median is the 4th value. Thus, ${f('b = 29')}.</p>
<p>2) <strong>Range:</strong> The range is the difference between the maximum and minimum values:</p>
<p>${f('\\text{Range} = c - a = 72 \\implies c = a + 72')}</p>
<p>3) <strong>Mean:</strong> The mean of the 7 values is 36, so their sum is:</p>
<p>${f('\\text{Sum} = 7 \\times 36 = 252')}</p>
<p>Set up the sum equation:</p>
<p>${f('a + 26 + 29 + 29 + 33 + 49 + c = 252')}</p>
<p>${f('a + c + 166 = 252')}</p>
<p>${f('a + c = 86')}</p>
<p>Substitute ${f('c = a + 72')}:</p>
<p>${f('a + (a + 72) = 86 \\implies 2a = 14 \\implies a = 7')}</p>
<p>Now find ${f('c')}:</p>
<p>${f('c = 7 + 72 = 79')}</p>`,

  // Q12
  '6a624727c3d08d90637d35d4': `<p><strong>The correct answer is One.</strong></p>
<p>Consider the function ${f('y = 3\\left(\\frac{a}{6}\\right)^{x+c} - b')}.</p>
<p>A graph crosses the ${f('x')}-axis where ${f('y = 0')}:</p>
<p>${f('3\\left(\\frac{a}{6}\\right)^{x+c} - b = 0 \\implies \\left(\\frac{a}{6}\\right)^{x+c} = \\frac{b}{3}')}</p>
<p>We are given that:</p>
<p>• ${f('a > 6')}, so the base ${f('\\frac{a}{6} > 1')}. This means ${f('f(x) = \\left(\\frac{a}{6}\\right)^{x+c}')} is a strictly increasing exponential function with range ${f('(0, \\infty)')}.</p>
<p>• ${f('b > 0')}, which means ${f('\\frac{b}{3} > 0')}.</p>
<p>Since the base is positive and strictly greater than 1, and the right-hand side ${f('\\frac{b}{3}')} is a positive constant, the equation has exactly one real solution for ${f('x')}:</p>
<p>${f('x + c = \\log_{a/6}\\left(\\frac{b}{3}\\right) \\implies x = \\log_{a/6}\\left(\\frac{b}{3}\\right) - c')}</p>
<p>Because the graph is strictly increasing, it crosses the ${f('x')}-axis at this unique point. Thus, it crosses the ${f('x')}-axis <strong>one</strong> time.</p>`,

  // Q13
  '6a624768c3d08d90637d35d8': `<p><strong>The correct answer is 4.</strong></p>
<p>For a linear function ${f('g(x) = ax + b')}, the coefficient ${f('a')} is the slope of the line.</p>
<p>The slope formula using the two points ${f('(-2, -7)')} and ${f('(1, 5)')} is:</p>
<p>${f('a = \\frac{g(1) - g(-2)}{1 - (-2)} = \\frac{5 - (-7)}{1 - (-2)} = \\frac{12}{3} = 4')}</p>`,

  // Q14
  '6a6247c9c3d08d90637d35e6': `<p><strong>The correct answer is 60.</strong></p>
<p>Given the quadratic equation ${f('2x^2 - 8x - 21 = 0')}, use the quadratic formula where ${f('A = 2')}, ${f('B = -8')}, and ${f('C = -21')}:</p>
<p>${f('x = \\frac{-(-8) \\pm \\sqrt{(-8)^2 - 4(2)(-21)}}{2(2)}')}</p>
<p>${f('x = \\frac{8 \\pm \\sqrt{64 + 168}}{4} = \\frac{8 \\pm \\sqrt{232}}{4}')}</p>
<p>Simplify the fraction:</p>
<p>${f('x = \\frac{8}{4} \\pm \\frac{\\sqrt{232}}{4} = 2 \\pm \\frac{1}{4}\\sqrt{232}')}</p>
<p>We want to write the second term as ${f('\\frac{1}{2}\\sqrt{k}')}:</p>
<p>${f('\\frac{1}{4}\\sqrt{232} = \\frac{1}{2} \\cdot \\frac{1}{2}\\sqrt{232} = \\frac{1}{2}\\sqrt{\\frac{232}{4}} = \\frac{1}{2}\\sqrt{58}')}</p>
<p>Therefore, the solution with the minus sign is:</p>
<p>${f('x = 2 - \\frac{1}{2}\\sqrt{58}')}</p>
<p>Matching this with ${f('x = h - \\frac{1}{2}\\sqrt{k}')}, we have ${f('h = 2')} and ${f('k = 58')}.</p>
<p>Thus, ${f('h + k = 2 + 58 = 60')}.</p>`,

  // Q15
  '6a624816c3d08d90637d35ea': `<p><strong>The correct answer is 3.</strong></p>
<p>We are given that ${f('r(x) \\cdot s(x) = 9(x^4 - 81)')}, where ${f('r(x) = 9(x - 3)')}.</p>
<p>Factor ${f('x^4 - 81')} as a difference of squares:</p>
<p>${f('x^4 - 81 = (x^2 - 9)(x^2 + 9) = (x - 3)(x + 3)(x^2 + 9)')}</p>
<p>Substitute this into the product:</p>
<p>${f('9(x - 3) \\cdot s(x) = 9(x - 3)(x + 3)(x^2 + 9)')}</p>
<p>Divide both sides by ${f('9(x - 3)')}:</p>
<p>${f('s(x) = (x + 3)(x^2 + 9) = x^3 + 3x^2 + 9x + 27')}</p>
<p>Comparing this with the given formula ${f('s(x) = x^3 + nx^2 + 3nx + 27')}:</p>
<p>The coefficient of ${f('x^2')} is ${f('n = 3')}.</p>
<p>Check the coefficient of ${f('x')}: ${f('3n = 3(3) = 9')}, which is fully consistent.</p>
<p>Thus, the value of ${f('n')} is <strong>3</strong>.</p>`,

  // Q16
  '6a62485dc3d08d90637d35f6': `<p><strong>The correct answer is ${f('V = 85(2.40)^{2t}')}.</strong></p>
<p>• The initial number of visitors at ${f('t = 0')} is 85.</p>
<p>• Every 30 minutes, the visitors increase by 140%. The growth factor per 30-minute period is:</p>
<p>${f('1 + 1.40 = 2.40')}</p>
<p>• Since ${f('t')} is measured in hours, and each hour contains two 30-minute periods, the number of 30-minute periods that elapse in ${f('t')} hours is:</p>
<p>${f('\\frac{t}{0.5} = 2t')}</p>
<p>Therefore, the exponential model is:</p>
<p>${f('V = 85(2.40)^{2t}')}</p>`,

  // Q17
  '6a6248cfc3d08d90637d35fa': `<p><strong>The correct answer is -6.</strong></p>
<p>The function is ${f('v(x) = \\frac{x^2 + bx + c}{(x + 5)(x - 19)}')}.</p>
<p>1) The graph passes through ${f('\\left(0, \\frac{66}{95}\\right)')}:</p>
<p>${f('v(0) = \\frac{0^2 + b(0) + c}{(5)(-19)} = \\frac{c}{-95} = \\frac{66}{95} \\implies c = -66')}</p>
<p>2) The graph passes through ${f('(11, 0)')}, so ${f('v(11) = 0')}:</p>
<p>${f('v(11) = \\frac{11^2 + 11b - 66}{(11 + 5)(11 - 19)} = 0 \\implies 121 + 11b - 66 = 0')}</p>
<p>${f('55 + 11b = 0 \\implies 11b = -55 \\implies b = -5')}</p>
<p>The numerator of ${f('v(x)')} is therefore:</p>
<p>${f('x^2 - 5x - 66 = (x - 11)(x + 6)')}</p>
<p>To have ${f('v(q) = 0')}, the numerator must be zero and denominator nonzero:</p>
<p>${f('(q - 11)(q + 6) = 0 \\implies q = 11 \\quad \\text{or} \\quad q = -6')}</p>
<p>Among the given choices (-6, -5, 5, 6), the value <strong>-6</strong> is correct.</p>`,

  // Q18
  '6a62492ac3d08d90637d35fe': `<p><strong>The correct answer is 48.</strong></p>
<p>First, find the slope of line ${f('s')}:</p>
<p>${f('x - 4y = 24 \\implies 4y = x - 24 \\implies y = \\frac{1}{4}x - 6')}</p>
<p>The slope of line ${f('s')} is ${f('m_s = \\frac{1}{4}')}.</p>
<p>Since line ${f('t')} is perpendicular to line ${f('s')}, its slope is the negative reciprocal:</p>
<p>${f('m_t = -\\frac{1}{m_s} = -4')}</p>
<p>Line ${f('t')} passes through ${f('(k, 0)')} and ${f('(60, -k)')}. Using the slope formula:</p>
<p>${f('\\text{Slope} = \\frac{-k - 0}{60 - k} = -4')}</p>
<p>${f('\\frac{-k}{60 - k} = -4 \\implies \\frac{k}{60 - k} = 4')}</p>
<p>Multiply by ${f('60 - k')}:</p>
<p>${f('k = 4(60 - k) = 240 - 4k')}</p>
<p>${f('5k = 240 \\implies k = 48')}</p>`,

  // Q19
  '6a62498ec3d08d90637d3602': `<p><strong>The correct answer is ${f('\\frac{2}{35}')}.</strong></p>
<p>In a series circuit, total resistance is the sum of the individual resistances:</p>
<p>${f('R_{\\text{total}} = a x + b y')}</p>
<p>We are given the equation ${f('\\frac{x}{7} + \\frac{y}{5} = \\frac{41}{35}')}, which can be rewritten as:</p>
<p>${f('\\left(\\frac{1}{7}\\right)x + \\left(\\frac{1}{5}\\right)y = \\frac{41}{35}')}</p>
<p>Comparing this to ${f('a x + b y = \\frac{41}{35}')}, the resistances of the two types of resistors are ${f('a = \\frac{1}{7}')} ohms and ${f('b = \\frac{1}{5}')} ohms (or vice versa).</p>
<p>The positive difference between ${f('a')} and ${f('b')} is:</p>
<p>${f('|b - a| = \\left|\\frac{1}{5} - \\frac{1}{7}\\right| = \\frac{7 - 5}{35} = \\frac{2}{35}')}</p>`,

  // Q20
  '6a624b02c3d08d90637d3608': `<p><strong>The correct answer is I only.</strong></p>
<p>We are given that ${f('x \\ge 0')}, ${f('a > 1')}, and ${f('a < b')}.</p>
<p><strong>Examining Function I:</strong></p>
<p>${f('f(x) = a(0.63)^{-bx} = a\\left(\\frac{1}{0.63}\\right)^{bx}')}</p>
<p>Since ${f('0.63 < 1')}, its reciprocal ${f('\\frac{1}{0.63} > 1')}. Since ${f('b > 1 > 0')}, this is a strictly increasing exponential function for ${f('x \\ge 0')}.</p>
<p>Its minimum value on the domain ${f('x \\ge 0')} occurs at the boundary ${f('x = 0')}:</p>
<p>${f('f(0) = a(0.63)^0 = a(1) = a')}</p>
<p>The minimum value is ${f('a')}, which appears explicitly as the coefficient in equation I.</p>
<p><strong>Examining Function II:</strong></p>
<p>${f('g(x) = a(1.37)^{x+2} + b')}</p>
<p>Since ${f('1.37 > 1')}, this function is also strictly increasing for ${f('x \\ge 0')}. The minimum value occurs at ${f('x = 0')}:</p>
<p>${f('g(0) = a(1.37)^2 + b = 1.8769a + b')}</p>
<p>This minimum value does not equal ${f('b')} nor is it displayed as a constant or coefficient in the equation (${f('b')} is the horizontal asymptote as ${f('x \\to -\\infty')}, which is outside the domain ${f('x \\ge 0')}).</p>
<p>Therefore, only equation <strong>I</strong> displays the minimum value.</p>`,

  // Q21
  '6a624b9cc3d08d90637d360c': `<p><strong>The correct answer is "The value of ${f('31 - 3x - 3y')}".</strong></p>
<p>In triangle ${f('XYZ')}, the sum of interior angles is ${f('180^\\circ')}:</p>
<p>${f('x + y + 31 = 180 \\implies x + y = 149')}</p>
<p>To determine the individual values of ${f('x')} and ${f('y')}, any additional piece of information must provide a new, linearly independent equation involving ${f('x')} and ${f('y')}.</p>
<p>Consider the expression ${f('31 - 3x - 3y')}:</p>
<p>${f('31 - 3x - 3y = 31 - 3(x + y)')}</p>
<p>Since we already know ${f('x + y = 149')}, the value of this expression is already fixed:</p>
<p>${f('31 - 3(149) = 31 - 447 = -416')}</p>
<p>Knowing this value provides zero new information about ${f('x')} and ${f('y')}; it is completely dependent on ${f('x + y = 149')}. Therefore, it is <strong>NOT sufficient</strong> to determine the values of ${f('x')} and ${f('y')}.</p>`,

  // Q22
  '6a624bd9c3d08d90637d3610': `<p><strong>The correct answer is 0.8499.</strong></p>
<p>Let ${f('C_{2012}')}, ${f('C_{2013}')}, and ${f('C_{2014}')} represent Chloe's earnings in each year.</p>
<p>In 2013, she earned 11% more than in 2012:</p>
<p>${f('C_{2013} = 1.11 \\times C_{2012}')}</p>
<p>In 2014, she earned 6% more than in 2013:</p>
<p>${f('C_{2014} = 1.06 \\times C_{2013} = 1.06(1.11 \\times C_{2012}) = 1.1766 \\times C_{2012}')}</p>
<p>We are given that Chloe earned ${f('y')} times as much in 2012 as in 2014:</p>
<p>${f('C_{2012} = y \\times C_{2014}')}</p>
<p>Substitute ${f('C_{2014} = 1.1766 \\times C_{2012}')}:</p>
<p>${f('C_{2012} = y \\times (1.1766 \\times C_{2012}) \\implies 1 = 1.1766y')}</p>
<p>${f('y = \\frac{1}{1.1766} \\approx 0.8499065')}</p>
<p>Among the given choices, the value closest to ${f('y')} is <strong>0.8499</strong>.</p>`
};

async function run() {
  console.log('🚀 Injecting 22 explanations for November 2025 · INT 3 Module 2...\n');
  const ids = Object.keys(explanations);
  let successCount = 0;

  for (let i = 0; i < ids.length; i++) {
    const id = ids[i];
    process.stdout.write(`Updating M2 Q${i + 1} (${id})... `);
    try {
      const res = await updateQuestionExplanation(id, explanations[id]);
      if (res.message === 'success') {
        console.log('✅');
        successCount++;
      } else {
        console.log('⚠️ ' + JSON.stringify(res));
      }
    } catch (err) {
      console.log('❌ Error: ' + err.message);
    }
  }

  console.log(`\n🎉 Finished Module 2: ${successCount}/${ids.length} explanations injected successfully!`);
}

run().catch(console.error);
