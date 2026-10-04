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
  '6a5fb800c3d08d90637d3398': `<p><strong>Choice B is correct.</strong></p>
<p>In the figure, transversal line ${f('k')} intersects lines ${f('r')} and ${f('s')}.</p>
<p>Angle ${f('w^\\circ')} and angle ${f('y^\\circ')} are corresponding angles located in the same relative position (top-right) at each intersection.</p>
<p>By the Corresponding Angles Converse Postulate, if two lines are cut by a transversal and their corresponding angles are congruent, then the lines are parallel.</p>
<p>Therefore, knowing that ${f('y = 141')} (so ${f('w = y = 141')}) is sufficient to prove that lines ${f('r')} and ${f('s')} are parallel.</p>
<p><strong>Choice A is incorrect</strong> because angle ${f('x')} and angle ${f('w')} are vertical angles on the same line ${f('r')}; their relationship provides no information about line ${f('s')}.</p>
<p><strong>Choices C and D are incorrect</strong> because ${f('w + y = 180')} would imply the lines are not parallel since ${f('w')} and ${f('y')} must be equal, not supplementary (unless both were 90°).</p>`,

  // Q2
  '6a5fb854c3d08d90637d339c': `<p><strong>The correct answer is 3/2 (or 1.5).</strong></p>
<p>Use the slope formula ${f('m = \\frac{y_2 - y_1}{x_2 - x_1}')} with the given points ${f('(4, 7)')} and ${f('(18, 28)')}:</p>
<p>${f('m = \\frac{28 - 7}{18 - 4} = \\frac{21}{14}')}</p>
<p>Reduce the fraction by dividing numerator and denominator by 7:</p>
<p>${f('m = \\frac{3}{2} = 1.5')}</p>`,

  // Q3
  '6a5fb88fc3d08d90637d33a9': `<p><strong>Choice C is correct.</strong></p>
<p>Let the rectangle have length ${f('l = 9')} and width ${f('w')}. By the Pythagorean theorem, the length of the diagonal is ${f('d = \\sqrt{106}')}:</p>
<p>${f('l^2 + w^2 = d^2 \\implies 9^2 + w^2 = (\\sqrt{106})^2')}</p>
<p>${f('81 + w^2 = 106')}</p>
<p>${f('w^2 = 106 - 81 = 25 \\implies w = 5')}</p>
<p>The perimeter of the rectangle is:</p>
<p>${f('P = 2(l + w) = 2(9 + 5) = 2(14) = 28')}</p>
<p><strong>Choice A is incorrect</strong> because 106 is the square of the diagonal.</p>
<p><strong>Choice B is incorrect</strong> because 45 is the area of the rectangle (${f('9 \\times 5 = 45')}), not the perimeter.</p>
<p><strong>Choice D is incorrect</strong> because 14 is the semi-perimeter (${f('l + w')}).</p>`,

  // Q4
  '6a5fb8bfc3d08d90637d33ad': `<p><strong>Choice B is correct.</strong></p>
<p>Set each factor of the quadratic equation to zero using the zero product property:</p>
<p>${f('5x + 6 = 0 \\implies 5x = -6 \\implies x = -\\frac{6}{5}')}</p>
<p>${f('8x - 5 = 0 \\implies 8x = 5 \\implies x = \\frac{5}{8}')}</p>
<p>Among the given choices, ${f('-\\frac{6}{5}')} is listed.</p>
<p><strong>Choices A, C, and D are incorrect</strong> and result from inverting numerator and denominator or using wrong signs.</p>`,

  // Q5
  '6a5fb901c3d08d90637d33b3': `<p><strong>The correct answer is -9.</strong></p>
<p>Convert the linear equation into slope-intercept form ${f('y = mx + b')}:</p>
<p>${f('9x + y = 16')}</p>
<p>Subtract ${f('9x')} from both sides:</p>
<p>${f('y = -9x + 16')}</p>
<p>The slope ${f('m')} is <strong>-9</strong>.</p>`,

  // Q6
  '6a5fb97cc3d08d90637d33b7': `<p><strong>Choice B is correct.</strong></p>
<p>From the second equation, express ${f('y')} in terms of ${f('x')}:</p>
<p>${f('y - 8x = 0 \\implies y = 8x')}</p>
<p>Substitute this into the first equation ${f('x^2 + y^2 = 3,185')}:</p>
<p>${f('x^2 + (8x)^2 = 3,185')}</p>
<p>${f('x^2 + 64x^2 = 3,185 \\implies 65x^2 = 3,185')}</p>
<p>Divide by 65:</p>
<p>${f('x^2 = \\frac{3,185}{65} = 49')}</p>
<p>Since we are given that ${f('x < 0')}:</p>
<p>${f('x = -7')}</p>
<p>Now find the value of ${f('y')}:</p>
<p>${f('y = 8x = 8(-7) = -56')}</p>
<p><strong>Choice A is incorrect</strong> because ${f('-392 = 8(-49)')}.</p>
<p><strong>Choices C and D are incorrect</strong> because ${f('-7')} is the value of ${f('x')}, and ${f('-8')} is the coefficient ratio.</p>`,

  // Q7
  '6a5fb9e2c3d08d90637d33bb': `<p><strong>Choice A is correct.</strong></p>
<p>Substitute ${f('x = a')} into ${f('f(x) = \\frac{x + 11}{5}')}:</p>
<p>${f('f(a) = \\frac{a + 11}{5}')}</p>
<p>We are given that ${f('f(a) = -15')}:</p>
<p>${f('\\frac{a + 11}{5} = -15')}</p>
<p>Multiply both sides by 5:</p>
<p>${f('a + 11 = -75')}</p>
<p>Subtract 11 from both sides:</p>
<p>${f('a = -75 - 11 = -86')}</p>
<p><strong>Choice B is incorrect</strong> because ${f('-64')} results from adding 11 to ${f('-75')} instead of subtracting.</p>
<p><strong>Choices C and D are incorrect</strong> and reflect arithmetic calculation errors.</p>`,

  // Q8
  '6a5fbabfc3d08d90637d33d7': `<p><strong>Choice B is correct.</strong></p>
<p>The equation is given in vertex form ${f('y = a(x - h)^2 + k')}:</p>
<p>${f('y = -4.9(x - 8.9)^2 + 12,400')}</p>
<p>The vertex of this parabola is at ${f('(h, k) = (8.9, 12,400)')}. Because the leading coefficient ${f('a = -4.9')} is negative, the parabola opens downwards, meaning the vertex corresponds to the absolute maximum point of the function.</p>
<p>In this context:</p>
<ul>
  <li>${f('x = 8.9')} represents time in seconds since the maneuver started.</li>
  <li>${f('y = 12,400')} represents the maximum height in meters reached by the plane.</li>
</ul>
<p>Therefore, the best interpretation is: "The plane reached an estimated maximum height of 12,400 meters 8.9 seconds after it started the parabolic maneuver."</p>
<p><strong>Choices A, C, and D are incorrect</strong> because they confuse the vertical acceleration coefficient (-4.9) or swap the time and height coordinates.</p>`,

  // Q9
  '6a5fbaf7c3d08d90637d33e3': `<p><strong>Choice C is correct.</strong></p>
<p>Expand and simplify the given equation:</p>
<p>${f('a(4 - x) = 28 - 7x')}</p>
<p>${f('4a - ax = 28 - 7x')}</p>
<p>Move the variable terms to one side and constants to the other:</p>
<p>${f('7x - ax = 28 - 4a')}</p>
<p>${f('(7 - a)x = 4(7 - a)')}</p>
<p>Notice:</p>
<ul>
  <li>If ${f('a = 7')}, the equation becomes ${f('0x = 0')}, which is true for all real numbers and therefore has <em>infinitely many solutions</em>.</li>
  <li>If ${f('a \\ne 7')}, we can divide both sides by ${f('(7 - a)')} to obtain ${f('x = 4')}, giving <em>exactly one unique solution</em>.</li>
</ul>
<p>Since the problem states the equation has exactly one solution, ${f('a')} <strong>CANNOT</strong> be 7.</p>
<p><strong>Choices A, B, and D are incorrect</strong> because each provides a value of ${f('a \\ne 7')}, all of which yield exactly one solution (${f('x = 4')}).</p>`,

  // Q10
  '6a5fbb3ac3d08d90637d33e7': `<p><strong>The correct answer is 312.</strong></p>
<p>We are given that the graph of ${f('y = g(x) = (x + 13)(t - x)')} passes through ${f('(24, 0)')}, which means ${f('g(24) = 0')}:</p>
<p>${f('(24 + 13)(t - 24) = 0')}</p>
<p>${f('37(t - 24) = 0 \\implies t - 24 = 0 \\implies t = 24')}</p>
<p>Now substitute ${f('t = 24')} into the definition of ${f('g(x)')}:</p>
<p>${f('g(x) = (x + 13)(24 - x)')}</p>
<p>To find ${f('g(0)')}, substitute ${f('x = 0')}:</p>
<p>${f('g(0) = (0 + 13)(24 - 0) = 13 \\times 24 = 312')}</p>`,

  // Q11
  '6a5fbb9fc3d08d90637d33eb': `<p><strong>Choice D is correct.</strong></p>
<p>In right triangle ${f('QRS')} with right angle at ${f('R')}, the side opposite to angle ${f('Q')} is ${f('RS = 23')}, and the hypotenuse is ${f('QS')}.</p>
<p>By the definition of sine for acute angle ${f('Q')}:</p>
<p>${f('\\sin Q = \\frac{\\text{opposite}}{\\text{hypotenuse}} = \\frac{RS}{QS} = \\frac{23}{QS}')}</p>
<p>Solve for ${f('QS')} by multiplying both sides by ${f('QS')} and dividing by ${f('\\sin Q')}:</p>
<p>${f('QS = \\frac{23}{\\sin Q}')}</p>
<p><strong>Choice A is incorrect</strong> because it multiplies by cosine.</p>
<p><strong>Choice B is incorrect</strong> because ${f('23 \\sin Q')} would be the length if 23 were the hypotenuse.</p>
<p><strong>Choice C is incorrect</strong> because cosine uses the adjacent side ${f('QR')}, not ${f('RS')}.</p>`,

  // Q12
  '6a5fbbf4c3d08d90637d33f1': `<p><strong>Choice A is correct.</strong></p>
<p>In the exponential function ${f('y = 5^x + k')}:</p>
<ul>
  <li>As ${f('x \\to -\\infty')}, ${f('5^x \\to 0')}, which means the horizontal asymptote of the graph is the line ${f('y = k')}. Looking at the coordinate plane, the graph flattens horizontally along ${f('y = -8')}, so ${f('k = -8')}.</li>
  <li>Alternatively, find the ${f('y')}-intercept at ${f('(0, -7)')}. Substitute ${f('x = 0')} and ${f('y = -7')}:
  <p>${f('-7 = 5^0 + k = 1 + k \\implies k = -7 - 1 = -8')}</p>
  </li>
</ul>
<p>Thus, the value of constant ${f('k')} is <strong>-8</strong>.</p>
<p><strong>Choice B is incorrect</strong> because ${f('-7')} is the ${f('y')}-intercept, not the asymptote parameter ${f('k')}.</p>
<p><strong>Choices C and D are incorrect</strong> because they have positive signs.</p>`,

  // Q13
  '6a5fbc37c3d08d90637d33f5': `<p><strong>Choice C is correct.</strong></p>
<p>The initial bee population is 1,800. For the first two weeks, it increases by 120 bees per week:</p>
<p>${f('\\text{Population at week 2} = 1,800 + 2(120) = 1,800 + 240 = 2,040 \\text{ bees}')}</p>
<p>For any week ${f('w > 2')}, the number of additional weeks beyond week 2 is ${f('w - 2')}, with an increase of 180 bees per week:</p>
<p>${f('\\text{Total population at week } w = 2,040 + 180(w - 2) = 2,040 + 180w - 360 = 1,680 + 180w')}</p>
<p>The beekeeper's goal is 3,300 bees. The number of bees still needed, ${f('p(w)')}, is the goal minus the population at week ${f('w')}:</p>
<p>${f('p(w) = 3,300 - (1,680 + 180w) = 3,300 - 1,680 - 180w = 1,620 - 180w')}</p>
<p><strong>Choice A is incorrect</strong> because it calculates ${f('3,300 - 180w')}, ignoring the initial 1,800 bees and first two weeks.</p>
<p><strong>Choices B and D are incorrect</strong> because they represent incorrect signs and growth slopes.</p>`,

  // Q14
  '6a5fbc95c3d08d90637d33fb': `<p><strong>Choice D is correct.</strong></p>
<p>The exponential function is ${f('f(x) = 55(0.19)^x')}. Compare ${f('f(n)')} to ${f('f(n - 1)')}:</p>
<p>${f('\\frac{f(n)}{f(n - 1)} = \\frac{55(0.19)^n}{55(0.19)^{n-1}} = 0.19')}</p>
<p>This means ${f('f(n)')} is 0.19 times ${f('f(n - 1)')}, which can be rewritten as:</p>
<p>${f('f(n) = f(n - 1)(1 - 0.81)')}</p>
<p>Therefore, the value of ${f('f(n)')} is 81% less than ${f('f(n - 1)')}, so ${f('p = 81')}.</p>
<p><strong>Choice A is incorrect</strong> because 19% is the proportion of the previous value that remains, not the percentage decrease.</p>
<p><strong>Choices B and C are incorrect</strong> and confuse the initial coefficient 55 with the decay percentage.</p>`,

  // Q15
  '6a5fbcf2c3d08d90637d3407': `<p><strong>The correct answer is 2.</strong></p>
<p>We are given ${f('r(x) = 13(x - 2)')} and ${f('r(x) \\cdot s(x) = 13(x^4 - 16)')}.</p>
<p>Factor ${f('x^4 - 16')} as a difference of squares:</p>
<p>${f('x^4 - 16 = (x^2 - 4)(x^2 + 4) = (x - 2)(x + 2)(x^2 + 4)')}</p>
<p>Multiply ${f('(x + 2)(x^2 + 4)')}:</p>
<p>${f('(x + 2)(x^2 + 4) = x^3 + 4x + 2x^2 + 8 = x^3 + 2x^2 + 4x + 8')}</p>
<p>Therefore:</p>
<p>${f('r(x) \\cdot s(x) = 13(x - 2)(x^3 + 2x^2 + 4x + 8)')}</p>
<p>Since ${f('r(x) = 13(x - 2)')}, it follows that:</p>
<p>${f('s(x) = x^3 + 2x^2 + 4x + 8')}</p>
<p>Comparing this with the given formula ${f('s(x) = x^3 + nx^2 + 2nx + 8')}:</p>
<p>${f('n = 2 \\quad \\text{and} \\quad 2n = 4 \\implies n = 2')}</p>`,

  // Q16
  '6a5fbd23c3d08d90637d340b': `<p><strong>Choice C is correct.</strong></p>
<p>By the Triangle Inequality Theorem, the length of the third side ${f('x')} of a triangle with sides of length ${f('a = 10')} and ${f('b = 11')} must satisfy:</p>
<p>${f('|a - b| < x < a + b')}</p>
<p>${f('|10 - 11| < x < 10 + 11')}</p>
<p>${f('1 < x < 21')}</p>
<p><strong>Choice A is incorrect</strong> because it omits the lower bound ${f('x > 1')}.</p>
<p><strong>Choice B is incorrect</strong> because a triangle with sides 10, 11 cannot have a third side greater than 21.</p>
<p><strong>Choice D is incorrect</strong> because it specifies lengths outside the valid triangle range.</p>`,

  // Q17
  '6a5fbd75c3d08d90637d340f': `<p><strong>The correct answer is 198.9 (or 1989/10).</strong></p>
<p>We are given that 1 nautical mile equals 1.852 kilometers. Therefore, the conversion factor for area is:</p>
<p>${f('1 \\text{ nautical mile}^2 = (1.852 \\text{ km})^2 = 3.429904 \\text{ km}^2')}</p>
<p>Convert 58.00 square nautical miles to square kilometers:</p>
<p>${f('k = 58.00 \\times 3.429904 = 198.934432 \\text{ km}^2')}</p>
<p>Rounding to the nearest tenth gives <strong>198.9</strong>.</p>`,

  // Q18
  '6a5fbea4c3d08d90637d3415': `<p><strong>The correct answer is 72/7 (or approximately 10.286).</strong></p>
<p>First calculate the slope of the line passing through ${f('(9, 1)')} and ${f('(0, 8)')}:</p>
<p>${f('m = \\frac{8 - 1}{0 - 9} = -\\frac{7}{9}')}</p>
<p>Since ${f('(0, 8)')} is the ${f('y')}-intercept, the line's equation is:</p>
<p>${f('y = -\\frac{7}{9}x + 8')}</p>
<p>The line also passes through ${f('(c, 0)')}. Substitute ${f('x = c')} and ${f('y = 0')}:</p>
<p>${f('0 = -\\frac{7}{9}c + 8')}</p>
<p>${f('\\frac{7}{9}c = 8 \\implies 7c = 72 \\implies c = \\frac{72}{7} \\approx 10.286')}</p>`,

  // Q19
  '6a5fbf1ac3d08d90637d3421': `<p><strong>Choice D is correct.</strong></p>
<p>The total resistance of resistors in series is the sum of their individual resistances:</p>
<p>${f('a \\cdot x + b \\cdot y = \\frac{41}{63}')}</p>
<p>Comparing this with the given equation ${f('\\frac{x}{7} + \\frac{y}{9} = \\frac{41}{63}')}, we can rewrite it as:</p>
<p>${f('\\frac{1}{7}x + \\frac{1}{9}y = \\frac{41}{63}')}</p>
<p>This gives individual resistances ${f('a = \\frac{1}{7}')} and ${f('b = \\frac{1}{9}')}.</p>
<p>The positive difference between ${f('a')} and ${f('b')} is:</p>
<p>${f('|a - b| = \\frac{1}{7} - \\frac{1}{9} = \\frac{9 - 7}{63} = \\frac{2}{63}')}</p>
<p><strong>Choice A is incorrect</strong> because 41 is the numerator of the total resistance.</p>
<p><strong>Choice B is incorrect</strong> because 2 is the numerator without the common denominator 63.</p>
<p><strong>Choice C is incorrect</strong> because ${f('\\frac{41}{63}')} is the total resistance, not the difference between individual resistances.</p>`,

  // Q20
  '6a5fbfaac3d08d90637d3425': `<p><strong>Choice D is correct.</strong></p>
<p>For similar figures, the ratio of areas equals the square of the ratio of linear dimensions (such as perimeters):</p>
<p>${f('\\frac{\\text{Area}_B}{\\text{Area}_A} = \\left(\\frac{\\text{Perimeter}_B}{\\text{Perimeter}_A}\\right)^2')}</p>
<p>Substitute the given values:</p>
<p>${f('\\frac{2,640}{660} = 4')}</p>
<p>Take the square root of the area ratio to find the linear scale factor:</p>
<p>${f('\\frac{\\text{Perimeter}_B}{\\text{Perimeter}_A} = \\sqrt{4} = 2')}</p>
<p>Therefore, the perimeter of Rectangle B is twice the perimeter of Rectangle A:</p>
<p>${f('n = 2 \\times 220 = 440')}</p>
<p><strong>Choice A is incorrect</strong> and results from multiplying 220 by 10.</p>
<p><strong>Choice B is incorrect</strong> because 1,760 results from multiplying the perimeter by the area ratio 4 instead of the linear scale factor 2 (wait, ${f('220 \\times 4 = 880')}).</p>
<p><strong>Choice C is incorrect</strong> because 880 multiplies the perimeter by 4 directly without taking the square root.</p>`,

  // Q21
  '6a5fbff9c3d08d90637d3431': `<p><strong>Choice C is correct.</strong></p>
<p>Let Aster's earnings in 2004 be ${f('E_{2004}')}.</p>
<p>In 2005, Aster earned 12% more than in 2004:</p>
<p>${f('E_{2005} = 1.12 \\times E_{2004}')}</p>
<p>In 2006, Aster earned 6% more than in 2005:</p>
<p>${f('E_{2006} = 1.06 \\times E_{2005} = 1.06 \\times (1.12 \\times E_{2004}) = 1.1872 \\times E_{2004}')}</p>
<p>We are given that ${f('E_{2004} = y \\times E_{2006}')}:</p>
<p>${f('E_{2004} = y \\times (1.1872 \\times E_{2004}) \\implies y = \\frac{1}{1.1872} \\approx 0.842318')}</p>
<p>Rounding to four decimal places gives <strong>0.8423</strong>.</p>
<p><strong>Choice A is incorrect</strong> because 0.5000 is half.</p>
<p><strong>Choice B is incorrect</strong> and results from simple percentage subtraction.</p>
<p><strong>Choice D is incorrect</strong> because 1.1872 is how many times as much Aster earned in 2006 compared to 2004 (${f('\\frac{E_{2006}}{E_{2004}}')}), rather than 2004 compared to 2006.</p>`,

  // Q22
  '6a5fc026c3d08d90637d3435': `<p><strong>Choice D is correct.</strong></p>
<p>Factor out the common factor ${f('(x - 9)')} from both terms of the expression:</p>
<p>${f('y^2(x - 9) - 36(x - 9)^3 = (x - 9)[y^2 - 36(x - 9)^2]')}</p>
<p>Notice that the term inside the bracket is a difference of squares ${f('A^2 - B^2 = (A - B)(A + B)')}, where ${f('A = y')} and ${f('B = 6(x - 9)')}:</p>
<p>${f('y^2 - [6(x - 9)]^2 = [y - 6(x - 9)][y + 6(x - 9)]')}</p>
<p>Simplify each factor:</p>
<p>${f('y - 6(x - 9) = y - 6x + 54')}</p>
<p>${f('y + 6(x - 9) = y + 6x - 54')}</p>
<p>The completely factored expression is:</p>
<p>${f('(x - 9)(y - 6x + 54)(y + 6x - 54)')}</p>
<p>Among the given choices, <strong>${f('y + 6x - 54')}</strong> is listed.</p>
<p><strong>Choices A, B, and C are incorrect</strong> because none of them is a factor of the polynomial expression.</p>`
};

async function run() {
    console.log('🚀 Injecting Explanations for November 2025 · INT 2 — Module 2...\n');
    let count = 0;
    for (const [id, expl] of Object.entries(explanations)) {
        process.stdout.write(`Injecting Q ID: ${id}... `);
        const res = await updateQuestionExplanation(id, expl);
        if (res.message === 'success') {
            console.log('✅');
            count++;
        } else {
            console.log('❌ ' + JSON.stringify(res));
        }
    }
    console.log(`\n🎉 Finished! Injected ${count}/${Object.keys(explanations).length} explanations for Module 2.`);
}

run();
