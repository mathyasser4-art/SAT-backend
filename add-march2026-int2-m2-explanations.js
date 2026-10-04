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
  '6a53e3784d554e04aa1bf9ec': `<p><strong>The correct answer is 18.</strong></p>
<p>The problem states that the value of the exponential function ${f('g(x)')} doubles for every increase of 2 in the value of ${f('x')}.</p>
<p>When ${f('x')} increases from 4 to 6, the change in ${f('x')} is ${f('6 - 4 = 2')}.</p>
<p>Therefore, ${f('g(6)')} is double the value of ${f('g(4)')}:</p>
<p>${f('g(6) = 2 \\times g(4) = 2 \\times 9 = 18')}</p>`,

  // Q2
  '6a53e4a44d554e04aa1bf9f2': `<p><strong>Choice D is correct.</strong></p>
<p>The variable ${f('x')} represents the number of months since December 2013. December 2014 occurs exactly 12 months after December 2013, so ${f('x = 12')}.</p>
<p>Locating ${f('x = 12')} on the horizontal axis and moving vertically to the line on the graph, the corresponding ${f('y')}-value is approximately <strong>91</strong> (just above 90).</p>
<p><strong>Choices A, B, and C are incorrect</strong> because 61, 71, and 81 correspond to much earlier or later points on the linear model.</p>`,

  // Q3
  '6a53e5604d554e04aa1bf9fc': `<p><strong>Choice D is correct.</strong></p>
<p>The line has a slope of ${f('m = -\\frac{4}{7}')} and passes through ${f('(0, 12)')}, which is the ${f('y')}-intercept (${f('b = 12')}).</p>
<p>Using the slope-intercept form ${f('y = mx + b')}:</p>
<p>${f('y = -\\frac{4}{7}x + 12')}</p>
<p>To find the ${f('x')}-intercept, set ${f('y = 0')} and solve for ${f('x')}:</p>
<p>${f('0 = -\\frac{4}{7}x + 12')}</p>
<p>${f('\\frac{4}{7}x = 12 \\implies 4x = 84 \\implies x = 21')}</p>
<p>Therefore, the ${f('x')}-intercept is ${f('(21, 0)')}.</p>
<p><strong>Choice A is incorrect</strong> because it has the wrong sign (${f('-21, 0')}).</p>
<p><strong>Choices B and C are incorrect</strong> and result from using coordinates of the slope fraction directly.</p>`,

  // Q4
  '6a53e61d4d554e04aa1bfa12': `<p><strong>Choice B is correct.</strong></p>
<p>First, find the equation of the boundary line:</p>
<ul>
  <li>The line crosses the ${f('y')}-axis at ${f('(0, 1)')}, so the ${f('y')}-intercept is ${f('b = 1')}.</li>
  <li>It also passes through the point ${f('(1, 5)')}. The slope is ${f('m = \\frac{5 - 1}{1 - 0} = 4')}.</li>
</ul>
<p>Thus, the boundary line has the equation ${f('y = 4x + 1')}.</p>
<p>Since the boundary line is dashed and the shaded region lies below the line, the appropriate inequality is ${f('y < 4x + 1')}.</p>
<p>Testing the origin ${f('(0, 0)')}, which lies in the shaded region:</p>
<p>${f('0 < 4(0) + 1 \\implies 0 < 1')} (true).</p>
<p><strong>Choice A is incorrect</strong> because it has a slope of ${f('\\frac{1}{4}')}.</p>
<p><strong>Choices C and D are incorrect</strong> because they use ${f('>')} (shaded above the line).</p>`,

  // Q5
  '6a53e72c4d554e04aa1bfa18': `<p><strong>Choice A is correct.</strong></p>
<p>The given system consists of two linear equations in slope-intercept form:</p>
<p>${f('y = 5x + 18')}</p>
<p>${f('y = 5x - 18')}</p>
<p>Both equations have the identical slope of ${f('m = 5')}, but different ${f('y')}-intercepts (${f('18 \\ne -18')}).</p>
<p>Lines with the same slope and different ${f('y')}-intercepts are parallel and never intersect. Therefore, the system has <strong>zero</strong> solutions.</p>
<p><strong>Choices B, C, and D are incorrect</strong> because parallel lines never intersect at one, two, or infinitely many points.</p>`,

  // Q6
  '6a53e79d4d554e04aa1bfa20': `<p><strong>Choice B is correct.</strong></p>
<p>In right triangle ${f('ABC')} with right angle at ${f('B')}, acute angles ${f('A')} and ${f('C')} are complementary (${f('A + C = 90^\\circ')}).</p>
<p>By the complementary angle trigonometric identity, the sine of an acute angle equals the cosine of its complement:</p>
<p>${f('\\sin C = \\cos(90^\\circ - C) = \\cos A')}</p>
<p>Since ${f('\\cos A = 0.65')}, it follows directly that:</p>
<p>${f('\\sin C = 0.65')}</p>
<p><strong>Choice A is incorrect</strong> because 0.87 is approximately ${f('\\sin A')}.</p>
<p><strong>Choice C is incorrect</strong> because ${f('0.35 = 1 - 0.65')}, which confuses complementary angles with complementary probabilities.</p>
<p><strong>Choice D is incorrect</strong> and reflects an arithmetic error.</p>`,

  // Q7
  '6a53f28d4d554e04aa1bfa39': `<p><strong>The correct answer is 13/5 (or 2.6).</strong></p>
<p>Using the definition ${f('f(x) = 3x - 7')}, evaluate ${f('f(b)')}:</p>
<p>${f('f(b) = 3b - 7')}</p>
<p>We are given that ${f('f(b) = \\frac{4}{5}')}:</p>
<p>${f('3b - 7 = \\frac{4}{5}')}</p>
<p>Add 7 to both sides:</p>
<p>${f('3b = 7 + \\frac{4}{5} = \\frac{35}{5} + \\frac{4}{5} = \\frac{39}{5}')}</p>
<p>Divide both sides by 3:</p>
<p>${f('b = \\frac{39}{5 \\times 3} = \\frac{13}{5} = 2.6')}</p>`,

  // Q8
  '6a53f2fc4d554e04aa1bfa47': `<p><strong>Choice B is correct.</strong></p>
<p>Simplify and solve the linear equation:</p>
<p>${f('97 - x + 5 = 95')}</p>
<p>Combine like constant terms on the left side:</p>
<p>${f('102 - x = 95')}</p>
<p>Subtract 102 from both sides:</p>
<p>${f('-x = 95 - 102 = -7')}</p>
<p>Multiply both sides by ${f('-1')}:</p>
<p>${f('x = 7')}</p>
<p><strong>Choice A is incorrect</strong> because 14 is ${f('2 \\times 7')}.</p>
<p><strong>Choices C and D are incorrect</strong> and result from sign errors during isolation.</p>`,

  // Q9
  '6a53f3604d554e04aa1bfa4d': `<p><strong>Choice B is correct.</strong></p>
<p>To display the minimum value of a quadratic function as a constant or coefficient, rewrite the function in vertex form ${f('f(x) = a(x - h)^2 + k')}, where ${f('k')} is the minimum value when ${f('a > 0')}.</p>
<p>Complete the square for ${f('f(x) = x^2 - 4x - 780')}:</p>
<p>${f('f(x) = (x^2 - 4x + 4) - 4 - 780')}</p>
<p>${f('f(x) = (x - 2)^2 - 784')}</p>
<p>In this form, the vertex is ${f('(2, -784)')}, and the minimum value ${f('-784')} appears explicitly as a constant.</p>
<p><strong>Choice A is incorrect</strong> because ${f('f(x) = (x + 26)(x - 30)')} is the factored form, which displays the ${f('x')}-intercepts (${f('-26')} and ${f('30')}), not the minimum value.</p>
<p><strong>Choice C is incorrect</strong> because it is not in vertex form.</p>
<p><strong>Choice D is incorrect</strong> because it is not equivalent to the given function.</p>`,

  // Q10
  '6a53f44b4d554e04aa1bfa5f': `<p><strong>The correct answer is -36.</strong></p>
<p>The given equation is ${f('y = 6x^2 + bx + c')}.</p>
<p>From the graph, the ${f('y')}-intercept is at ${f('(0, -3)')}. Substituting ${f('x = 0')} into the equation gives:</p>
<p>${f('c = -3')}</p>
<p>The parabola passes through ${f('(1, 15)')} and has vertex/roots consistent with ${f('b = 12')}:</p>
<p>Checking ${f('y = 6x^2 + 12x - 3')}:</p>
<ul>
  <li>At ${f('x = 0')}, ${f('y = -3')}.</li>
  <li>Vertex occurs at ${f('x = -\\frac{b}{2a} = -\\frac{12}{12} = -1')}, where ${f('y = 6(-1)^2 + 12(-1) - 3 = 6 - 12 - 3 = -9')}, matching the graph.</li>
</ul>
<p>Now evaluate the product ${f('bc')}:</p>
<p>${f('bc = 12 \\times (-3) = -36')}</p>`,

  // Q11
  '6a53f4f74d554e04aa1bfa73': `<p><strong>The correct answer is 72/7 (or approximately 10.286).</strong></p>
<p>Find the slope ${f('m')} of the line using the two known points ${f('(9, 1)')} and ${f('(0, 8)')}:</p>
<p>${f('m = \\frac{8 - 1}{0 - 9} = -\\frac{7}{9}')}</p>
<p>Since the line crosses the ${f('y')}-axis at ${f('(0, 8)')}, its equation in slope-intercept form is:</p>
<p>${f('y = -\\frac{7}{9}x + 8')}</p>
<p>The line also passes through ${f('(c, 0)')}. Substitute ${f('x = c')} and ${f('y = 0')}:</p>
<p>${f('0 = -\\frac{7}{9}c + 8')}</p>
<p>${f('\\frac{7}{9}c = 8 \\implies 7c = 72 \\implies c = \\frac{72}{7} \\approx 10.286')}</p>`,

  // Q12
  '6a53f5514d554e04aa1bfa7b': `<p><strong>Choice C is correct.</strong></p>
<p>The deck has an area of ${f('d')} square feet. Covering the deck twice means the total area to be sealed is ${f('2d')} square feet.</p>
<p>Since one gallon covers 350 square feet, the number of gallons needed is:</p>
<p>${f('\\text{Gallons} = \\frac{2d}{350} = \\frac{d}{175}')}</p>
<p>At a cost of $19 per gallon, the total cost ${f('c')} is:</p>
<p>${f('c = 19 \\times \\frac{d}{175} = \\frac{19d}{175}')}</p>
<p><strong>Choice A is incorrect</strong> because it inverts the ratio.</p>
<p><strong>Choice B is incorrect</strong> because it calculates ${f('\\frac{700d}{19}')}, which inverts and doubles the coverage.</p>
<p><strong>Choice D is incorrect</strong> because ${f('\\frac{19d}{350}')} is the cost to cover the deck only once.</p>`,

  // Q13
  '6a53f5f94d554e04aa1bfa8b': `<p><strong>Choice A is correct.</strong></p>
<p>An increase of 166% corresponds to a growth multiplier of:</p>
<p>${f('1 + 1.66 = 2.66')}</p>
<p>A subsequent decrease of 14% corresponds to a decay multiplier of:</p>
<p>${f('1 - 0.14 = 0.86')}</p>
<p>The overall multiplier from the end of 2011 to the end of 2013 is the product of the two multipliers:</p>
<p>${f('2.66 \\times 0.86 = 2.2876')}</p>
<p>To convert this multiplier back to a net percentage change, subtract 1 and multiply by 100%:</p>
<p>${f('(2.2876 - 1) \\times 100\\% = 1.2876 \\times 100\\% = 128.76\\%')}</p>
<p><strong>Choice B is incorrect</strong> because 142.76% results from subtracting 14% from 166% without compound scaling.</p>
<p><strong>Choice C is incorrect</strong> because ${f('166\\% - 14\\% = 152.00\\%')}, which incorrectly treats percentages as simple additive values.</p>
<p><strong>Choice D is incorrect</strong> and results from multiplying 2.66 by 1.14 instead of 0.86.</p>`,

  // Q14
  '6a53f67e4d554e04aa1bfaa6': `<p><strong>Choice C is correct.</strong></p>
<p>Rewrite the quadratic equation in standard form ${f('ax^2 + bx + c = 0')}:</p>
<p>${f('4x^2 - px + (w + 83) = 0')}</p>
<p>A quadratic equation has exactly one real solution if and only if its discriminant ${f('D = b^2 - 4ac')} equals zero:</p>
<p>${f('(-p)^2 - 4(4)(w + 83) = 0 \\implies p^2 = 16(w + 83)')}</p>
<p>Since ${f('p')} is an integer, ${f('p^2')} is a perfect square, which requires ${f('16(w + 83)')} to be a perfect square. Thus, ${f('w + 83')} must be a perfect square integer ${f('k^2 \\ge 0')}.</p>
<p>Test each choice:</p>
<ul>
  <li>If ${f('w = -19')}: ${f('-19 + 83 = 64 = 8^2')} (possible).</li>
  <li>If ${f('w = 17')}: ${f('17 + 83 = 100 = 10^2')} (possible).</li>
  <li>If ${f('w = 317')}: ${f('317 + 83 = 400 = 20^2')} (possible).</li>
  <li>If ${f('w = 36')}: ${f('36 + 83 = 119')}, which is NOT a perfect square.</li>
</ul>
<p>Therefore, 36 is NOT a possible value of ${f('w')}.</p>`,

  // Q15
  '6a53f72d4d554e04aa1bfab2': `<p><strong>The correct answer is 28.2 (or 141/5).</strong></p>
<p>The given rate is ${f('12.60 \\text{ m/s}^2')}. We convert this into miles per minute squared:</p>
<ol>
  <li>Convert meters to miles using ${f('1 \\text{ mile} = 1,609 \\text{ meters}')}:
  <p>${f('12.60 \\text{ m/s}^2 = \\frac{12.60}{1,609} \\text{ miles/s}^2')}</p>
  </li>
  <li>Convert seconds squared to minutes squared using ${f('1 \\text{ min} = 60 \\text{ s} \\implies 1 \\text{ s} = \\frac{1}{60} \\text{ min} \\implies 1 \\text{ s}^2 = \\frac{1}{3,600} \\text{ min}^2')}:
  <p>${f('\\text{Rate} = \\frac{12.60}{1,609} \\times 3,600 = \\frac{45,360}{1,609} \\approx 28.1914 \\text{ miles/min}^2')}</p>
  </li>
</ol>
<p>Rounding to the nearest tenth gives <strong>28.2</strong>.</p>`,

  // Q16
  '6a53f7b94d554e04aa1bfac4': `<p><strong>Choice B is correct.</strong></p>
<p>The total volume of the resulting mixture is ${f('x + y')} liters.</p>
<p>The amount of saline in ${f('x')} liters of 6% solution is ${f('0.06x')}, and in ${f('y')} liters of 9% solution is ${f('0.09y')}.</p>
<p>The total saline in the 7% mixture of volume ${f('x + y')} is ${f('0.07(x + y)')}.</p>
<p>Equating the amounts of saline gives:</p>
<p>${f('0.06x + 0.09y = 0.07(x + y)')}</p>
<p><strong>Choice A is incorrect</strong> because it uses 7 instead of 0.07.</p>
<p><strong>Choices C and D are incorrect</strong> because they use 0.6 and 0.9 (60% and 90%) instead of 0.06 and 0.09.</p>`,

  // Q17
  '6a53f8424d554e04aa1bfae2': `<p><strong>The correct answer is 147.</strong></p>
<p>Expand the expression using the distributive property:</p>
<p>${f('3x(57x - 8) = 3x \\times 57x - 3x \\times 8 = 171x^2 - 24x')}</p>
<p>Comparing this to ${f('ax^2 + bx + c')}:</p>
<p>${f('a = 171, \\quad b = -24, \\quad c = 0')}</p>
<p>The value of ${f('a + b')} is:</p>
<p>${f('a + b = 171 + (-24) = 147')}</p>`,

  // Q18
  '6a53f8a94d554e04aa1bfaee': `<p><strong>Choice B is correct.</strong></p>
<p>The area of a rectangle is length times width:</p>
<p>${f('\\text{Area} = x(x - 3) = 28')}</p>
<p>${f('x^2 - 3x - 28 = 0')}</p>
<p>Factor the quadratic equation:</p>
<p>${f('(x - 7)(x + 4) = 0')}</p>
<p>This gives solutions ${f('x = 7')} or ${f('x = -4')}. Since the length of a rectangle must be positive, ${f('x = 7')}.</p>
<p><strong>Choice A is incorrect</strong> because ${f('x = 4')} gives an area of ${f('4(4 - 3) = 4 \\ne 28')}.</p>
<p><strong>Choices C and D are incorrect</strong> because ${f('11(8) = 88 \\ne 28')} and ${f('28(25) = 700 \\ne 28')}.</p>`,

  // Q19
  '6a53f9b04d554e04aa1bfb02': `<p><strong>The correct answer is -3.</strong></p>
<p>The condition "a number ${f('x')} is at most 27 less than 3 times ${f('y')}" translates into the inequality:</p>
<p>${f('x \\le 3y - 27')}</p>
<p>Substitute ${f('y = 8')}:</p>
<p>${f('x \\le 3(8) - 27')}</p>
<p>${f('x \\le 24 - 27')}</p>
<p>${f('x \\le -3')}</p>
<p>The greatest possible value of ${f('x')} is <strong>-3</strong>.</p>`,

  // Q20
  '6a53fa1a4d554e04aa1bfb12': `<p><strong>Choice A is correct.</strong></p>
<p>From the sample of 370 scales, the estimated percentage of inaccurate scales is 9% with an associated margin of error of 2.9%.</p>
<p>The plausible range for the percentage of inaccurate scales in the entire population is:</p>
<p>${f('9\\% - 2.9\\% = 6.1\\% \\quad \\text{to} \\quad 9\\% + 2.9\\% = 11.9\\%')}</p>
<p>Apply these bounds to the total population of 8,000 scales:</p>
<ul>
  <li>Lower bound: ${f('0.061 \\times 8,000 = 488')} scales</li>
  <li>Upper bound: ${f('0.119 \\times 8,000 = 952')} scales</li>
</ul>
<p>Therefore, it is plausible that between 488 and 952 of the scales in the population are inaccurate.</p>
<p><strong>Choices B and D are incorrect</strong> because values below 488 or above 952 lie outside the margin of error confidence interval.</p>
<p><strong>Choice C is incorrect</strong> because sample estimates with margins of error cannot guarantee an exact count of 720.</p>`,

  // Q21
  '6a53fabb4d554e04aa1bfb20': `<p><strong>Choice D is correct.</strong></p>
<p>The sum of the angles in triangle ${f('JKL')} is ${f('180^\\circ')}:</p>
<p>${f('90b + 66a + 24a = 180 \\implies 90b + 90a = 180 \\implies b + a = 2')}</p>
<p>The sum of angles ${f('K')} and ${f('L')} is:</p>
<p>${f('\\angle K + \\angle L = 66a + 24a = 90a^\\circ')}</p>
<p>If ${f('a = 1')} (which means ${f('b = 1')}), then ${f('\\angle K + \\angle L = 90^\\circ')}, making ${f('K')} and ${f('L')} complementary angles, so ${f('\\cos L = \\sin K')}.</p>
<p>However, if ${f('a = 0.5')} (and ${f('b = 1.5')}), then ${f('\\angle K = 33^\\circ')} and ${f('\\angle L = 12^\\circ')}. In this case, ${f('\\cos(12^\\circ) \\approx 0.978')} while ${f('\\sin(33^\\circ) \\approx 0.545')}, so ${f('\\cos L > \\sin K')}.</p>
<p>Since the values of ${f('a')} and ${f('b')} are not fixed, it cannot be determined whether ${f('\\cos L')} is equal to, greater than, or less than ${f('\\sin K')}. Thus, there is not enough information to compare them.</p>
<p><strong>Choices A, B, and C are incorrect</strong> because none must hold for all valid values of constants ${f('a')} and ${f('b')}.</p>`,

  // Q22
  '6a53fb134d554e04aa1bfb2c': `<p><strong>Choice C is correct.</strong></p>
<p>Rewrite the quadratic equation in standard form ${f('ax^2 + bx + c = 0')}:</p>
<p>${f('4x^2 - px + (w + 85) = 0')}</p>
<p>A quadratic equation has exactly one real solution if and only if its discriminant is zero:</p>
<p>${f('(-p)^2 - 4(4)(w + 85) = 0 \\implies p^2 = 16(w + 85)')}</p>
<p>Because ${f('p')} is an integer, ${f('p^2')} must be a non-negative perfect square. Dividing by 16, ${f('w + 85')} must also be a perfect square integer ${f('k^2 \\ge 0')}.</p>
<p>Test each given choice for ${f('w')}:</p>
<ul>
  <li>If ${f('w = -21')}: ${f('-21 + 85 = 64 = 8^2')} (possible).</li>
  <li>If ${f('w = 15')}: ${f('15 + 85 = 100 = 10^2')} (possible).</li>
  <li>If ${f('w = 315')}: ${f('315 + 85 = 400 = 20^2')} (possible).</li>
  <li>If ${f('w = 64')}: ${f('64 + 85 = 149')}, which is NOT a perfect square.</li>
</ul>
<p>Therefore, 64 is NOT a possible value of ${f('w')}.</p>`
};

async function run() {
    console.log('🚀 Injecting Explanations for March 2026 · INT 2 — Module 2...\n');
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
