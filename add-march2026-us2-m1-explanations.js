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
  '6a52d4d14d554e04aa1bf38c': `<p><strong>Choice A is correct.</strong></p>
<p>The function is given by ${f('f(x) = 23(1.20)^{x/8}')}.</p>
<p>To determine the percentage change in ${f('f(x)')} when ${f('x')} increases by 8, compare ${f('f(x + 8)')} to ${f('f(x)')}:</p>
<p>${f('\\frac{f(x + 8)}{f(x)} = \\frac{23(1.20)^{(x + 8)/8}}{23(1.20)^{x/8}} = \\frac{23(1.20)^{x/8} \\cdot (1.20)^{8/8}}{23(1.20)^{x/8}} = (1.20)^1 = 1.20')}</p>
<p>A multiplicative growth factor of 1.20 corresponds to:</p>
<p>${f('1.20 = 1 + 0.20 = 1 + \\frac{20}{100}')}</p>
<p>This represents a 20% increase for every increase of ${f('x')} by 8. Therefore, the value of ${f('p')} is 20.</p>
<p><strong>Choice B is incorrect</strong> and may result from misidentifying coefficients.</p>
<p><strong>Choices C and D are incorrect</strong> and may result from miscalculating the growth factor over different intervals.</p>`,

  // Q2
  '6a52d5b34d554e04aa1bf39a': `<p><strong>Choice A is correct.</strong></p>
<p>The problem states that the number of trees decreases by 21% for each 1-inch increase in diameter ${f('x')}.</p>
<p>The decay factor ${f('b')} is:</p>
<p>${f('b = 1 - 0.21 = 0.79')}</p>
<p>Thus, the model has the form ${f('f(x) = a(0.79)^x')}.</p>
<p>We are given that there are 3,100 trees with a diameter of 13 inches, so ${f('f(13) = 3100')}:</p>
<p>${f('a(0.79)^{13} = 3100')}</p>
<p>Solving for ${f('a')}:</p>
<p>${f('a = \\frac{3100}{(0.79)^{13}} \\approx \\frac{3100}{0.046985} \\approx 66000')}</p>
<p>Therefore, the model is ${f('f(x) = 66000 \\cdot 0.79^x')}.</p>
<p><strong>Choice B is incorrect</strong> because it uses 0.21 as the base rather than the decay factor 0.79.</p>
<p><strong>Choice C is incorrect</strong> because it uses 3,100 as the initial coefficient ${f('a')}, which is the value at ${f('x = 13')}, not ${f('x = 0')}.</p>
<p><strong>Choice D is incorrect</strong> because it uses 0.21 instead of 0.79.</p>`,

  // Q3
  '6a52d69a4d554e04aa1bf3a4': `<p><strong>Choice B is correct.</strong></p>
<p>We can identify the correct linear equation by testing points along the line of best fit:</p>
<p>• At ${f('t = 240')}, the line passes near ${f('d \\approx 420')}.</p>
<p>• At ${f('t = 260')}, the line passes near ${f('d \\approx 460')}.</p>
<p>Let us test the equation in Choice B (${f('d = -60.1 + 2.0t')}):</p>
<p>${f('d = -60.1 + 2.0(240) = -60.1 + 480 = 419.9 \\approx 420')}</p>
<p>${f('d = -60.1 + 2.0(260) = -60.1 + 520 = 459.9 \\approx 460')}</p>
<p>This matches the plotted line of best fit extremely accurately.</p>
<p><strong>Choices A, C, and D are incorrect</strong> because their positive intercepts combined with a positive slope would predict values of ${f('d')} exceeding 800 at ${f('t = 240')}, which is far off the graph.</p>`,

  // Q4
  '6a52d8864d554e04aa1bf3b8': `<p><strong>Choice A is correct.</strong></p>
<p>The function is defined by ${f('f(x) = a^x - b')}. Since the graph passes through ${f('(c, 11)')} and ${f('(2c, 221)')}:</p>
<p>1. ${f('a^c - b = 11 \\implies a^c = b + 11')}</p>
<p>2. ${f('a^{2c} - b = 221 \\implies (a^c)^2 - b = 221')}</p>
<p>Substitute ${f('a^c = b + 11')} into the second equation:</p>
<p>${f('(b + 11)^2 - b = 221')}</p>
<p>${f('b^2 + 22b + 121 - b = 221')}</p>
<p>${f('b^2 + 21b - 100 = 0')}</p>
<p>Factor the quadratic equation:</p>
<p>${f('(b + 25)(b - 4) = 0')}</p>
<p>This gives solutions ${f('b = 4')} or ${f('b = -25')}. Among the given answer choices, 4 is an option.</p>
<p>Checking ${f('b = 4')}: ${f('a^c = 4 + 11 = 15 > 0')}, which is valid for an exponential base.</p>
<p><strong>Choices B, C, and D are incorrect</strong> because they do not satisfy the quadratic system formed by the two points.</p>`,

  // Q5
  '6a52da814d554e04aa1bf3c4': `<p><strong>Choice A is correct.</strong></p>
<p>Two triangles are similar by the Side-Angle-Side (SAS) similarity criterion if two pairs of corresponding sides are proportional and their included angles are congruent.</p>
<p>We are given that ${f('\\angle A = 56^\\circ')} and ${f('\\angle P = 56^\\circ')}, so the included angles are congruent (${f('\\angle A \\cong \\angle P')}).</p>
<p>The given side lengths adjacent to these angles are ${f('AC = 30')} and ${f('PR = 90')}, which have a ratio of:</p>
<p>${f('\\frac{PR}{AC} = \\frac{90}{30} = 3')}</p>
<p>If ${f('AB = 10')} and ${f('PQ = 30')}, the ratio of the other adjacent sides is:</p>
<p>${f('\\frac{PQ}{AB} = \\frac{30}{10} = 3')}</p>
<p>Since the ratios of the adjacent sides are equal (${f('\\frac{PR}{AC} = \\frac{PQ}{AB} = 3')}) and the included angle is congruent (${f('\\angle A = \\angle P = 56^\\circ')}), ${f('\\triangle ABC')} is similar to ${f('\\triangle PQR')} by SAS similarity.</p>
<p><strong>Choices B, C, and D are incorrect</strong> because they do not satisfy the required side proportionality or proper angle pairings.</p>`,

  // Q6
  '6a52e1af4d554e04aa1bf406': `<p><strong>The correct answer is 20.</strong></p>
<p>For a quadratic equation in standard form ${f('ax^2 + bx + c = 0')}, Vieta's formulas state that the product of the solutions is given by:</p>
<p>${f('\\text{Product of solutions} = \\frac{c}{a}')}</p>
<p>In the given equation ${f('x^2 + 6x + k = 0')}, we have ${f('a = 1')}, ${f('b = 6')}, and ${f('c = k')}:</p>
<p>${f('\\text{Product} = \\frac{k}{1} = k')}</p>
<p>We are given that the product of the solutions is 20. Therefore, ${f('k = 20')}.</p>`,

  // Q7
  '6a52e25a4d554e04aa1bf40c': `<p><strong>Choice C is correct.</strong></p>
<p>Rewrite the quadratic equation in standard form ${f('ax^2 + bx + c = 0')}:</p>
<p>${f('4x^2 - px + w = -86')}</p>
<p>${f('4x^2 - px + (w + 86) = 0')}</p>
<p>A quadratic equation has exactly one real solution if and only if its discriminant ${f('\\Delta = b^2 - 4ac')} equals 0:</p>
<p>${f('(-p)^2 - 4(4)(w + 86) = 0')}</p>
<p>${f('p^2 - 16(w + 86) = 0')}</p>
<p>${f('p^2 = 16(w + 86)')}</p>
<p>Since ${f('p')} is an integer, ${f('p^2')} is a perfect square. Because ${f('16 = 4^2')} is already a perfect square, ${f('w + 86')} must also be a perfect square of an integer.</p>
<p>Let us test the given choices for ${f('w')}:</p>
<p>• If ${f('w = -22')}: ${f('-22 + 86 = 64 = 8^2')} (a perfect square, so possible)</p>
<p>• If ${f('w = 14')}: ${f('14 + 86 = 100 = 10^2')} (a perfect square, so possible)</p>
<p>• If ${f('w = 314')}: ${f('314 + 86 = 400 = 20^2')} (a perfect square, so possible)</p>
<p>• If ${f('w = 25')}: ${f('25 + 86 = 111')}, which is NOT a perfect square.</p>
<p>Therefore, 25 is NOT a possible value of ${f('w')}.</p>`,

  // Q8
  '6a52e2fb4d554e04aa1bf418': `<p><strong>Choice A is correct.</strong></p>
<p>We are given the equation:</p>
<p>${f('\\frac{x + 6}{5} = \\frac{x + 6}{13}')}</p>
<p>Subtract ${f('\\frac{x + 6}{13}')} from both sides:</p>
<p>${f('\\frac{x + 6}{5} - \\frac{x + 6}{13} = 0')}</p>
<p>Factor out ${f('(x + 6)')}:</p>
<p>${f('(x + 6)\\left(\\frac{1}{5} - \\frac{1}{13}\\right) = 0')}</p>
<p>Since ${f('\\frac{1}{5} - \\frac{1}{13} = \\frac{8}{65} \\ne 0')}, we must have:</p>
<p>${f('x + 6 = 0')}</p>
<p>Thus, the value of ${f('x + 6')} is 0. The value 0 lies strictly between -2 and 2.</p>
<p><strong>Choices B, C, and D are incorrect</strong> because 0 does not fall within their intervals.</p>`,

  // Q9
  '6a52e3b64d554e04aa1bf41e': `<p><strong>The correct answer is 17/2 (or 8.5).</strong></p>
<p>We are given that ${f('6x^4 + 17x^2 + 7')} can be rewritten in two factored forms:</p>
<p>1. <strong>Factorization with positive integers ${f('a')} and ${f('b')}:</strong></p>
<p>${f('(3x^2 + a)(2x^2 + b) = 6x^4 + (3b + 2a)x^2 + ab')}</p>
<p>Comparing coefficients with ${f('6x^4 + 17x^2 + 7')}:</p>
<p>• ${f('ab = 7')}</p>
<p>• ${f('2a + 3b = 17')}</p>
<p>Since ${f('a')} and ${f('b')} are positive integers and 7 is prime, either ${f('a = 1, b = 7')} or ${f('a = 7, b = 1')}:</p>
<p>If ${f('a = 7, b = 1')}: ${f('2(7) + 3(1) = 14 + 3 = 17')}, which satisfies the condition. Thus, ${f('a = 7')}.</p>
<p>2. <strong>Factorization with positive nonintegers ${f('c')} and ${f('d')}:</strong></p>
<p>${f('(3x^2 + c)(2x^2 + d) = 6x^4 + (3d + 2c)x^2 + cd')}</p>
<p>Here ${f('cd = 7 \\implies d = \\frac{7}{c}')}. Substituting into the middle term:</p>
<p>${f('2c + 3\\left(\\frac{7}{c}\\right) = 17')}</p>
<p>${f('2c^2 - 17c + 21 = 0')}</p>
<p>Factor this quadratic equation:</p>
<p>${f('(2c - 3)(c - 7) = 0')}</p>
<p>Since ${f('c')} must be a noninteger, ${f('c = \\frac{3}{2} = 1.5')}.</p>
<p>3. <strong>Find ${f('a + c')}:</strong></p>
<p>${f('a + c = 7 + 1.5 = 8.5 = \\frac{17}{2}')}</p>`,

  // Q10
  '6a52e48f4d554e04aa1bf42a': `<p><strong>Choice A is correct.</strong></p>
<p>To determine the equation of the line of best fit, examine its y-intercept and slope:</p>
<p>1. <strong>y-intercept:</strong> When ${f('x = 0')}, the line crosses the vertical axis at approximately ${f('y = 9.5')}. This eliminates choices with negative intercepts.</p>
<p>2. <strong>Slope:</strong> As ${f('x')} increases, ${f('y')} decreases, meaning the slope is negative (${f('m < 0')}).</p>
<p>Between ${f('x = 0')} (${f('y \\approx 9.5')}) and ${f('x = 10')} (${f('y \\approx 5.5')}):</p>
<p>${f('m \\approx \\frac{5.5 - 9.5}{10 - 0} = -0.4')}</p>
<p>Therefore, the line of best fit is represented by ${f('y = 9.5 - 0.4x')}.</p>
<p><strong>Choice B is incorrect</strong> because it has a positive slope.</p>
<p><strong>Choices C and D are incorrect</strong> because they have a negative y-intercept of -9.5.</p>`,

  // Q11
  '6a52e5844d554e04aa1bf439': `<p><strong>Choice A is correct.</strong></p>
<p>In the coordinate plane, the graph of a function ${f('y = f(x)')} passes through the point ${f('(h, k)')} if and only if ${f('f(h) = k')}.</p>
<p>Since the graph passes through ${f('(9, 8)')}, substituting ${f('x = 9')} and ${f('y = 8')} gives:</p>
<p>${f('f(9) = 8')}</p>
<p><strong>Choice B is incorrect</strong> because ${f('f(0) = 8')} would mean the graph passes through ${f('(0, 8)')}.</p>
<p><strong>Choice C is incorrect</strong> because ${f('f(8) = 9')} would mean the graph passes through ${f('(8, 9)')}.</p>
<p><strong>Choice D is incorrect</strong> because ${f('f(9) = 0')} represents the x-intercept ${f('(9, 0)')}.</p>`,

  // Q12
  '6a52e6254d554e04aa1bf43f': `<p><strong>The correct answer is 18.</strong></p>
<p>We are given that the exponential function ${f('g(x)')} doubles for every increase of 2 in the value of ${f('x')}.</p>
<p>This means:</p>
<p>${f('g(x + 2) = 2 \\times g(x)')}</p>
<p>We are given that ${f('g(4) = 9')}. To find ${f('g(6)')}, note that ${f('6 = 4 + 2')}:</p>
<p>${f('g(6) = g(4 + 2) = 2 \\times g(4) = 2 \\times 9 = 18')}</p>`,

  // Q13
  '6a52e7b54d554e04aa1bf456': `<p><strong>Choice A is correct.</strong></p>
<p>The graph shows the monthly mean number of sunspots as a function of the number of months ${f('x')} since December 2013.</p>
<p>The line has a vertical intercept at ${f('(0, 120)')} and passes through ${f('(20, 61)')}.</p>
<p>Reading the graph directly at ${f('x = 20')}, the monthly mean number of sunspots is approximately 61.</p>
<p><strong>Choices B, C, and D are incorrect</strong> because they correspond to different points along the line.</p>`,

  // Q14
  '6a52e8764d554e04aa1bf45c': `<p><strong>Choice A is correct.</strong></p>
<p>The line passes through ${f('(0, 12)')}, which means its y-intercept is ${f('b = 12')}.</p>
<p>With a slope of ${f('m = -\\frac{4}{7}')}, the equation of the line in slope-intercept form is:</p>
<p>${f('y = -\\frac{4}{7}x + 12')}</p>
<p>The x-intercept is the point where ${f('y = 0')}:</p>
<p>${f('0 = -\\frac{4}{7}x + 12')}</p>
<p>${f('\\frac{4}{7}x = 12')}</p>
<p>Multiply both sides by ${f('\\frac{7}{4}')}:</p>
<p>${f('x = 12 \\times \\frac{7}{4} = 3 \\times 7 = 21')}</p>
<p>Therefore, the x-intercept is ${f('(21, 0)')}.</p>
<p><strong>Choice B is incorrect</strong> because it has a negative x-coordinate.</p>
<p><strong>Choices C and D are incorrect</strong> and may result from confusing the slope numerator and denominator.</p>`,

  // Q15
  '6a52e8e44d554e04aa1bf462': `<p><strong>Choice A is correct.</strong></p>
<p>To determine the correct inequality from the graph:</p>
<p>1. <strong>Boundary Line:</strong> The dashed line passes through ${f('(0, 1)')} and ${f('(1, 5)')}.</p>
<p>Its slope is:</p>
<p>${f('m = \\frac{5 - 1}{1 - 0} = 4')}</p>
<p>Thus, the boundary line equation is ${f('y = 4x + 1')}. Because the line is dashed, the inequality is strict (${f('<')} or ${f('>')}).</p>
<p>2. <strong>Shaded Region:</strong> The region below and to the right of the line is shaded. Let us test a test point in the shaded region, such as ${f('(4, 0)')}:</p>
<p>${f('0 < 4(4) + 1 \\implies 0 < 17')} (True)</p>
<p>Therefore, the inequality representing the shaded region is ${f('y < 4x + 1')}.</p>
<p><strong>Choices B, C, and D are incorrect</strong> because they use an incorrect slope of 1/4 or shade above the line.</p>`,

  // Q16
  '6a52e95e4d554e04aa1bf468': `<p><strong>Choice A is correct.</strong></p>
<p>The given system of linear equations is:</p>
<p>${f('y = 5x + 18')}</p>
<p>${f('y = 5x - 18')}</p>
<p>Notice that both lines have the exact same slope (${f('m = 5')}) but different y-intercepts (18 and -18).</p>
<p>Lines with the same slope and different y-intercepts are parallel and distinct. Because parallel lines never intersect, the system has <strong>zero</strong> solutions.</p>
<p><strong>Choice B is incorrect</strong> because parallel lines never intersect at a single point.</p>
<p><strong>Choices C and D are incorrect</strong> because two linear equations can only have 0, 1, or infinitely many solutions.</p>`,

  // Q17
  '6a52ea514d554e04aa1bf46e': `<p><strong>Choice A is correct.</strong></p>
<p>In the given figure, ${f('\\triangle ACE')} is a right triangle with right angle at ${f('E')}.</p>
<p>The two acute angles in a right triangle are complementary, meaning:</p>
<p>${f('m\\angle A + m\\angle C = 90^\\circ')}</p>
<p>By the cofunction identity for sine and cosine:</p>
<p>${f('\\sin(C) = \\cos(90^\\circ - C) = \\cos(A)')}</p>
<p>Since we are given that ${f('\\cos A = 0.65')}, it follows directly that:</p>
<p>${f('\\sin C = 0.65')}</p>
<p><strong>Choices B, C, and D are incorrect</strong> because they do not reflect the cofunction identity.</p>`,

  // Q18
  '6a52ead44d554e04aa1bf472': `<p><strong>The correct answer is 12/5 (or 2.4).</strong></p>
<p>The function is defined by ${f('f(x) = 3x - 7')}.</p>
<p>We are given that ${f('f(b) = \\frac{1}{5}')}. Substitute ${f('x = b')} into the equation:</p>
<p>${f('3b - 7 = \\frac{1}{5}')}</p>
<p>Add 7 to both sides:</p>
<p>${f('3b = 7 + \\frac{1}{5} = \\frac{35}{5} + \\frac{1}{5} = \\frac{36}{5}')}</p>
<p>Divide both sides by 3:</p>
<p>${f('b = \\frac{36}{5 \\times 3} = \\frac{12}{5} = 2.4')}</p>`,

  // Q19
  '6a52eb234d554e04aa1bf47e': `<p><strong>Choice A is correct.</strong></p>
<p>We are given the equation:</p>
<p>${f('97 - x^2 + 5 = 95')}</p>
<p>Simplify the left side:</p>
<p>${f('102 - x^2 = 95')}</p>
<p>Subtract 102 from both sides:</p>
<p>${f('-x^2 = -7 \\implies x^2 = 7')}</p>
<p>Taking the square root of both sides gives the two solutions:</p>
<p>${f('x = \\sqrt{7}')} and ${f('x = -\\sqrt{7}')}</p>
<p>The sum of the solutions is:</p>
<p>${f('\\sqrt{7} + (-\\sqrt{7}) = 0')}</p>
<p><strong>Choices B, C, and D are incorrect</strong> because the two symmetric solutions cancel out to 0.</p>`,

  // Q20
  '6a52eb914d554e04aa1bf484': `<p><strong>Choice A is correct.</strong></p>
<p>The vertex form of a quadratic function is ${f('f(x) = a(x - h)^2 + k')}, where the vertex is ${f('(h, k)')}. Since the coefficient ${f('a = 1 > 0')}, the parabola opens upward, and the minimum value of the function is ${f('k')}, which appears directly as a constant.</p>
<p>To write ${f('f(x) = x^2 - 4x - 780')} in vertex form, complete the square:</p>
<p>${f('f(x) = (x^2 - 4x + 4) - 4 - 780 = (x - 2)^2 - 784')}</p>
<p>In this form, the minimum value of the function, -784, is explicitly displayed as a constant.</p>
<p><strong>Choice B is incorrect</strong> because it is in factored form, which displays the x-intercepts (zeros), not the minimum value.</p>
<p><strong>Choice C is incorrect</strong> because it is not in vertex form.</p>
<p><strong>Choice D is incorrect</strong> because its factors do not display the vertex coordinates.</p>`,

  // Q21
  '6a52ec734d554e04aa1bf490': `<p><strong>The correct answer is -36.</strong></p>
<p>The parabola is given by ${f('y = 6x^2 + bx + c')}.</p>
<p>From the graph:</p>
<p>1. The y-intercept is at ${f('(0, -3)')}. Substituting ${f('x = 0')} gives:</p>
<p>${f('c = -3')}</p>
<p>2. The graph highlights two points with the same y-value of -3: ${f('(-2, -3)')} and ${f('(0, -3)')}.</p>
<p>The axis of symmetry lies midway between these points:</p>
<p>${f('x = \\frac{-2 + 0}{2} = -1')}</p>
<p>For any quadratic function ${f('y = ax^2 + bx + c')}, the axis of symmetry is given by ${f('x = -\\frac{b}{2a}')}:</p>
<p>${f('-1 = -\\frac{b}{2(6)} = -\\frac{b}{12}')}</p>
<p>Multiply both sides by -12:</p>
<p>${f('b = 12')}</p>
<p>3. Calculate ${f('bc')}:</p>
<p>${f('bc = 12 \\times (-3) = -36')}</p>`,

  // Q22
  '6a53b6694d554e04aa1bf6c9': `<p><strong>Choice A is correct.</strong></p>
<p>Let ${f('V')} be the original value of the painting at the end of 2011.</p>
<p>1. <strong>Increase by 166% from 2011 to 2012:</strong></p>
<p>The multiplier is ${f('1 + 1.66 = 2.66')}. The value at the end of 2012 is:</p>
<p>${f('V_{2012} = 2.66V')}</p>
<p>2. <strong>Decrease by 14% from 2012 to 2013:</strong></p>
<p>The multiplier is ${f('1 - 0.14 = 0.86')}. The value at the end of 2013 is:</p>
<p>${f('V_{2013} = 0.86 \\times 2.66V = 2.2876V')}</p>
<p>3. <strong>Net percentage increase:</strong></p>
<p>${f('\\text{Net Increase} = (2.2876 - 1) \\times 100\\% = 1.2876 \\times 100\\% = 128.76\\%')}</p>
<p><strong>Choice B is incorrect</strong> and may result from simply subtracting the two percentages (${f('166\\% - 14\\% = 152\\%')}).</p>
<p><strong>Choices C and D are incorrect</strong> and result from applying the percentage changes additively or incorrectly.</p>`
};

async function main() {
  console.log('🚀 Uploading explanations for March 2026 US 2 Module 1 (22 questions)...\n');
  const questionIds = Object.keys(explanations);
  
  for (let i = 0; i < questionIds.length; i++) {
    const qid = questionIds[i];
    const explanation = explanations[qid];
    process.stdout.write(`Updating M1 Q${i + 1} (${qid})... `);
    try {
      const res = await updateQuestionExplanation(qid, explanation);
      if (res && res.message === 'success') {
        console.log('✅ Success');
      } else {
        console.log('⚠️ Unexpected response:', res);
      }
    } catch (err) {
      console.log('❌ Error:', err.message);
    }
  }
  console.log('\n🎉 Finished Module 1 explanations (22 questions updated).');
}

main();
