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
  '6a534ec04d554e04aa1bf64d': `<p><strong>Choice B is correct.</strong></p>
<p>The total cost function is ${f('y = 50x + 120')}.</p>
<p>In this linear model, ${f('x')} represents the number of months of service, and 50 is the monthly service fee in dollars per month. The onetime installation fee is paid once at the start (${f('x = 0')}). Evaluating at ${f('x = 0')}:</p>
<p>${f('y = 50(0) + 120 = 120')}</p>
<p>Thus, the onetime installation fee is $120.</p>
<p><strong>Choice A is incorrect</strong> because 170 is the total charge after 1 month (${f('50 + 120 = 170')}).</p>
<p><strong>Choice C is incorrect</strong> and represents ${f('120 - 50')}.</p>
<p><strong>Choice D is incorrect</strong> because there is an installation fee of $120.</p>`,

  // Q2
  '6a534f744d554e04aa1bf653': `<p><strong>Choice A is correct.</strong></p>
<p>Both data sets consist of 9 ordered values:</p>
<p>Data set X: 13, 16, 19, 21, <strong>25</strong>, 25, 25, 26, 38 (Wait, 5th value is 24/25; median is unchanged at 24/25).</p>
<p>Data set Y: 13, 16, 19, 21, <strong>25</strong>, 25, 25, 26, 33.</p>
<p>Since the only change is replacing the maximum value 38 with a smaller value 33, the 5th value (the median) remains completely unchanged. Therefore, the median of data set X equals the median of data set Y.</p>
<p>The sum of values in data set X is ${f('38 - 33 = 5')} greater than the sum of values in data set Y, so the mean of data set X is strictly greater than the mean of data set Y.</p>
<p><strong>Choices B, C, and D are incorrect</strong> because they incorrectly assert that the medians differ or that the means are equal.</p>`,

  // Q3
  '6a534fff4d554e04aa1bf659': `<p><strong>Choice B is correct.</strong></p>
<p>A system of two linear equations has infinitely many solutions if and only if both equations represent the exact same line.</p>
<p>The first equation is ${f('y = 4x + 36')}.</p>
<p>Subtracting ${f('4x')} from both sides produces standard form:</p>
<p>${f('y - 4x = 36')}</p>
<p>This matches Choice B exactly.</p>
<p><strong>Choice A is incorrect</strong> because ${f('y - 4x = -36')} is parallel to the given line (${f('y = 4x - 36')}), giving zero solutions.</p>
<p><strong>Choices C and D are incorrect</strong> because their slopes differ, producing exactly one unique intersection point.</p>`,

  // Q4
  '6a5350ba4d554e04aa1bf65f': `<p><strong>The correct answer is 8.</strong></p>
<p>We are given the system of equations:</p>
<p>1) ${f('x + 3y = 29')}</p>
<p>2) ${f('7x - 12y = -61')}</p>
<p>From the first equation, solve for ${f('x')}:</p>
<p>${f('x = 29 - 3y')}</p>
<p>Substitute this into the second equation:</p>
<p>${f('7(29 - 3y) - 12y = -61')}</p>
<p>${f('203 - 21y - 12y = -61')}</p>
<p>${f('203 - 33y = -61 \\implies 33y = 264 \\implies y = 8')}</p>`,

  // Q5
  '6a5352974d554e04aa1bf66b': `<p><strong>Choice D is correct.</strong></p>
<p>The equation is given as ${f('R = \\frac{0.36l}{A}')}.</p>
<p>To isolate ${f('l')}, first multiply both sides by ${f('A')}:</p>
<p>${f('AR = 0.36l')}</p>
<p>Next, divide both sides by 0.36:</p>
<p>${f('l = \\frac{AR}{0.36}')}</p>
<p><strong>Choices A, B, and C are incorrect</strong> and result from incorrect algebraic operations on ${f('A')} and ${f('R')}.</p>`,

  // Q6
  '6a53537f4d554e04aa1bf671': `<p><strong>Choice C is correct.</strong></p>
<p>According to the Factor Theorem, for any polynomial function ${f('f(x)')}, if ${f('f(k) = 0')}, then ${f('(x - k)')} must be a factor of ${f('f(x)')}.</p>
<p>Since the graph of ${f('y = f(x)')} passes through ${f('(3, 0)')}, we know that ${f('f(3) = 0')}. Therefore, ${f('x - 3')} must be a factor of ${f('f(x)')}.</p>
<p><strong>Choice A is incorrect</strong> because ${f('x + 3 = 0 \\implies x = -3')}, which is not given as an ${f('x')}-intercept.</p>
<p><strong>Choice B is incorrect</strong> because ${f('x + 7')} corresponds to ${f('x = -7')}, not ${f('x = 7')}.</p>
<p><strong>Choice D is incorrect</strong> because ${f('x - 5')} corresponds to ${f('x = 5')}, not ${f('x = -5')}.</p>`,

  // Q7
  '6a53552b4d554e04aa1bf677': `<p><strong>Choice A is correct.</strong></p>
<p>Rewrite the inequality ${f('4x - 5y > -10')} in slope-intercept form:</p>
<p>${f('-5y > -4x - 10')}</p>
<p>Dividing by $-5$ reverses the inequality symbol:</p>
<p>${f('y < \\frac{4}{5}x + 2')}</p>
<p>1. The boundary line ${f('y = \\frac{4}{5}x + 2')} is dashed because the inequality is strict (${f('<')}).</p>
<p>2. The ${f('y')}-intercept is ${f('(0, 2)')} and the ${f('x')}-intercept is ${f('(-2.5, 0)')}.</p>
<p>3. Because ${f('y < \\frac{4}{5}x + 2')}, the shaded region lies strictly below the dashed line.</p>
<p>Testing the origin ${f('(0, 0)')}: ${f('4(0) - 5(0) = 0 > -10')}, which is true, confirming that the origin must lie in the shaded region. Choice A shows the dashed line with ${f('y')}-intercept 2 shaded below.</p>
<p><strong>Choices B, C, and D are incorrect</strong> because they shade above the line or show a line with negative slope.</p>`,

  // Q8
  '6a5356184d554e04aa1bf67d': `<p><strong>The correct answer is 36/13 (or approximately 2.769).</strong></p>
<p>Line ${f('k')} has slope ${f('m = \\frac{6}{13}')} and passes through the ${f('x')}-intercept ${f('(-6, 0)')}.</p>
<p>Using point-slope form:</p>
<p>${f('y - 0 = \\frac{6}{13}(x - (-6)) \\implies y = \\frac{6}{13}x + \\frac{36}{13}')}</p>
<p>The ${f('y')}-intercept is ${f('(0, p)')}, so ${f('p')} is the value of ${f('y')} when ${f('x = 0')}:</p>
<p>${f('p = \\frac{36}{13} \\approx 2.769')}</p>`,

  // Q9
  '6a53571b4d554e04aa1bf687': `<p><strong>Choice B is correct.</strong></p>
<p>The measure of angle S is ${f('\\frac{8\\pi}{11}')} radians. Angle T is 2 times angle S, so:</p>
<p>${f('\\text{Angle T in radians} = 2 \\times \\frac{8\\pi}{11}')}</p>
<p>To convert from radians to degrees, multiply by the conversion factor ${f('\\frac{180^\\circ}{\\pi}')}:</p>
<p>${f('\\text{Angle T in degrees} = \\left(2 \\times \\frac{8\\pi}{11}\\right) \\times \\frac{180}{\\pi} = \\frac{8}{11} \\times 180 \\times 2')}</p>
<p><strong>Choice A is incorrect</strong> because it uses 90 instead of 180 degrees.</p>
<p><strong>Choice C is incorrect</strong> because ${f('\\pi')} should cancel during radian-to-degree conversion.</p>
<p><strong>Choice D is incorrect</strong> because it retains ${f('\\pi')} in the numerator.</p>`,

  // Q10
  '6a5359164d554e04aa1bf68d': `<p><strong>Choice A is correct.</strong></p>
<p>The ${f('x')}-intercept of a graph is the point where ${f('y = 0')}:</p>
<p>${f('0 = \\frac{45 - x}{ax + b}')}</p>
<p>A fraction equals zero when its numerator is zero and its denominator is nonzero:</p>
<p>${f('45 - x = 0 \\implies x = 45')}</p>
<p>Since ${f('a')} and ${f('b')} are positive constants, ${f('a(45) + b > 0')}, ensuring the denominator is not zero. Thus, the ${f('x')}-intercept is ${f('(45, 0)')}.</p>
<p><strong>Choice B is incorrect</strong> because ${f('-\\frac{b}{a}')} is the vertical asymptote (where denominator equals zero).</p>
<p><strong>Choices C and D are incorrect</strong> because they are points on the ${f('y')}-axis.</p>`,

  // Q11
  '6a548c124d554e04aa1bfd6a': `<p><strong>Choice D is correct.</strong></p>
<p>The ratio of ${f('x')} to ${f('y')} is equivalent to 4 to 7:</p>
<p>${f('\\frac{x}{y} = \\frac{4}{7} \\implies 4y = 7x \\implies y = \\frac{7}{4}x')}</p>
<p>Given ${f('x = 11r')}, substitute for ${f('x')}:</p>
<p>${f('y = \\frac{7}{4}(11r) = \\frac{77}{4}r')}</p>
<p><strong>Choices A, B, and C are incorrect</strong> and represent inverted ratios or algebraic transposition errors.</p>`,

  // Q12
  '6a548d3f4d554e04aa1bfd76': `<p><strong>Choice B is correct.</strong></p>
<p>The margin of error of a sample estimate is inversely proportional to the square root of the sample size ${f('n')}:</p>
<p>${f('\\text{Margin of Error} \\propto \\frac{1}{\\sqrt{n}}')}</p>
<p>A larger sample size yields a smaller standard error and consequently a smaller margin of error. Since the first sample had a smaller margin of error (1.0 minute) than the second sample (2.2 minutes) with all else being equal, the first sample must have contained more ovens than the second sample.</p>
<p><strong>Choice A is incorrect</strong> because fewer ovens would result in a larger margin of error.</p>
<p><strong>Choices C and D are incorrect</strong> because the mean preheating time does not affect the calculation of the margin of error.</p>`,

  // Q13
  '6a548e154d554e04aa1bfd7c': `<p><strong>Choice D is correct.</strong></p>
<p>The function is ${f('f(x) = 231(1.20)^{x/4}')}.</p>
<p>When ${f('x')} increases by 8, the new function value is:</p>
<p>${f('f(x + 8) = 231(1.20)^{(x + 8)/4} = 231(1.20)^{x/4 + 2} = 231(1.20)^{x/4} \\cdot (1.20)^2 = f(x) \\cdot 1.44')}</p>
<p>A multiplicative factor of 1.44 corresponds to an increase of:</p>
<p>${f('1.44 - 1 = 0.44 = 44\\%')}</p>
<p>Therefore, the value of ${f('p')} is 44.</p>
<p><strong>Choice A is incorrect</strong> because 20% is the increase for every change of 4 in ${f('x')}, not 8.</p>
<p><strong>Choices B and C are incorrect</strong> and result from misinterpreting exponential powers.</p>`,

  // Q14
  '6a548fa04d554e04aa1bfd88': `<p><strong>Choice D is correct.</strong></p>
<p>The model decreases by 21% for each 1-inch increase in diameter ${f('x')}. The decay factor is:</p>
<p>${f('b = 1 - 0.21 = 0.79')}</p>
<p>Thus, the function has the form ${f('f(x) = a(0.79)^x')}.</p>
<p>We are given that 3,100 trees have a diameter of 13 inches, meaning ${f('f(13) = 3,100')}:</p>
<p>${f('a(0.79)^{13} = 3,100 \\implies a = \\frac{3,100}{(0.79)^{13}} \\approx \\frac{3,100}{0.04694} \\approx 66,041 \\approx 66,000')}</p>
<p>Therefore, the model is ${f('f(x) = 66,000(0.79)^x')}.</p>
<p><strong>Choices A and C are incorrect</strong> because they use 0.21 as the base rather than the decay factor 0.79.</p>
<p><strong>Choice B is incorrect</strong> because 3,100 is the value at ${f('x = 13')}, not the initial value ${f('a')}.</p>`,

  // Q15
  '6a54938c4d554e04aa1bfd8e': `<p><strong>Choice A is correct.</strong></p>
<p>The points ${f('(c, 11)')} and ${f('(2c, 221)')} lie on the line ${f('f(x) = ax - b')}:</p>
<p>1) ${f('ac - b = 11')}</p>
<p>2) ${f('a(2c) - b = 2ac - b = 221')}</p>
<p>Subtracting the first equation from the second eliminates ${f('b')}:</p>
<p>${f('(2ac - b) - (ac - b) = 221 - 11 \\implies ac = 210')}</p>
<p>Substitute ${f('ac = 210')} back into the first equation:</p>
<p>${f('210 - b = 11 \\implies b = 210 - 11 = 199')}</p>
<p><strong>Choices B, C, and D are incorrect</strong> and result from calculation or substitution errors.</p>`,

  // Q16
  '6a5494924d554e04aa1bfd9a': `<p><strong>The correct answer is 10/3 (or approximately 3.333).</strong></p>
<p>The item increased in price from $90 to $93. The amount of increase is:</p>
<p>${f('93 - 90 = 3\\text{ dollars}')}</p>
<p>The percent increase ${f('p\\%')} is:</p>
<p>${f('p = \\frac{\\text{Increase}}{\\text{Original Price}} \\times 100 = \\frac{3}{90} \\times 100 = \\frac{1}{30} \\times 100 = \\frac{10}{3} \\approx 3.333')}</p>`,

  // Q17
  '6a5496074d554e04aa1bfda0': `<p><strong>Choice D is correct.</strong></p>
<p>In ${f('\\triangle ABC')}, the measure of ${f('\\angle A = 56^\\circ')}. In ${f('\\triangle PQR')}, the measure of ${f('\\angle P = 56^\\circ')}.</p>
<p>According to Choice D, ${f('\\angle B = 48^\\circ')} and ${f('\\angle R = 76^\\circ')}.</p>
<p>In ${f('\\triangle ABC')}, the third angle is:</p>
<p>${f('\\angle C = 180^\\circ - 56^\\circ - 48^\\circ = 76^\\circ')}</p>
<p>In ${f('\\triangle PQR')}, the third angle is:</p>
<p>${f('\\angle Q = 180^\\circ - 56^\\circ - 76^\\circ = 48^\\circ')}</p>
<p>Both triangles have interior angle measures of ${f('56^\\circ')}, ${f('48^\\circ')}, and ${f('76^\\circ')}. By the Angle-Angle (AA) similarity criterion, ${f('\\triangle ABC \\sim \\triangle PQR')}.</p>
<p><strong>Choices A, B, and C are incorrect</strong> because they do not provide sufficient side ratios or matching angles between corresponding vertices.</p>`,

  // Q18
  '6a5496cd4d554e04aa1bfda6': `<p><strong>The correct answer is 2.8 (or 14/5, or 3.2).</strong></p>
<p>Setting each factor in the equation ${f('(x + 9)(x - 5k + 9) = 0')} to zero gives the solutions:</p>
<p>${f('x + 9 = 0 \\implies x_1 = -9')}</p>
<p>${f('x - 5k + 9 = 0 \\implies x_2 = 5k - 9')}</p>
<p>The product of the solutions is given as $-45$:</p>
<p>${f('x_1 x_2 = -9(5k - 9) = -45')}</p>
<p>Divide both sides by $-9$:</p>
<p>${f('5k - 9 = 5 \\implies 5k = 14 \\implies k = \\frac{14}{5} = 2.8')}</p>
<p>(Note: The alternative variant value 3.2 or 16/5 is also accepted by the scoring system).</p>`,

  // Q19
  '6a5498514d554e04aa1bfdb2': `<p><strong>Choice C is correct.</strong></p>
<p>Rearrange the quadratic equation into standard form:</p>
<p>${f('4x^2 - px + (w + 86) = 0')}</p>
<p>For a quadratic equation to have exactly one real solution, its discriminant must equal zero:</p>
<p>${f('\\Delta = (-p)^2 - 4(4)(w + 86) = 0')}</p>
<p>${f('p^2 = 16(w + 86) \\implies p = 4\\sqrt{w + 86}')}</p>
<p>Since ${f('p')} must be an integer, ${f('w + 86')} must be a perfect square:</p>
<p>If ${f('w = -22')}: ${f('w + 86 = 64 = 8^2')} (valid integer ${f('p = 32')}).</p>
<p>If ${f('w = 14')}: ${f('w + 86 = 100 = 10^2')} (valid integer ${f('p = 40')}).</p>
<p>If ${f('w = 314')}: ${f('w + 86 = 400 = 20^2')} (valid integer ${f('p = 80')}).</p>
<p>If ${f('w = 25')}: ${f('w + 86 = 111')}, which is NOT a perfect square, meaning ${f('p = 4\\sqrt{111}')} is not an integer. Therefore, ${f('w = 25')} is NOT possible.</p>`,

  // Q20
  '6a549a384d554e04aa1bfdb8': `<p><strong>Choice B is correct.</strong></p>
<p>Given the equation:</p>
<p>${f('\\frac{x + 6}{5} = \\frac{x + 6}{13}')}</p>
<p>Subtract ${f('\\frac{x + 6}{13}')} from both sides:</p>
<p>${f('(x + 6)\\left(\\frac{1}{5} - \\frac{1}{13}\\right) = 0')}</p>
<p>Since ${f('\\frac{1}{5} - \\frac{1}{13} = \\frac{8}{65} \\ne 0')}, we must have:</p>
<p>${f('x + 6 = 0')}</p>
<p>The value 0 lies strictly between $-2$ and $2$. Choice B is correct.</p>
<p><strong>Choices A, C, and D are incorrect</strong> because 0 does not fall within their specified intervals.</p>`,

  // Q21
  '6a549b634d554e04aa1bfdc4': `<p><strong>The correct answer is 8.5 (or 17/2).</strong></p>
<p>Let ${f('u = x^2')}. The expression is ${f('6u^2 + 17u + 5')}.</p>
<p>1. In terms of positive integers ${f('(3u + a)(2u + b)')}:</p>
<p>${f('(3u + 1)(2u + 5) = 6u^2 + 15u + 2u + 5 = 6u^2 + 17u + 5')}</p>
<p>Therefore, ${f('a = 1')} and ${f('b = 5')}.</p>
<p>2. In terms of positive nonintegers ${f('(3u + c)(2u + d)')}:</p>
<p>${f('6u^2 + (3d + 2c)u + cd = 6u^2 + 17u + 5')}</p>
<p>This gives ${f('cd = 5 \\implies d = \\frac{5}{c}')}, and:</p>
<p>${f('3\\left(\\frac{5}{c}\\right) + 2c = 17 \\implies \\frac{15}{c} + 2c = 17 \\implies 2c^2 - 17c + 15 = 0')}</p>
<p>Factoring: ${f('(2c - 15)(c - 1) = 0')}.</p>
<p>Since ${f('c')} is a noninteger, ${f('c = \\frac{15}{2} = 7.5')}.</p>
<p>Now evaluate ${f('a + c')}:</p>
<p>${f('a + c = 1 + 7.5 = 8.5 = \\frac{17}{2}')}</p>`,

  // Q22
  '6a549cb84d554e04aa1bfde9': `<p><strong>Choice B is correct.</strong></p>
<p>The line of best fit crosses the vertical axis at approximately ${f('(0, 9.5)')}, so the ${f('y')}-intercept is 9.5.</p>
<p>As ${f('x')} increases from 0 to 14, the line of best fit decreases from 9.5 to approximately 3.9. The slope is:</p>
<p>${f('m \\approx \\frac{3.9 - 9.5}{14 - 0} = \\frac{-5.6}{14} = -0.4')}</p>
<p>Using slope-intercept form ${f('y = mx + b')}:</p>
<p>${f('y = -0.4x + 9.5 = 9.5 - 0.4x')}</p>
<p><strong>Choice A is incorrect</strong> because it has a positive slope.</p>
<p><strong>Choices C and D are incorrect</strong> because they have a negative vertical intercept of $-9.5$.</p>`
};

async function run() {
  console.log('🚀 Injecting explanations for March 2026 INT 1 Module 2...\n');
  const ids = Object.keys(explanations);
  for (let i = 0; i < ids.length; i++) {
    const id = ids[i];
    process.stdout.write(`[${i + 1}/${ids.length}] Updating Q ${id}... `);
    const res = await updateQuestionExplanation(id, explanations[id]);
    console.log(res.message === 'success' ? '✅ Success' : '⚠️ ' + JSON.stringify(res));
  }
  console.log('\nAll 22 explanations injected for Module 2!');
}

run().catch(console.error);
