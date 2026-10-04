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
  '6a53d3684d554e04aa1bf8f5': `<p><strong>Choice C is correct.</strong></p>
<p>In right triangle ${f('FGH')}, angle ${f('H')} is a right angle (${f('90^\\circ')}), and angle ${f('G')} is given as ${f('60^\\circ')}. The sum of angles in a triangle is ${f('180^\\circ')}, so:</p>
<p>${f('\\angle F = 180^\\circ - 90^\\circ - 60^\\circ = 30^\\circ')}</p>
<p>The cosine of angle ${f('F')} is defined as the cosine of ${f('30^\\circ')}:</p>
<p>${f('\\cos F = \\cos(30^\\circ) = \\frac{\\sqrt{3}}{2}')}</p>
<p>Alternatively, using side lengths in a ${f('30^\\circ-60^\\circ-90^\\circ')} right triangle with hypotenuse 68, the side opposite the ${f('30^\\circ')} angle (${f('GH')}) is ${f('34\\sqrt{3}')} and the adjacent side (${f('FH')}) is 34. Thus:</p>
<p>${f('\\cos F = \\frac{\\text{adjacent}}{\\text{hypotenuse}} = \\frac{34\\sqrt{3}}{68} = \\frac{\\sqrt{3}}{2}')}</p>
<p><strong>Choice A is incorrect</strong> because it results from dividing by the hypotenuse without simplifying.</p>
<p><strong>Choice B is incorrect</strong> because ${f('\\frac{1}{2}')} is ${f('\\sin(30^\\circ)')} or ${f('\\cos(60^\\circ)')}.</p>
<p><strong>Choice D is incorrect</strong> because it is the side length itself, not a trigonometric ratio.</p>`,

  // Q2
  '6a53d4114d554e04aa1bf901': `<p><strong>Choice D is correct.</strong></p>
<p>The mass on day 1 is 253 grams. Each day after day 1, the mass decreases by 4 grams. For day ${f('x')}, exactly ${f('x - 1')} days have passed after day 1.</p>
<p>Therefore, the linear model is:</p>
<p>${f('m = 253 - 4(x - 1)')}</p>
<p>Expanding and simplifying the right side:</p>
<p>${f('m = 253 - 4x + 4 = -4x + 257')}</p>
<p><strong>Choice A is incorrect</strong> because it subtracts 4 from 249 instead of adding.</p>
<p><strong>Choice B is incorrect</strong> because it uses 249 as the intercept, which would mean day 0 had 249 grams.</p>
<p><strong>Choice C is incorrect</strong> because ${f('m = -4x + 253')} gives a mass of 249 grams on day 1 instead of 253 grams.</p>`,

  // Q3
  '6a53d46d4d554e04aa1bf90e': `<p><strong>Choice A is correct.</strong></p>
<p>First, solve the given linear equation for ${f('x')}:</p>
<p>${f('6x = 60 \\implies x = 10')}</p>
<p>Now evaluate the expression ${f('7x + 3')} by substituting ${f('x = 10')}:</p>
<p>${f('7(10) + 3 = 70 + 3 = 73')}</p>
<p><strong>Choice B is incorrect</strong> because ${f('63')} results from evaluating ${f('6x + 3')}.</p>
<p><strong>Choices C and D are incorrect</strong> and reflect arithmetic calculation errors.</p>`,

  // Q4
  '6a53d4be4d554e04aa1bf914': `<p><strong>The correct answer is 7.</strong></p>
<p>Substitute ${f('y = 9')} into the first equation ${f('3x + 8y = 93')}:</p>
<p>${f('3x + 8(9) = 93')}</p>
<p>${f('3x + 72 = 93')}</p>
<p>Subtract 72 from both sides:</p>
<p>${f('3x = 21')}</p>
<p>Divide by 3:</p>
<p>${f('x = 7')}</p>`,

  // Q5
  '6a53d50f4d554e04aa1bf925': `<p><strong>Choice A is correct.</strong></p>
<p>Reading directly from the given distribution table, find the row corresponding to "At least 30 mph but less than 35 mph".</p>
<p>The number of pitchers listed in that row is <strong>11</strong>.</p>
<p><strong>Choice B is incorrect</strong> because 5 is the number of pitchers with speeds between 35 mph and 40 mph.</p>
<p><strong>Choice C is incorrect</strong> because 4 is the number of pitchers with speeds between 40 mph and 45 mph.</p>
<p><strong>Choice D is incorrect</strong> because 1 is the number of pitchers with speeds between 45 mph and 50 mph.</p>`,

  // Q6
  '6a53d5884d554e04aa1bf931': `<p><strong>Choice D is correct.</strong></p>
<p>Substitute ${f('x = 4')} into the definition of the function ${f('f(x) = 5x^3')}:</p>
<p>${f('f(4) = 5(4)^3 = 5(64) = 320')}</p>
<p><strong>Choice A is incorrect</strong> because 64 is ${f('4^3')} without multiplying by 5.</p>
<p><strong>Choice B is incorrect</strong> because 81 is ${f('3^4')}.</p>
<p><strong>Choice C is incorrect</strong> and reflects an arithmetic calculation error.</p>`,

  // Q7
  '6a53d60d4d554e04aa1bf937': `<p><strong>Choice C is correct.</strong></p>
<p>Parallel lines in the coordinate plane have identical slopes. Since line ${f('s')} has a slope of 8, parallel line ${f('p')} must also have a slope of ${f('m = 8')}.</p>
<p>Line ${f('p')} passes through the point ${f('(0, 7)')}, which represents its ${f('y')}-intercept (${f('b = 7')}).</p>
<p>Using slope-intercept form ${f('y = mx + b')}:</p>
<p>${f('y = 8x + 7')}</p>
<p><strong>Choice A is incorrect</strong> because it has a ${f('y')}-intercept of ${f('-7')}.</p>
<p><strong>Choices B and D are incorrect</strong> because they use ${f('\\frac{1}{7}')} instead of 7 for the ${f('y')}-intercept.</p>`,

  // Q8
  '6a53d67e4d554e04aa1bf93b': `<p><strong>Choice C is correct.</strong></p>
<p>The total volume of the resulting mixture is the sum of the volumes of the two solutions: ${f('x + y')} liters.</p>
<p>The amount of saline in ${f('x')} liters of 4% saline solution is ${f('0.04x')}, and in ${f('y')} liters of 7% saline solution is ${f('0.07y')}.</p>
<p>The total saline in the 6% resulting solution of volume ${f('x + y')} is ${f('0.06(x + y)')}.</p>
<p>Equating the saline amounts gives:</p>
<p>${f('0.04x + 0.07y = 0.06(x + y)')}</p>
<p><strong>Choices A and B are incorrect</strong> because they use 0.4 and 0.7 (40% and 70%) or 6 instead of 0.06.</p>
<p><strong>Choice D is incorrect</strong> because it uses 6 instead of the decimal form 0.06 for 6%.</p>`,

  // Q9
  '6a53d6ee4d554e04aa1bf941': `<p><strong>Choice C is correct.</strong></p>
<p>Let the rectangle have length ${f('l = 8')} and width ${f('w')}. By the Pythagorean theorem, the diagonal ${f('d = \\sqrt{145}')} satisfies:</p>
<p>${f('l^2 + w^2 = d^2 \\implies 8^2 + w^2 = (\\sqrt{145})^2')}</p>
<p>${f('64 + w^2 = 145')}</p>
<p>${f('w^2 = 145 - 64 = 81 \\implies w = 9')}</p>
<p>The perimeter of the rectangle is:</p>
<p>${f('P = 2(l + w) = 2(8 + 9) = 2(17) = 34')}</p>
<p><strong>Choice A is incorrect</strong> because 145 is the square of the diagonal.</p>
<p><strong>Choice B is incorrect</strong> because 72 is the area of the rectangle (${f('8 \\times 9 = 72')}), not the perimeter.</p>
<p><strong>Choice D is incorrect</strong> because 17 is the semi-perimeter (${f('l + w')}).</p>`,

  // Q10
  '6a53d8434d554e04aa1bf94d': `<p><strong>The correct answer is 13.</strong></p>
<p>Combine like terms in the expression:</p>
<p>${f('7x^3 + 16x^3 - 10x^3 = (7 + 16 - 10)x^3 = 13x^3')}</p>
<p>Since this is equivalent to ${f('bx^3')}, the value of constant ${f('b')} is <strong>13</strong>.</p>`,

  // Q11
  '6a53d9234d554e04aa1bf960': `<p><strong>Choice B is correct.</strong></p>
<p>Factor the given quadratic equation:</p>
<p>${f('x^2 - 8x = 0 \\implies x(x - 8) = 0')}</p>
<p>Setting each factor to zero yields:</p>
<p>${f('x = 0 \\quad \\text{or} \\quad x = 8')}</p>
<p>Among the given choices, 8 is listed.</p>
<p><strong>Choice A is incorrect</strong> because ${f('16^2 - 8(16) = 256 - 128 = 128 \\ne 0')}.</p>
<p><strong>Choice C is incorrect</strong> because ${f('4^2 - 8(4) = 16 - 32 = -16 \\ne 0')}.</p>
<p><strong>Choice D is incorrect</strong> because ${f('(\\sqrt{8})^2 - 8\\sqrt{8} = 8 - 16\\sqrt{2} \\ne 0')}.</p>`,

  // Q12
  '6a53da614d554e04aa1bf96c': `<p><strong>The correct answer is 15.6 (or 78/5).</strong></p>
<p>Substitute the given volume of mineral ${f('Y')}, ${f('y = 12.8')}, into the equation:</p>
<p>${f('3.00x + 4.00(12.8) = 98.0')}</p>
<p>${f('3.00x + 51.2 = 98.0')}</p>
<p>Subtract 51.2 from both sides:</p>
<p>${f('3.00x = 46.8')}</p>
<p>Divide by 3:</p>
<p>${f('x = \\frac{46.8}{3} = 15.6')}</p>`,

  // Q13
  '6a53db074d554e04aa1bf972': `<p><strong>Choice D is correct.</strong></p>
<p>Standard deviation measures the spread or dispersion of data values around their mean.</p>
<p>In all four options, the mean of the 5 values is ${f('p')}. The data set whose values are furthest away from ${f('p')} will have the largest standard deviation.</p>
<p>In the set ${f('\\{p - 5, p - 4, p, p + 4, p + 5\\}')}, the deviations from the mean are ${f('-5, -4, 0, 4, 5')}. The sum of squared deviations is:</p>
<p>${f('(-5)^2 + (-4)^2 + 0^2 + 4^2 + 5^2 = 25 + 16 + 0 + 16 + 25 = 82')}</p>
<p>This is greater than any other option, so this set has the largest standard deviation.</p>
<p><strong>Choice A is incorrect</strong> because its squared deviations sum to ${f('16 + 0 + 0 + 0 + 16 = 32')}.</p>
<p><strong>Choice B is incorrect</strong> because its squared deviations sum to ${f('1 + 1 + 0 + 1 + 1 = 4')}.</p>
<p><strong>Choice C is incorrect</strong> because all values are identical (${f('p')}), so the standard deviation is 0 (the smallest possible).</p>`,

  // Q14
  '6a53db974d554e04aa1bf978': `<p><strong>Choice C is correct.</strong></p>
<p>In the right triangle shown, the side adjacent to angle ${f('A')} has length 22, and the hypotenuse has length 41.</p>
<p>By the definition of cosine in a right triangle:</p>
<p>${f('\\cos A = \\frac{\\text{adjacent}}{\\text{hypotenuse}} = \\frac{22}{41}')}</p>
<p><strong>Choice A is incorrect</strong> because it uses 1 in the numerator.</p>
<p><strong>Choice B is incorrect</strong> because it is the reciprocal of the adjacent side.</p>
<p><strong>Choice D is incorrect</strong> because ${f('\\frac{41}{22}')} is the secant (${f('\\sec A = \\frac{\\text{hypotenuse}}{\\text{adjacent}}')}), which is greater than 1.</p>`,

  // Q15
  '6a53dc254d554e04aa1bf984': `<p><strong>Choice D is correct.</strong></p>
<p>A quadratic function with maximum vertex ${f('(h, k)')} is written in vertex form as:</p>
<p>${f('f(t) = a(t - h)^2 + k')}</p>
<p>The problem states that the maximum height of 276 feet is reached at ${f('t = 3')} seconds, so the vertex is ${f('(3, 276)')}:</p>
<p>${f('f(t) = a(t - 3)^2 + 276')}</p>
<p>The object is launched at ${f('t = 0')} from a height of 132 feet (${f('f(0) = 132')}):</p>
<p>${f('132 = a(0 - 3)^2 + 276 \\implies 132 = 9a + 276 \\implies 9a = -144 \\implies a = -16')}</p>
<p>Thus, the equation is ${f('f(t) = -16(t - 3)^2 + 276')}.</p>
<p><strong>Choice A is incorrect</strong> because it represents a vertex at ${f('(-3, 276)')}.</p>
<p><strong>Choices B and C are incorrect</strong> because they use 132 as the maximum height instead of 276.</p>`,

  // Q16
  '6a53dcac4d554e04aa1bf988': `<p><strong>Choice D is correct.</strong></p>
<p>To find the ${f('y')}-intercept of ${f('y = f(x)')}, evaluate ${f('f(0)')}:</p>
<p>${f('f(0) = (0 - 2)(0 - 9)(0 + 4) = (-2)(-9)(4) = 72')}</p>
<p>The graph of ${f('y = h(x)')} is translated vertically up by 7 units, so:</p>
<p>${f('h(x) = f(x) + 7')}</p>
<p>The ${f('y')}-coordinate of the ${f('y')}-intercept of ${f('y = h(x)')} is:</p>
<p>${f('h(0) = f(0) + 7 = 72 + 7 = 79')}</p>
<p><strong>Choice A is incorrect</strong> because 0 is the ${f('x')}-coordinate.</p>
<p><strong>Choice B is incorrect</strong> because 7 is the vertical translation distance.</p>
<p><strong>Choice C is incorrect</strong> because 72 is the ${f('y')}-intercept of the original function ${f('f(x)')} before translation.</p>`,

  // Q17
  '6a53dd5a4d554e04aa1bf994': `<p><strong>Choice B is correct.</strong></p>
<p>The measure of angle ${f('T')} is 3 times angle ${f('S')}:</p>
<p>${f('T = 3 \\times \\frac{9\\pi}{11} = \\frac{27\\pi}{11} \\text{ radians}')}</p>
<p>To convert from radians to degrees, multiply by ${f('\\frac{180^\\circ}{\\pi}')}:</p>
<p>${f('\\text{Measure in degrees} = \\frac{27\\pi}{11} \\times \\frac{180}{\\pi} = \\frac{27 \\times 180}{11}')}</p>
<p>Rewriting ${f('27')} as ${f('9 \\times 3')}:</p>
<p>${f('\\frac{9 \\times (3 \\times 180)}{11} = \\frac{9}{11} \\times 540')}</p>
<p><strong>Choice A is incorrect</strong> because it uses 903 instead of multiplying by 180.</p>
<p><strong>Choices C and D are incorrect</strong> because they incorrectly retain ${f('\\pi')} in the degree conversion.</p>`,

  // Q18
  '6a53dde14d554e04aa1bf9a0': `<p><strong>Choice D is correct.</strong></p>
<p>The ratio of ${f('x')} to ${f('y')} is 5 to 6:</p>
<p>${f('\\frac{x}{y} = \\frac{5}{6} \\implies 5y = 6x \\implies y = \\frac{6}{5}x')}</p>
<p>Substitute ${f('x = 7t')} into the expression for ${f('y')}:</p>
<p>${f('y = \\frac{6}{5}(7t) = \\frac{42}{5}t')}</p>
<p><strong>Choice A is incorrect</strong> because ${f('\\frac{5}{42}t')} is the reciprocal ratio.</p>
<p><strong>Choices B and C are incorrect</strong> and result from inverting terms in the ratio proportion.</p>`,

  // Q19
  '6a53deb44d554e04aa1bf9a6': `<p><strong>The correct answer is 545.</strong></p>
<p>We are given ${f('r = 1,526')}. First find ${f('q')}:</p>
<p>${f('q = 0.30(q + r) = 0.30(q + 1,526)')}</p>
<p>${f('q = 0.30q + 457.8 \\implies 0.70q = 457.8 \\implies q = \\frac{457.8}{0.70} = 654')}</p>
<p>Now calculate the combined sum of ${f('q')} and ${f('r')}:</p>
<p>${f('q + r = 654 + 1,526 = 2,180')}</p>
<p>Next, use the fact that ${f('m')} is 20% of ${f('m + q + r')}:</p>
<p>${f('m = 0.20(m + 2,180)')}</p>
<p>${f('m = 0.20m + 436 \\implies 0.80m = 436 \\implies m = \\frac{436}{0.80} = 545')}</p>`,

  // Q20
  '6a53df374d554e04aa1bf9b2': `<p><strong>Choice A is correct.</strong></p>
<p>In the exponential model ${f('P(t) = 67.5\\left(\\frac{5}{4}\\right)^t')}, the base ${f('\\frac{5}{4}')} represents the annual growth factor (the ratio of the population in any given year to the population in the previous year):</p>
<p>${f('\\frac{P(t + 1)}{P(t)} = \\frac{5}{4}')}</p>
<p>This means that for every 4 reindeer in the population in a given year, there are predicted to be 5 reindeer the next year.</p>
<p><strong>Choice B is incorrect</strong> because it describes a population decay by a factor of ${f('\\frac{4}{5}')}.</p>
<p><strong>Choices C and D are incorrect</strong> because the exponent ${f('t')} is in single years, not every 4 or 5 years.</p>`,

  // Q21
  '6a53dfe84d554e04aa1bf9be': `<p><strong>Choice B is correct.</strong></p>
<p>Since line ${f('m')} is parallel to line ${f('n')}, the alternate interior angles formed with transversals ${f('AE')} and ${f('CD')} are congruent:</p>
<p>${f('\\angle CAB \\cong \\angle EDB')} and ${f('\\angle ACB \\cong \\angle DEB')}</p>
<p>Vertical angles at ${f('B')} are also congruent: ${f('\\angle ABC \\cong \\angle EBD')}. Thus, the two triangles are similar by AAA similarity.</p>
<p>To prove triangle congruence (${f('\\triangle ABC \\cong \\triangle EBD')}), at least one pair of corresponding sides must be congruent. Side ${f('AB')} corresponds directly to side ${f('EB')} along line ${f('AE')}.</p>
<p>Therefore, knowing ${f('AB = 15')} and ${f('EB = 15')} proves that ${f('AB \\cong EB')}, which establishes congruence by ASA (or AAS).</p>
<p><strong>Choice A is incorrect</strong> because ${f('DB')} corresponds to ${f('CB')}, not ${f('AB')}.</p>
<p><strong>Choice C is incorrect</strong> because isosceles triangles with equal angles are only similar, not necessarily congruent without side lengths.</p>
<p><strong>Choice D is incorrect</strong> because AAA similarity is insufficient to prove congruence.</p>`,

  // Q22
  '6a53e03a4d554e04aa1bf9c4': `<p><strong>Choice A is correct.</strong></p>
<p>Solve the linear equation for ${f('n')}:</p>
<p>${f('11n - 8 = 5n + 16')}</p>
<p>Subtract ${f('5n')} from both sides:</p>
<p>${f('6n - 8 = 16')}</p>
<p>Add 8 to both sides:</p>
<p>${f('6n = 24')}</p>
<p>Divide by 6:</p>
<p>${f('n = 4')}</p>
<p><strong>Choice B is incorrect</strong> because ${f('11(6) - 8 = 58 \\ne 5(6) + 16 = 46')}.</p>
<p><strong>Choices C and D are incorrect</strong> and result from signs errors in isolating ${f('n')}.</p>`
};

async function run() {
    console.log('🚀 Injecting Explanations for March 2026 · INT 2 — Module 1...\n');
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
    console.log(`\n🎉 Finished! Injected ${count}/${Object.keys(explanations).length} explanations for Module 1.`);
}

run();
