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
  '6a6643e3c3d08d90637d3943': `<p><strong>The correct answer is ${f('f(x) = \\frac{x}{5}')}.</strong></p>
<p>For a linear function ${f('f(x) = mx + b')}, find the slope ${f('m')} using the two given points ${f('(0, 0)')} and ${f('(40, 8)')}:</p>
<p>${f('m = \\frac{8 - 0}{40 - 0} = \\frac{8}{40} = \\frac{1}{5}')}</p>
<p>Since the graph passes through the origin ${f('(0, 0)')}, the ${f('y')}-intercept is ${f('b = 0')}.</p>
<p>Therefore, the equation defining ${f('f')} is:</p>
<p>${f('f(x) = \\frac{1}{5}x = \\frac{x}{5}')}</p>`,

  // Q2
  '6a66444cc3d08d90637d3951': `<p><strong>The correct answer is 1458.</strong></p>
<p>We are given the exponential function ${f('g(x) = 18 \\cdot a^x')}.</p>
<p>Use ${f('g(3) = 486')} to find the constant ${f('a')}:</p>
<p>${f('18 \\cdot a^3 = 486')}</p>
<p>Divide both sides by 18:</p>
<p>${f('a^3 = \\frac{486}{18} = 27')}</p>
<p>Take the cube root of both sides:</p>
<p>${f('a = \\sqrt[3]{27} = 3')}</p>
<p>Now evaluate ${f('g(4)')}:</p>
<p>${f('g(4) = 18 \\cdot 3^4 = 18 \\cdot 81 = 1{,}458')}</p>
<p><em>(Alternatively, since ${f('g(x + 1) = g(x) \\cdot a')}, ${f('g(4) = g(3) \\cdot 3 = 486 \\cdot 3 = 1{,}458')}.)</em></p>`,

  // Q3
  '6a6644f2c3d08d90637d3955': `<p><strong>The correct answer is 24.</strong></p>
<p>In the figure, parallel lines ${f('n')} and ${f('s')} are intersected by line ${f('t')}.</p>
<p>The angle corresponding to ${f('y^\\circ')} at line ${f('n')} is the top-right angle at the intersection with line ${f('n')}.</p>
<p>Because the angle labeled ${f('x^\\circ')} (top-left) and this corresponding angle (top-right) form a linear pair along line ${f('t')}, they are supplementary:</p>
<p>${f('x + y = 180')}</p>
<p>Substitute the expressions for ${f('x')} and ${f('y')}:</p>
<p>${f('(6z - 87) + (3z + 51) = 180')}</p>
<p>${f('9z - 36 = 180')}</p>
<p>Add 36 to both sides:</p>
<p>${f('9z = 216')}</p>
<p>Divide by 9:</p>
<p>${f('z = \\frac{216}{9} = 24')}</p>`,

  // Q4
  '6a6653bac3d08d90637d3975': `<p><strong>The correct answer is -7.</strong></p>
<p>The point ${f('(x, 38)')} is a solution to the system:</p>
<p>1) ${f('y > 15')}</p>
<p>2) ${f('3x + y < 19')}</p>
<p>With ${f('y = 38')}, the first inequality is satisfied since ${f('38 > 15')}.</p>
<p>Substitute ${f('y = 38')} into the second inequality:</p>
<p>${f('3x + 38 < 19')}</p>
<p>Subtract 38 from both sides:</p>
<p>${f('3x < 19 - 38 \\implies 3x < -19')}</p>
<p>Divide by 3:</p>
<p>${f('x < -\\frac{19}{3} \\approx -6.33')}</p>
<p>Among the given choices (7, 3, -3, -7), only <strong>-7</strong> is less than ${f('-6.33')}.</p>`,

  // Q5
  '6a665430c3d08d90637d3981': `<p><strong>The correct answer is "The value of the bank account is estimated to be approximately 263 dollars at the end of 1958."</strong></p>
<p>In the given model ${f('f(x) = 231(1.026)^x')}:</p>
<p>• ${f('x')} represents the number of years after the end of 1953.</p>
<p>• Therefore, ${f('x = 5')} corresponds to ${f('1953 + 5 = 1958')}.</p>
<p>• The function value ${f('f(x)')} represents the estimated value of the bank account in dollars.</p>
<p>Hence, "${f('f(5) \\approx 263')}" means that at the end of 1958, the value of the bank account is estimated to be approximately 263 dollars.</p>`,

  // Q6
  '6a665473c3d08d90637d3985': `<p><strong>The correct answer is I only.</strong></p>
<p>Expand and simplify the given expression:</p>
<p>${f('(5x + 10)(2x + 1) - (2x - 18)')}</p>
<p>First, expand the product using the distributive property (FOIL):</p>
<p>${f('(5x + 10)(2x + 1) = 10x^2 + 5x + 20x + 10 = 10x^2 + 25x + 10')}</p>
<p>Next, subtract the second term, being careful to distribute the negative sign across both terms of ${f('(2x - 18)')}:</p>
<p>${f('(10x^2 + 25x + 10) - (2x - 18) = 10x^2 + 25x + 10 - 2x + 18')}</p>
<p>Combine like terms:</p>
<p>${f('10x^2 + (25x - 2x) + (10 + 18) = 10x^2 + 23x + 28')}</p>
<p>• Roman numeral I states ${f('10x^2 + 23x + 28')}, which is equivalent to the expression.</p>
<p>• Roman numeral II states ${f('10x^2 + 25x + 10 - 2x - 18')}, which incorrectly subtracts 18 instead of adding 18.</p>
<p>Therefore, <strong>I only</strong> is equivalent.</p>`,

  // Q7
  '6a6654abc3d08d90637d3989': `<p><strong>The correct answer is the table with pairs (2, 22), (4, 29), and (6, 35).</strong></p>
<p>We are given the inequality ${f('y < 4x + 15')}. Test each pair in this table:</p>
<p>• For ${f('x = 2')}: ${f('4(2) + 15 = 23')}. The given ${f('y = 22 < 23')} is true.</p>
<p>• For ${f('x = 4')}: ${f('4(4) + 15 = 31')}. The given ${f('y = 29 < 31')} is true.</p>
<p>• For ${f('x = 6')}: ${f('4(6) + 15 = 39')}. The given ${f('y = 35 < 39')} is true.</p>
<p>Since all three pairs satisfy the inequality, this table contains only valid solutions.</p>`,

  // Q8
  '6a6654eec3d08d90637d398d': `<p><strong>The correct answer is ${f('-8a + 25')}.</strong></p>
<p>Set the function definition equal to ${f('2a')}:</p>
<p>${f('-\\frac{1}{4}(x - 9) + 4 = 2a')}</p>
<p>Subtract 4 from both sides:</p>
<p>${f('-\\frac{1}{4}(x - 9) = 2a - 4')}</p>
<p>Multiply both sides by ${f('-4')}:</p>
<p>${f('x - 9 = -4(2a - 4) = -8a + 16')}</p>
<p>Add 9 to both sides:</p>
<p>${f('x = -8a + 16 + 9 = -8a + 25')}</p>`,

  // Q9
  '6a66551cc3d08d90637d3999': `<p><strong>The correct answer is 64.</strong></p>
<p>We are given the equation:</p>
<p>${f('\\sqrt{x - 5} = 8')}</p>
<p>Square both sides of the equation:</p>
<p>${f('(\\sqrt{x - 5})^2 = 8^2')}</p>
<p>${f('x - 5 = 64')}</p>
<p>The question asks directly for the value of ${f('x - 5')}, which is <strong>64</strong>.</p>`,

  // Q10
  '6a665553c3d08d90637d399d': `<p><strong>The correct answer is 3.</strong></p>
<p>We are given the system:</p>
<p>1) ${f('2(8x) + 7(6y) = 21')}</p>
<p>2) ${f('-2(8x) + 7(6y) = 21')}</p>
<p>Add the two equations together to eliminate the ${f('8x')} term:</p>
<p>${f('[2(8x) + (-2(8x))] + [7(6y) + 7(6y)] = 21 + 21')}</p>
<p>${f('14(6y) = 42')}</p>
<p>Divide by 14:</p>
<p>${f('6y = 3')}</p>
<p>Now subtract the second equation from the first to eliminate the ${f('6y')} term:</p>
<p>${f('4(8x) = 0 \\implies 8x = 0')}</p>
<p>We are asked for the value of ${f('8x + 6y')}:</p>
<p>${f('8x + 6y = 0 + 3 = 3')}</p>`,

  // Q11
  '6a6655c8c3d08d90637d39a1': `<p><strong>The correct answer is 329.</strong></p>
<p>Expand the product ${f('(3x^9 + q)(rx^9 + 2)')}:</p>
<p>${f('(3x^9 + q)(rx^9 + 2) = 3r x^{18} + 6x^9 + qrx^9 + 2q = 3r x^{18} + (6 + qr)x^9 + 2q')}</p>
<p>Equate the coefficients with ${f('57x^{18} + bx^9 + 34')}:</p>
<p>• Leading coefficient: ${f('3r = 57 \\implies r = 19')}</p>
<p>• Constant term: ${f('2q = 34 \\implies q = 17')}</p>
<p>• Middle coefficient: ${f('b = 6 + qr')}</p>
<p>Substitute ${f('r = 19')} and ${f('q = 17')}:</p>
<p>${f('b = 6 + (17)(19) = 6 + 323 = 329')}</p>`,

  // Q12
  '6a665637c3d08d90637d39a7': `<p><strong>The correct answer is II only.</strong></p>
<p>Consider the effects of adding a single game with a score of 17 points to an existing data set of 50 games:</p>
<p><strong>I. Median:</strong> The median depends on the middle values. Adding a low value shifts the median position from the average of the 25th and 26th values to the 26th value. If multiple values around the center fall into the same bin or are identical, the median may not decrease at all. Thus, statement I is not guaranteed to be true.</p>
<p><strong>II. Mean:</strong> The mean of the original 50 games is significantly greater than 17. Whenever a new value that is strictly less than the existing mean is added to a data set, the new mean is strictly less than the original mean:</p>
<p>${f('\\text{New Mean} = \\frac{50 \\cdot (\\text{Old Mean}) + 17}{51} < \\text{Old Mean}')}</p>
<p>Thus, statement II <strong>must be true</strong>.</p>`,

  // Q13
  '6a665696c3d08d90637d39ab': `<p><strong>The correct answer is 6.</strong></p>
<p>A cubic polynomial with leading coefficient 1 and zeros at ${f('-2, -7, 3')} can be factored completely as:</p>
<p>${f('g(x) = (x - (-2))(x - (-7))(x - 3) = (x + 2)(x + 7)(x - 3)')}</p>
<p>By Vieta's formulas, the coefficient ${f('a')} of the ${f('x^2')} term in a monic polynomial ${f('x^3 + ax^2 + bx + c')} is the negative of the sum of the roots:</p>
<p>${f('a = -((-2) + (-7) + 3) = -(-6) = 6')}</p>
<p>Alternatively, expanding the product confirms:</p>
<p>${f('(x + 2)(x + 7) = x^2 + 9x + 14')}</p>
<p>${f('(x^2 + 9x + 14)(x - 3) = x^3 - 3x^2 + 9x^2 - 27x + 14x - 42 = x^3 + 6x^2 - 13x - 42')}</p>
<p>Thus, ${f('a = 6')}.</p>`,

  // Q14
  '6a665703c3d08d90637d39af': `<p><strong>The correct answer is ${f('g(x) = n(4.41)^x')}.</strong></p>
<p>In the function ${f('f(x) = 18(2.10)^{x/2}')}, when ${f('x')} increases by 4, the factor by which ${f('f(x)')} is multiplied is:</p>
<p>${f('\\frac{f(x + 4)}{f(x)} = (2.10)^{\\frac{4}{2}} = (2.10)^2 = 4.41')}</p>
<p>This means ${f('f(x)')} increases by ${f('p\\% = (4.41 - 1) \\times 100\\% = 341\\%')} for every increase of 4 in ${f('x')}.</p>
<p>We seek a function ${f('g(x) = n \\cdot B^x')} that increases by this same percentage (${f('p\\%')}) when ${f('x')} increases by 1:</p>
<p>${f('\\frac{g(x + 1)}{g(x)} = B^1 = 4.41 \\implies B = 4.41')}</p>
<p>Therefore, the function is ${f('g(x) = n(4.41)^x')}.</p>`,

  // Q15
  '6a665737c3d08d90637d39b3': `<p><strong>The correct answer is ${f('0.33x + 0.83y = 3.1')}.</strong></p>
<p>Determine the rate of vitamin B12 per ounce for each food:</p>
<p>• A 3.0-ounce serving of cheddar cheese provides 1 microgram of B12:</p>
<p>${f('\\frac{1\\text{ microgram}}{3.0\\text{ ounces}} \\approx 0.33\\text{ micrograms per ounce}')}</p>
<p>• A 1.2-ounce serving of tuna provides 1 microgram of B12:</p>
<p>${f('\\frac{1\\text{ microgram}}{1.2\\text{ ounces}} = \\frac{10}{12} \\approx 0.83\\text{ micrograms per ounce}')}</p>
<p>The total vitamin B12 from ${f('x')} ounces of cheese and ${f('y')} ounces of tuna is 3.1 micrograms:</p>
<p>${f('0.33x + 0.83y = 3.1')}</p>`,

  // Q16
  '6a665778c3d08d90637d39bf': `<p><strong>The correct answer is -4.</strong></p>
<p>The standard equation of a circle with center ${f('(h, k) = (-4, 4)')} and radius ${f('r = 6')} is:</p>
<p>${f('(x - (-4))^2 + (y - 4)^2 = 6^2')}</p>
<p>${f('(x + 4)^2 + (y - 4)^2 = 36')}</p>
<p>Expand the squared terms:</p>
<p>${f('(x^2 + 8x + 16) + (y^2 - 8y + 16) = 36')}</p>
<p>${f('x^2 + y^2 + 8x - 8y + 32 = 36')}</p>
<p>Subtract 36 from both sides to put into the form ${f('x^2 + y^2 + ax + by + c = 0')}:</p>
<p>${f('x^2 + y^2 + 8x - 8y - 4 = 0')}</p>
<p>Matching coefficients, the constant ${f('c = -4')}.</p>`,

  // Q17
  '6a6657bec3d08d90637d39c3': `<p><strong>The correct answer is 2100.</strong></p>
<p>For two similar three-dimensional figures with linear scale factor ${f('k')}:</p>
<p>• The ratio of their surface areas is ${f('k^2')}.</p>
<p>• The ratio of their volumes is ${f('k^3')}.</p>
<p>Given the surface areas of prisms ${f('X')} and ${f('Y')}:</p>
<p>${f('k^2 = \\frac{\\text{Surface Area of } Y}{\\text{Surface Area of } X} = \\frac{1{,}550}{62} = 25')}</p>
<p>Taking the square root gives the linear scale factor:</p>
<p>${f('k = \\sqrt{25} = 5')}</p>
<p>The volume ratio is:</p>
<p>${f('\\frac{\\text{Volume of } Y}{\\text{Volume of } X} = k^3 = 5^3 = 125')}</p>
<p>Given that the volume of prism ${f('X')} is ${f('16.8\\text{ cm}^3')}:</p>
<p>${f('\\text{Volume of } Y = 125 \\times 16.8 = 2{,}100\\text{ cm}^3')}</p>`,

  // Q18
  '6a6657f9c3d08d90637d39c9': `<p><strong>The correct answer is 75.</strong></p>
<p>Let ${f('N')} be the initial number of predators and prey at the start of the week.</p>
<p>At the end of the week:</p>
<p>• The prey increased by 2100%:</p>
<p>${f('\\text{Prey} = N + 21.00N = 22N')}</p>
<p>• The predators increased by 450%:</p>
<p>${f('\\text{Predators} = N + 4.50N = 5.5N')}</p>
<p>The percentage ${f('p\\%')} by which the predators are less than the prey is:</p>
<p>${f('p = \\frac{\\text{Prey} - \\text{Predators}}{\\text{Prey}} \\times 100')}</p>
<p>${f('p = \\frac{22N - 5.5N}{22N} \\times 100 = \\frac{16.5N}{22N} \\times 100 = 0.75 \\times 100 = 75')}</p>`,

  // Q19
  '6a665828c3d08d90637d39cd': `<p><strong>The correct answer is 0.34.</strong></p>
<p>We are given the rate of area increase as 220 square feet per hour.</p>
<p>Convert units using dimensional analysis:</p>
<p>• Convert feet to meters: Since ${f('1\\text{ meter} = 3.28\\text{ feet}')},</p>
<p>${f('1\\text{ square meter} = (3.28\\text{ feet})^2 = 10.7584\\text{ square feet}')}</p>
<p>• Convert hours to minutes: ${f('1\\text{ hour} = 60\\text{ minutes}')}.</p>
<p>Now perform the complete conversion:</p>
<p>${f('\\text{Rate} = \\frac{220\\text{ ft}^2}{1\\text{ hr}} \\times \\frac{1\\text{ m}^2}{10.7584\\text{ ft}^2} \\times \\frac{1\\text{ hr}}{60\\text{ min}} = \\frac{220}{10.7584 \\times 60} = \\frac{220}{645.504} \\approx 0.3408\\text{ m}^2/\\text{min}')}</p>
<p>The closest value is <strong>0.34</strong>.</p>`,

  // Q20
  '6a665878c3d08d90637d39d1': `<p><strong>The correct answer is ${f('y = -\\frac{3}{2}x + 10')}.</strong></p>
<p>First, find the slope of line ${f('k')} from the graph. The line passes through the points ${f('(2, 0)')} and ${f('(8, 4)')}:</p>
<p>${f('m_k = \\frac{4 - 0}{8 - 2} = \\frac{4}{6} = \\frac{2}{3}')}</p>
<p>Since line ${f('n')} is perpendicular to line ${f('k')}, its slope ${f('m_n')} is the negative reciprocal of ${f('m_k')}:</p>
<p>${f('m_n = -\\frac{1}{2/3} = -\\frac{3}{2}')}</p>
<p>Line ${f('n')} passes through the point ${f('(2, 7)')}. Using point-slope form:</p>
<p>${f('y - 7 = -\\frac{3}{2}(x - 2)')}</p>
<p>${f('y - 7 = -\\frac{3}{2}x + 3')}</p>
<p>Add 7 to both sides:</p>
<p>${f('y = -\\frac{3}{2}x + 10')}</p>`,

  // Q21
  '6a6658e9c3d08d90637d39d5': `<p><strong>The correct answer is 5.</strong></p>
<p>The question asks for the number of data points where the actual ${f('y')}-value is greater than the predicted ${f('y')}-value from the line of best fit.</p>
<p>A point satisfies this condition if and only if it lies vertically <strong>above</strong> the line of best fit.</p>
<p>Carefully inspecting the 9 plotted data points:</p>
<p>• Points above the line: 5 points (located at ${f('x \\approx 3.6, 6.0, 6.5, 8.4, 9.8')})</p>
<p>• Points below the line: 4 points (located at ${f('x \\approx 5.5, 6.9, 7.3, 9.4')})</p>
<p>Thus, exactly <strong>5</strong> data points have an actual ${f('y')}-value greater than predicted.</p>`,

  // Q22
  '6a665917c3d08d90637d39d9': `<p><strong>The correct answer is 17.</strong></p>
<p>Notice the repeated expression ${f('8 - 3x')} on both sides of the equation:</p>
<p>${f('9(8 - 3x) + 2 = 8(8 - 3x) + 19')}</p>
<p>Let ${f('u = 8 - 3x')}. The equation becomes:</p>
<p>${f('9u + 2 = 8u + 19')}</p>
<p>Subtract ${f('8u')} from both sides:</p>
<p>${f('u + 2 = 19')}</p>
<p>Subtract 2 from both sides:</p>
<p>${f('u = 17')}</p>
<p>Therefore, the value of ${f('8 - 3x')} is <strong>17</strong>.</p>`
};

async function run() {
  console.log('🚀 Injecting 22 explanations for October 2025 · INT 1 Module 2...\n');
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
