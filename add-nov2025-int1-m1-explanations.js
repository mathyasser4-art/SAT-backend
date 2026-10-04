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
  '6a5b4731c3d08d90637d3156': `<p><strong>Choice D is correct.</strong></p>
<p>Notice that each term in the expression ${f('90x + 40')} is 10 times the corresponding term in the given equation ${f('9x + 4 = 67')}:</p>
<p>${f('90x + 40 = 10(9x + 4)')}</p>
<p>Substitute ${f('9x + 4 = 67')}:</p>
<p>${f('90x + 40 = 10(67) = 670')}</p>
<p>Alternatively, solving for ${f('x')}: ${f('9x = 63 \\implies x = 7')}. Then ${f('90(7) + 40 = 630 + 40 = 670')}.</p>
<p><strong>Choice A is incorrect</strong> because 7 is the value of ${f('x')}.</p>
<p><strong>Choices B and C are incorrect</strong> and reflect arithmetic calculation errors.</p>`,

  // Q2
  '6a5b47c0c3d08d90637d315a': `<p><strong>Choice B is correct.</strong></p>
<p>In the figure, parallel line ${f('p')} is intersected by transversal line ${f('t')}.</p>
<p>Angle ${f('x^\\circ')} and angle ${f('72^\\circ')} are vertical angles formed by the intersection of line ${f('p')} and transversal ${f('t')}.</p>
<p>Because vertical angles are always congruent, their measures are equal:</p>
<p>${f('x = 72')}</p>
<p><strong>Choice A is incorrect</strong> because 36 is half of 72.</p>
<p><strong>Choice C is incorrect</strong> because 180 is the straight angle measure.</p>
<p><strong>Choice D is incorrect</strong> because 252 is ${f('180 + 72')}.</p>`,

  // Q3
  '6a5b47f6c3d08d90637d315e': `<p><strong>The correct answer is 4500.</strong></p>
<p>We are given that ${f('1 \\text{ meter} = 10 \\text{ decimeters}')}.</p>
<p>To convert 450 meters to decimeters, multiply by 10:</p>
<p>${f('450 \\text{ meters} \\times 10 \\frac{\\text{decimeters}}{\\text{meter}} = 4,500 \\text{ decimeters}')}</p>`,

  // Q4
  '6a5b4839c3d08d90637d3162': `<p><strong>The correct answer is 15.</strong></p>
<p>The perimeter equation is given as ${f('58 = 2x + 2y')}, where ${f('x')} is the length and ${f('y')} is the width.</p>
<p>Substitute the given width ${f('y = 14')}:</p>
<p>${f('58 = 2x + 2(14)')}</p>
<p>${f('58 = 2x + 28')}</p>
<p>Subtract 28 from both sides:</p>
<p>${f('2x = 30')}</p>
<p>Divide by 2:</p>
<p>${f('x = 15')}</p>`,

  // Q5
  '6a5b48c8c3d08d90637d3166': `<p><strong>Choice A is correct.</strong></p>
<p>An exponential equation has the form ${f('y = a(b)^x')}, where ${f('a')} is the initial value at ${f('x = 0')} and ${f('b')} is the growth multiplier.</p>
<p>We are given that when ${f('x = 0')}, ${f('y = 40')}, so ${f('a = 40')}.</p>
<p>Each unit increase in ${f('x')} increases ${f('y')} by 50% of its previous value, so the multiplier is:</p>
<p>${f('b = 1 + 0.50 = 1.50')}</p>
<p>Thus, the equation is ${f('y = 40(1.50)^x')}.</p>
<p><strong>Choice B is incorrect</strong> because base 1.05 represents a 5% increase rather than 50%.</p>
<p><strong>Choices C and D are incorrect</strong> because they use 50 as the initial value instead of 40.</p>`,

  // Q6
  '6a5b4936c3d08d90637d316a': `<p><strong>The correct answer is 1/72.</strong></p>
<p>Substitute ${f('x = 9')} into the function definition ${f('f(x) = \\frac{1}{8x}')}:</p>
<p>${f('f(9) = \\frac{1}{8(9)} = \\frac{1}{72}')}</p>`,

  // Q7
  '6a5b498bc3d08d90637d316e': `<p><strong>Choice A is correct.</strong></p>
<p>The ${f('y')}-intercept occurs where ${f('x = 0')}:</p>
<p>${f('f(0) = 3(0) - \\frac{1}{4} = -\\frac{1}{4}')}</p>
<p>Therefore, the coordinates of the ${f('y')}-intercept are ${f('\\left(0, -\\frac{1}{4}\\right)')}.</p>
<p><strong>Choice B is incorrect</strong> because ${f('-3')} is the negative of the slope.</p>
<p><strong>Choice C is incorrect</strong> because 3 is the slope, not the intercept.</p>
<p><strong>Choice D is incorrect</strong> because 4 is the reciprocal denominator.</p>`,

  // Q8
  '6a5b49c6c3d08d90637d3172': `<p><strong>The correct answer is 14.</strong></p>
<p>The system of equations is:</p>
<p>${f('x + 6y = 28')}</p>
<p>${f('6y = 14')}</p>
<p>Substitute ${f('6y = 14')} directly into the first equation:</p>
<p>${f('x + 14 = 28')}</p>
<p>Subtract 14 from both sides:</p>
<p>${f('x = 28 - 14 = 14')}</p>`,

  // Q9
  '6a5b4a01c3d08d90637d3176': `<p><strong>Choice B is correct.</strong></p>
<p>First, calculate the area of square X with side length 9 cm:</p>
<p>${f('\\text{Area of square X} = 9^2 = 81 \\text{ cm}^2')}</p>
<p>The area of rectangle Y is given as 32 square centimeters.</p>
<p>The total area of square X and rectangle Y combined is:</p>
<p>${f('\\text{Total area} = 81 + 32 = 113 \\text{ cm}^2')}</p>
<p><strong>Choice A is incorrect</strong> and results from arithmetic miscalculation.</p>
<p><strong>Choice C is incorrect</strong> because 82 is ${f('81 + 1')}.</p>
<p><strong>Choice D is incorrect</strong> because 81 is the area of square X alone.</p>`,

  // Q10
  '6a5b4a64c3d08d90637d318a': `<p><strong>Choice C is correct.</strong></p>
<p>The black bear enters hibernation weighing 293 pounds and needs to reach 230 pounds.</p>
<p>The total weight lost is:</p>
<p>${f('293 - 230 = 63 \\text{ pounds}')}</p>
<p>At a mean rate of 0.9 pounds per day, the number of days required is:</p>
<p>${f('\\text{Number of days} = \\frac{63}{0.9} = 70')}</p>
<p><strong>Choices A, B, and D are incorrect</strong> and reflect arithmetic calculation errors.</p>`,

  // Q11
  '6a5b4acac3d08d90637d319b': `<p><strong>Choice C is correct.</strong></p>
<p>The values of ${f('x')} for which ${f('f(x) = 0')} correspond to the ${f('x')}-intercepts of the graph of ${f('y = f(x)')}.</p>
<p>Observing the complete graph, the curve intersects the horizontal ${f('x')}-axis at 3 distinct points (at ${f('x = -4')}, ${f('x = 0')}, and ${f('x = 2')}).</p>
<p>Therefore, there are <strong>three</strong> values of ${f('x')} for which ${f('f(x) = 0')}.</p>
<p><strong>Choices A, B, and D are incorrect</strong> because the graph clearly crosses the ${f('x')}-axis at exactly three locations.</p>`,

  // Q12
  '6a5b4fafc3d08d90637d319f': `<p><strong>Choice C is correct.</strong></p>
<p>Isolate ${f('b^2')} in the given equation ${f('b^2 - 4c = 7d')}:</p>
<p>${f('b^2 = 7d + 4c')}</p>
<p>Take the square root of both sides:</p>
<p>${f('b = \\pm \\sqrt{7d + 4c}')}</p>
<p><strong>Choices A and B are incorrect</strong> because dividing by 2 confuses squaring with doubling.</p>
<p><strong>Choice D is incorrect</strong> because the term is ${f('+4c')}, not ${f('-4c')}.</p>`,

  // Q13
  '6a5b4fefc3d08d90637d31a5': `<p><strong>Choice C is correct.</strong></p>
<p>Isolate ${f('x^2')} in the given equation:</p>
<p>${f('x^2 = \\frac{81}{16}')}</p>
<p>Take the square root of both sides:</p>
<p>${f('x = \\pm \\sqrt{\\frac{81}{16}} = \\pm \\frac{9}{4}')}</p>
<p>The equation has two distinct real solutions: ${f('x = \\frac{9}{4}')} and ${f('x = -\\frac{9}{4}')}.</p>
<p>Therefore, the equation has <strong>exactly two</strong> distinct real solutions.</p>
<p><strong>Choices A, B, and D are incorrect</strong> because a non-zero positive constant on the right yields two real symmetric roots.</p>`,

  // Q14
  '6a5b50adc3d08d90637d31a9': `<p><strong>Choice D is correct.</strong></p>
<p>When a geometric figure is dilated by a scale factor of ${f('k')}, every side length of the image is ${f('k')} times the corresponding side length of the pre-image.</p>
<p>Here, the scale factor is ${f('k = 6')} and the length of corresponding side ${f('AB = 18')}:</p>
<p>${f('A\'B\' = 6 \\times AB = 6 \\times 18 = 108')}</p>
<p><strong>Choice A is incorrect</strong> because 3 results from dividing by 6 (${f('18 / 6')}).</p>
<p><strong>Choice B is incorrect</strong> because 6 is the scale factor.</p>
<p><strong>Choice C is incorrect</strong> because 24 results from adding 6 to 18 (${f('18 + 6')}).</p>`,

  // Q15
  '6a5b50f8c3d08d90637d31b5': `<p><strong>The correct answer is 19.</strong></p>
<p>The standard equation of a circle in the ${f('xy')}-plane is:</p>
<p>${f('(x - h)^2 + (y - k)^2 = r^2')}</p>
<p>where ${f('(h, k)')} is the center and ${f('r')} is the radius.</p>
<p>Comparing this to the given equation ${f('(x + 3)^2 + (y + 9)^2 = 361')}:</p>
<p>${f('r^2 = 361 \\implies r = \\sqrt{361} = 19')}</p>`,

  // Q16
  '6a5b5166c3d08d90637d31b9': `<p><strong>Choice D is correct.</strong></p>
<p>Consider the inequality ${f('5x - 7y > 35')}.</p>
<p>In the region where ${f('x < 0')} and ${f('y > 0')} (Quadrant II):</p>
<ul>
  <li>Since ${f('x < 0')}, ${f('5x < 0')} (strictly negative).</li>
  <li>Since ${f('y > 0')}, ${f('-7y < 0')} (strictly negative).</li>
</ul>
<p>The sum of two strictly negative quantities is always strictly negative:</p>
<p>${f('5x - 7y < 0')}</p>
<p>Since ${f('5x - 7y < 0')}, it can never be greater than 35. Therefore, this region contains no solutions.</p>
<p><strong>Choices A, B, and C are incorrect</strong> because they all contain points that satisfy the inequality (for example, ${f('(10, 0)')} on the ${f('x')}-axis gives ${f('5(10) - 0 = 50 > 35')}).</p>`,

  // Q17
  '6a5b5198c3d08d90637d31bd': `<p><strong>Choice B is correct.</strong></p>
<p>We are asked to find the conditional probability of selecting a person who is greater than 65 years old, given that the person is at least 18 years old:</p>
<p>${f('P(\\text{> 65} \\mid \\text{\\ge 18}) = \\frac{P(\\text{> 65})}{P(\\text{\\ge 18})}')}</p>
<p>From the table, the proportion of people at least 18 years old is the sum of the three adult age groups:</p>
<p>${f('P(\\text{\\ge 18}) = 21\\% + 29\\% + 24\\% = 74\\% = 0.74')}</p>
<p>The proportion of people greater than 65 years old is ${f('24\\% = 0.24')}.</p>
<p>Calculate the conditional probability:</p>
<p>${f('P = \\frac{0.24}{0.74} = \\frac{24}{74} = \\frac{12}{37} \\approx 0.3243')}</p>
<p>Rounding to the nearest hundredth gives <strong>0.32</strong>.</p>
<p><strong>Choice A is incorrect</strong> because 0.24 is the unconditioned probability out of the entire city population.</p>
<p><strong>Choices C and D are incorrect</strong> and reflect arithmetic calculation errors.</p>`,

  // Q18
  '6a5b520ac3d08d90637d31c9': `<p><strong>Choice D is correct.</strong></p>
<p>Find the slope of line ${f('h')} by converting its equation to slope-intercept form ${f('y = mx + b')}:</p>
<p>${f('\\frac{1}{2}x + \\frac{1}{9}y - 54 = 0')}</p>
<p>${f('\\frac{1}{9}y = -\\frac{1}{2}x + 54')}</p>
<p>Multiply by 9:</p>
<p>${f('y = -\\frac{9}{2}x + 486')}</p>
<p>The slope of line ${f('h')} is ${f('m_h = -\\frac{9}{2}')}.</p>
<p>Since line ${f('j')} is perpendicular to line ${f('h')}, its slope is the negative reciprocal:</p>
<p>${f('m_j = -\\frac{1}{m_h} = -\\frac{1}{-\\frac{9}{2}} = \\frac{2}{9}')}</p>
<p><strong>Choice A is incorrect</strong> because ${f('-\\frac{9}{2}')} is the slope of line ${f('h')}.</p>
<p><strong>Choice B is incorrect</strong> because it has a negative sign.</p>
<p><strong>Choice C is incorrect</strong> because ${f('\\frac{9}{2}')} is the negative of the slope without taking the reciprocal.</p>`,

  // Q19
  '6a5b5277c3d08d90637d31cd': `<p><strong>Choice C is correct.</strong></p>
<p>The 7 data values are listed in ascending order: ${f('a, 26, 29, b, 31, 47, c')}.</p>
<p>The median is the 4th value in the sorted list, which is ${f('b')}:</p>
<p>${f('b = 29')}</p>
<p>The mean of the 7 values is 36, so their sum is:</p>
<p>${f('\\text{Sum} = 7 \\times 36 = 252')}</p>
<p>Add the known values:</p>
<p>${f('a + 26 + 29 + 29 + 31 + 47 + c = 252')}</p>
<p>${f('a + c + 162 = 252 \\implies a + c = 90')}</p>
<p>The range of the data set is 72, which is the difference between the maximum ${f('c')} and minimum ${f('a')}:</p>
<p>${f('c - a = 72')}</p>
<p>Add the two equations together:</p>
<p>${f('(a + c) + (c - a) = 90 + 72')}</p>
<p>${f('2c = 162 \\implies c = 81')}</p>
<p><strong>Choices A, B, and D are incorrect</strong> and reflect arithmetic miscalculations.</p>`,

  // Q20
  '6a5b52bcc3d08d90637d31d1': `<p><strong>Choice D is correct.</strong></p>
<p>In right triangle ${f('QRS')} with right angle at ${f('R')}, the side opposite to angle ${f('Q')} is ${f('RS = 37')}, and the hypotenuse is ${f('QS')}.</p>
<p>By the definition of sine for acute angle ${f('Q')}:</p>
<p>${f('\\sin Q = \\frac{\\text{opposite}}{\\text{hypotenuse}} = \\frac{RS}{QS} = \\frac{37}{QS}')}</p>
<p>Solving for the hypotenuse ${f('QS')}:</p>
<p>${f('QS = \\frac{37}{\\sin Q}')}</p>
<p><strong>Choice A is incorrect</strong> because it multiplies by cosine.</p>
<p><strong>Choice B is incorrect</strong> because ${f('37 \\sin Q')} would be the side if 37 were the hypotenuse.</p>
<p><strong>Choice C is incorrect</strong> because cosine uses the adjacent side ${f('QR')}.</p>`,

  // Q21
  '6a5b534fc3d08d90637d31d5': `<p><strong>Choice B is correct.</strong></p>
<p>To find the number of times the graph crosses the ${f('x')}-axis, set ${f('y = 0')}:</p>
<p>${f('0 = 9 \\left(\\frac{a}{7}\\right)^{x - c} - b \\implies 9 \\left(\\frac{a}{7}\\right)^{x - c} = b \\implies \\left(\\frac{a}{7}\\right)^{x - c} = \\frac{b}{9}')}</p>
<p>We are given that ${f('a > 7')}, so the base ${f('\\frac{a}{7} > 1')}. This means the exponential function ${f('\\left(\\frac{a}{7}\\right)^{x - c}')} is strictly increasing for all real numbers ${f('x')}.</p>
<p>Because ${f('b > 0')}, ${f('\\frac{b}{9} > 0')}. Taking the logarithm base ${f('\\frac{a}{7}')} of both sides:</p>
<p>${f('x - c = \\log_{a/7}\\left(\\frac{b}{9}\\right) \\implies x = c + \\log_{a/7}\\left(\\frac{b}{9}\\right)')}</p>
<p>Since the logarithmic function has a unique real value for any positive input, there is exactly <strong>one</strong> real solution for ${f('x')}. Therefore, the graph crosses the ${f('x')}-axis exactly once.</p>
<p><strong>Choices A, C, and D are incorrect</strong> because an exponential function with a negative vertical shift crosses the horizontal axis exactly once.</p>`,

  // Q22
  '6a5b53d1c3d08d90637d31d9': `<p><strong>Choice D is correct.</strong></p>
<p>We are given that ${f('1 \\text{ mile} = 1,760 \\text{ yards}')}.</p>
<p>To convert square miles to square yards, square the linear conversion factor:</p>
<p>${f('1 \\text{ mile}^2 = (1,760 \\text{ yards})^2 = 3,097,600 \\text{ yards}^2')}</p>
<p>Multiply the town's area of 4.29 square miles by this conversion factor:</p>
<p>${f('\\text{Area} = 4.29 \\times 3,097,600 = 13,288,704 \\text{ square yards}')}</p>
<p><strong>Choice A is incorrect</strong> because 410 results from dividing 1,760 by 4.29.</p>
<p><strong>Choice B is incorrect</strong> because 7,550 results from multiplying 4.29 by 1,760 linearly without squaring.</p>
<p><strong>Choice C is incorrect</strong> and reflects an arithmetic calculation error.</p>`
};

async function run() {
    console.log('🚀 Injecting Explanations for November 2025 · INT 1 — Module 1...\n');
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
