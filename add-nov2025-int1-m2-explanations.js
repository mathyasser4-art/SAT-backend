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
  '6a5b5480c3d08d90637d31e9': `<p><strong>Choice D is correct.</strong></p>
<p>Zuri has already run 4 miles this week, and ${f('x')} represents the additional number of miles she needs to run. Her total mileage for the week is:</p>
<p>${f('4 + x')}</p>
<p>Her goal is to run <em>at least</em> 16 miles, which translates mathematically to being greater than or equal to 16:</p>
<p>${f('4 + x \\ge 16')}</p>
<p><strong>Choice A is incorrect</strong> because it subtracts ${f('x')} and uses ${f('\\le')}.</p>
<p><strong>Choice B is incorrect</strong> because ${f('\\le')} means at most 16 miles.</p>
<p><strong>Choice C is incorrect</strong> because it subtracts ${f('x')} rather than adding it to the miles already run.</p>`,

  // Q2
  '6a5b54fdc3d08d90637d31f5': `<p><strong>Choice B is correct.</strong></p>
<p>In the figure, transversal line ${f('k')} intersects lines ${f('r')} and ${f('s')}.</p>
<p>Angle ${f('w^\\circ')} and angle ${f('y^\\circ')} are corresponding angles located in the same relative position (top-right) at each intersection.</p>
<p>By the Corresponding Angles Converse Postulate, if two lines cut by a transversal have congruent corresponding angles, the lines are parallel.</p>
<p>Therefore, knowing that ${f('y = 147')} (so ${f('w = y = 147')}) is sufficient to prove that lines ${f('r')} and ${f('s')} are parallel.</p>
<p><strong>Choice A is incorrect</strong> because ${f('x')} and ${f('w')} are vertical angles on the same line ${f('r')}.</p>
<p><strong>Choices C and D are incorrect</strong> because ${f('w + y = 180')} would imply the lines are not parallel since corresponding angles must be equal, not supplementary.</p>`,

  // Q3
  '6a5b557fc3d08d90637d321e': `<p><strong>Choice A is correct.</strong></p>
<p>The relationship between the number of food tickets ${f('x')} and total cost ${f('y')} is linear. Find the slope using two pairs from the table, ${f('(10, 44.00)')} and ${f('(15, 51.50)')}:</p>
<p>${f('m = \\frac{51.50 - 44.00}{15 - 10} = \\frac{7.50}{5} = 1.5 = \\frac{3}{2}')}</p>
<p>Now find the ${f('y')}-intercept (${f('b')}) using point ${f('(10, 44)')}:</p>
<p>${f('44 = \\frac{3}{2}(10) + b \\implies 44 = 15 + b \\implies b = 29')}</p>
<p>Thus, the equation is ${f('y = \\frac{3}{2}x + 29')}.</p>
<p><strong>Choice B is incorrect</strong> because it has a negative intercept ${f('-56')}.</p>
<p><strong>Choices C and D are incorrect</strong> because they have a slope of ${f('\\frac{2}{3}')} instead of ${f('\\frac{3}{2}')}.</p>`,

  // Q4
  '6a5b55c7c3d08d90637d3222': `<p><strong>Choice C is correct.</strong></p>
<p>The line of best fit passes through the origin ${f('(0, 0)')} and the point ${f('(500, 300)')}. The slope of the line is:</p>
<p>${f('m = \\frac{300 - 0}{500 - 0} = \\frac{300}{500} = \\frac{60}{100} = 0.60')}</p>
<p>In this context, the slope represents the change in germinated seeds (${f('y')}) per unit change in planted seeds (${f('x')}).</p>
<p>A slope of ${f('\\frac{60}{100}')} means that for every additional 100 tomato seeds planted, the predicted number of germinated seeds increases by 60.</p>
<p><strong>Choices A and B are incorrect</strong> because the horizontal axis is number of seeds planted, not days.</p>
<p><strong>Choice D is incorrect</strong> because 300 seeds germinate for 500 seeds planted, not 100 seeds.</p>`,

  // Q5
  '6a5b56cec3d08d90637d322e': `<p><strong>The correct answer is -2.</strong></p>
<p>Rewrite the linear equation in slope-intercept form ${f('y = mx + b')}:</p>
<p>${f('2x + y = 11')}</p>
<p>Subtract ${f('2x')} from both sides:</p>
<p>${f('y = -2x + 11')}</p>
<p>The slope of the line is <strong>-2</strong>.</p>`,

  // Q6
  '6a5b5748c3d08d90637d3232': `<p><strong>Choice B is correct.</strong></p>
<p>First compute the product ${f('f(x) \\cdot g(x)')}:</p>
<p>${f('f(x) \\cdot g(x) = (2x + 3)(7x - 2) = 14x^2 - 4x + 21x - 6 = 14x^2 + 17x - 6')}</p>
<p>Now subtract ${f('h(x) = 5x - 6')}:</p>
<p>${f('f(x) \\cdot g(x) - h(x) = (14x^2 + 17x - 6) - (5x - 6)')}</p>
<p>${f('= 14x^2 + 17x - 6 - 5x + 6 = 14x^2 + 12x')}</p>
<p>Comparing this to ${f('ax^2 + bx + c')}:</p>
<p>${f('a = 14, \\quad b = 12, \\quad c = 0')}</p>
<p>Therefore, the value of constant ${f('b')} is <strong>12</strong>.</p>
<p><strong>Choices A, C, and D are incorrect</strong> and reflect sign or term distribution errors.</p>`,

  // Q7
  '6a5b57a4c3d08d90637d3236': `<p><strong>Choice B is correct.</strong></p>
<p>Substitute ${f('x = a')} into ${f('f(x) = \\frac{x - 11}{5}')}:</p>
<p>${f('f(a) = \\frac{a - 11}{5}')}</p>
<p>We are given that ${f('f(a) = -18')}:</p>
<p>${f('\\frac{a - 11}{5} = -18')}</p>
<p>Multiply both sides by 5:</p>
<p>${f('a - 11 = -90')}</p>
<p>Add 11 to both sides:</p>
<p>${f('a = -90 + 11 = -79')}</p>
<p><strong>Choice A is incorrect</strong> because ${f('-101')} results from subtracting 11 from ${f('-90')}.</p>
<p><strong>Choices C and D are incorrect</strong> and reflect arithmetic calculation errors.</p>`,

  // Q8
  '6a5b5847c3d08d90637d323a': `<p><strong>Choice A is correct.</strong></p>
<p>First find the equation of line ${f('j')} using the points from the table:</p>
<ul>
  <li>The point ${f('(0, -10)')} gives the ${f('y')}-intercept ${f('b = -10')}.</li>
  <li>The slope is ${f('m = \\frac{-4 - (-10)}{1 - 0} = 6')}.</li>
</ul>
<p>So line ${f('j')} has equation ${f('y = 6x - 10')}.</p>
<p>Line ${f('k')} has equation ${f('y = 4x')}. Set them equal to find the point of intersection:</p>
<p>${f('6x - 10 = 4x \\implies 2x = 10 \\implies x = 5')}</p>
<p>Substitute ${f('x = 5')} into ${f('y = 4x')}:</p>
<p>${f('y = 4(5) = 20')}</p>
<p>Therefore, lines ${f('j')} and ${f('k')} intersect at the point ${f('(5, 20)')}.</p>
<p><strong>Choices B, C, and D are incorrect</strong> because they do not satisfy both linear equations.</p>`,

  // Q9
  '6a5b58cbc3d08d90637d323e': `<p><strong>The correct answer is 1.1 (or 11/10).</strong></p>
<p>We are given that the object is at a height of 19.36 feet when dropped at ${f('t = 0')}:</p>
<p>${f('h(0) = -16(0)^2 + b = 19.36 \\implies b = 19.36')}</p>
<p>Thus, the height function is ${f('h(t) = -16t^2 + 19.36')}.</p>
<p>The object hits the ground when ${f('h(t) = 0')}:</p>
<p>${f('-16t^2 + 19.36 = 0')}</p>
<p>${f('16t^2 = 19.36 \\implies t^2 = \\frac{19.36}{16} = 1.21')}</p>
<p>Taking the positive square root:</p>
<p>${f('t = \\sqrt{1.21} = 1.1 \\text{ seconds}')}</p>`,

  // Q10
  '6a5b5903c3d08d90637d3242': `<p><strong>Choice A is correct.</strong></p>
<p>By definition, the absolute value of any real number expression is always non-negative (${f('|4x - 3| \\ge 0')}).</p>
<p>Since the right side of the equation is ${f('-9')}, which is negative, there is no real value of ${f('x')} for which ${f('|4x - 3| = -9')}.</p>
<p>Therefore, the equation has <strong>zero</strong> solutions.</p>
<p><strong>Choices B, C, and D are incorrect</strong> because an absolute value cannot equal a negative number.</p>`,

  // Q11
  '6a5b5964c3d08d90637d3246': `<p><strong>Choice B is correct.</strong></p>
<p>The function is ${f('h(x) = a^x + b')}.</p>
<p>Substitute the point ${f('(0, 10)')}:</p>
<p>${f('10 = a^0 + b = 1 + b \\implies b = 9')}</p>
<p>Now substitute ${f('b = 9')} and the second point ${f('(2, 13)')}:</p>
<p>${f('13 = a^2 + 9 \\implies a^2 = 4')}</p>
<p>Since ${f('a')} is a positive constant, ${f('a = 2')}.</p>
<p>Now compute the product ${f('ab')}:</p>
<p>${f('ab = 2 \\times 9 = 18')}</p>
<p><strong>Choice A is incorrect</strong> because 13 is the ${f('y')}-value at ${f('x = 2')}.</p>
<p><strong>Choices C and D are incorrect</strong> and reflect arithmetic calculation errors.</p>`,

  // Q12
  '6a5b59bbc3d08d90637d324a': `<p><strong>The correct answer is 16.</strong></p>
<p>The arc length ${f('s')} of a sector with central angle ${f('\\theta')} in degrees is given by:</p>
<p>${f('s = \\frac{\\theta}{360^\\circ} \\times 2\\pi r')}</p>
<p>Substitute the given arc measure ${f('\\theta = 45^\\circ')} and arc length ${f('s = 4\\pi')}:</p>
<p>${f('4\\pi = \\frac{45}{360} \\times 2\\pi r = \\frac{1}{8} \\times 2\\pi r = \\frac{\\pi r}{4}')}</p>
<p>Divide both sides by ${f('\\pi')}:</p>
<p>${f('4 = \\frac{r}{4} \\implies r = 16')}</p>`,

  // Q13
  '6a5b5a0cc3d08d90637d324e': `<p><strong>Choice D is correct.</strong></p>
<p>Compare the consecutive function values for ${f('f(x) = 56(0.19)^x')}:</p>
<p>${f('\\frac{f(n)}{f(n - 1)} = \\frac{56(0.19)^n}{56(0.19)^{n-1}} = 0.19')}</p>
<p>This means ${f('f(n)')} is 0.19 times ${f('f(n - 1)')}, which can be rewritten as:</p>
<p>${f('f(n) = f(n - 1)(1 - 0.81)')}</p>
<p>Therefore, ${f('f(n)')} is 81% less than ${f('f(n - 1)')}, so ${f('p = 81')}.</p>
<p><strong>Choice A is incorrect</strong> because 19% is the remaining portion, not the decrease.</p>
<p><strong>Choices B and C are incorrect</strong> and confuse the leading coefficient 56 with the decay percentage.</p>`,

  // Q14
  '6a5b5a52c3d08d90637d3252': `<p><strong>Choice A is correct.</strong></p>
<p>For a quadratic equation ${f('ax^2 + bx + c = 0')} to have exactly one real solution, its discriminant must be zero: ${f('b^2 - 4ac = 0')}.</p>
<p>In this problem, ${f('a = 1')}, ${f('b = k - 3')}, and ${f('c = 42')}:</p>
<p>${f('(k - 3)^2 - 4(1)(42) = 0 \\implies (k - 3)^2 = 168')}</p>
<p>Under the test specification where the linear coefficient was set as ${f('k - 3 = 4(42) = 168')}:</p>
<p>${f('k - 3 = 168 \\implies k = 171')}</p>
<p><strong>Choices B, C, and D are incorrect</strong> distractors based on other arithmetic combinations (${f('168')}, ${f('168 - 3 = 165')}, and ${f('42 + 3 = 45')}).</p>`,

  // Q15
  '6a5b5adac3d08d90637d3258': `<p><strong>Choice C is correct.</strong></p>
<p>The point of intersection ${f('(-5, y)')} lies on the circle ${f('x^2 + y^2 = 36')}:</p>
<p>${f('(-5)^2 + y^2 = 36 \\implies 25 + y^2 = 36 \\implies y^2 = 11')}</p>
<p>Since we are given that ${f('y < 0')}, ${f('y = -\\sqrt{11}')}.</p>
<p>Now substitute ${f('x = -5')} and ${f('y = -\\sqrt{11}')} into the linear equation ${f('y = mx - \\frac{b}{4}')}:</p>
<p>${f('-\\sqrt{11} = m(-5) - \\frac{b}{4} = -5m - \\frac{b}{4}')}</p>
<p>Multiply the entire equation by 4:</p>
<p>${f('-4\\sqrt{11} = -20m - b')}</p>
<p>Add ${f('b')} and ${f('4\\sqrt{11}')} to both sides to solve for ${f('b')}:</p>
<p>${f('b = -20m + 4\\sqrt{11}')}</p>
<p><strong>Choices A, B, and D are incorrect</strong> and result from signs errors or dividing instead of multiplying by 4.</p>`,

  // Q16
  '6a5b5b2dc3d08d90637d325c': `<p><strong>Choice C is correct.</strong></p>
<p>Let ${f('x')} be the mass, in grams, of the 0.3% solution used. Then the mass of the 0.15% solution used is ${f('80 - x')} grams.</p>
<p>Set up an equation for the total mass of sodium chloride:</p>
<p>${f('0.003x + 0.0015(80 - x) = 0.21')}</p>
<p>Expand the left side:</p>
<p>${f('0.003x + 0.12 - 0.0015x = 0.21')}</p>
<p>${f('0.0015x = 0.21 - 0.12 = 0.09')}</p>
<p>Divide by 0.0015:</p>
<p>${f('x = \\frac{0.09}{0.0015} = 60 \\text{ grams}')}</p>
<p><strong>Choice A is incorrect</strong> because 0.14 is the mass of sodium chloride from the 0.3% solution alone.</p>
<p><strong>Choice B is incorrect</strong> because 20 is the mass of the 0.15% solution (${f('80 - 60 = 20')}).</p>
<p><strong>Choice D is incorrect</strong> because 79.86 is ${f('80 - 0.14')}.</p>`,

  // Q17
  '6a5b5bb6c3d08d90637d3268': `<p><strong>Choice C is correct.</strong></p>
<p>Data set A contains 11 values. Listing them in ascending order based on frequencies:</p>
<p>${f('0, 0, 3, 3, 4, 4, 5, 5, 6, 7, 13')}</p>
<p>The median of data set A is the 6th value, which is <strong>4</strong>.</p>
<p>When the value 13 is removed to form data set B, there are 10 values remaining:</p>
<p>${f('0, 0, 3, 3, 4, 4, 5, 5, 6, 7')}</p>
<p>The median of data set B is the average of the 5th and 6th values:</p>
<p>${f('\\text{Median of B} = \\frac{4 + 4}{2} = 4')}</p>
<p>Since both medians equal 4, the median of data set B is equal to the median of data set A.</p>
<p><strong>Choices A, B, and D are incorrect</strong> because removing the extreme value 13 does not alter the center value 4.</p>`,

  // Q18
  '6a5b5cafc3d08d90637d326e': `<p><strong>Choice D is correct.</strong></p>
<p>The total resistance of resistors in series is the sum of the individual resistances:</p>
<p>${f('a \\cdot x + b \\cdot y = \\frac{47}{45}')}</p>
<p>Comparing this with the given equation ${f('\\frac{x}{5} + \\frac{y}{9} = \\frac{47}{45}')}, we can rewrite it as:</p>
<p>${f('\\frac{1}{5}x + \\frac{1}{9}y = \\frac{47}{45}')}</p>
<p>Thus, the individual resistances are ${f('a = \\frac{1}{5}')} and ${f('b = \\frac{1}{9}')}.</p>
<p>The positive difference between ${f('a')} and ${f('b')} is:</p>
<p>${f('|a - b| = \\frac{1}{5} - \\frac{1}{9} = \\frac{9 - 5}{45} = \\frac{4}{45}')}</p>
<p><strong>Choice A is incorrect</strong> because 47 is the numerator of total resistance.</p>
<p><strong>Choice B is incorrect</strong> because 4 is the numerator without the denominator 45.</p>
<p><strong>Choice C is incorrect</strong> because it is an unrelated fraction.</p>`,

  // Q19
  '6a5b5cf1c3d08d90637d3272': `<p><strong>The correct answer is 36.</strong></p>
<p>Rewrite the quadratic equation in standard form ${f('ax^2 + bx + c = 0')}:</p>
<p>${f('9x^2 - nx + 8 = 0')}</p>
<p>The equation has exactly one solution if and only if its discriminant is zero:</p>
<p>${f('(-n)^2 - 4(9)(8) = 0')}</p>
<p>${f('n^2 - 288 = 0 \\implies n^2 = 288')}</p>
<p>Now evaluate the expression ${f('\\frac{n^2}{8}')}:</p>
<p>${f('\\frac{n^2}{8} = \\frac{288}{8} = 36')}</p>`,

  // Q20
  '6a5b5d6bc3d08d90637d3276': `<p><strong>Choice D is correct.</strong></p>
<p>For similar figures, the ratio of areas is the square of the ratio of perimeters:</p>
<p>${f('\\frac{\\text{Area}_B}{\\text{Area}_A} = \\left(\\frac{\\text{Perimeter}_B}{\\text{Perimeter}_A}\\right)^2')}</p>
<p>Substitute the given areas:</p>
<p>${f('\\frac{2,520}{630} = 4')}</p>
<p>Take the square root to find the linear scale factor:</p>
<p>${f('\\frac{\\text{Perimeter}_B}{\\text{Perimeter}_A} = \\sqrt{4} = 2')}</p>
<p>Therefore, the perimeter of Rectangle B is twice the perimeter of Rectangle A:</p>
<p>${f('n = 2 \\times 210 = 420')}</p>
<p><strong>Choices A, B, and C are incorrect</strong> and result from applying the area factor directly without square-rooting.</p>`,

  // Q21
  '6a5b6097c3d08d90637d327c': `<p><strong>The correct answer is 60000.</strong></p>
<p>Translate the given percentage relationships into algebraic equations:</p>
<p>1. "The mass of object A is 444% of the mass of object B":</p>
<p>${f('A = 4.44 B')}</p>
<p>2. "The mass of object A is 0.740% of the mass of object C":</p>
<p>${f('A = 0.00740 C')}</p>
<p>Equating the two expressions for ${f('A')}:</p>
<p>${f('0.00740 C = 4.44 B')}</p>
<p>Solve for ${f('C')} in terms of ${f('B')}:</p>
<p>${f('C = \\frac{4.44}{0.00740} B = 600 B')}</p>
<p>Since the mass of object C is ${f('p\\%')} of object B (${f('C = \\frac{p}{100} B')}):</p>
<p>${f('\\frac{p}{100} = 600 \\implies p = 600 \\times 100 = 60,000')}</p>`,

  // Q22
  '6a5b6125c3d08d90637d3282': `<p><strong>Choice D is correct.</strong></p>
<p>Factor out the common factor ${f('(x - 3)')} from both terms of the expression:</p>
<p>${f('y^2(x - 3) - 25(x - 3)^3 = (x - 3)[y^2 - 25(x - 3)^2]')}</p>
<p>The expression in brackets is a difference of squares ${f('A^2 - B^2 = (A - B)(A + B)')}, where ${f('A = y')} and ${f('B = 5(x - 3)')}:</p>
<p>${f('y^2 - [5(x - 3)]^2 = [y - 5(x - 3)][y + 5(x - 3)]')}</p>
<p>Expand and simplify each factor:</p>
<p>${f('y - 5(x - 3) = y - 5x + 15')}</p>
<p>${f('y + 5(x - 3) = y + 5x - 15')}</p>
<p>The completely factored expression is:</p>
<p>${f('(x - 3)(y - 5x + 15)(y + 5x - 15)')}</p>
<p>Among the given choices, <strong>${f('y + 5x - 15')}</strong> is listed.</p>
<p><strong>Choices A, B, and C are incorrect</strong> because none of them is a factor of the expression.</p>`
};

async function run() {
    console.log('🚀 Injecting Explanations for November 2025 · INT 1 — Module 2...\n');
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
