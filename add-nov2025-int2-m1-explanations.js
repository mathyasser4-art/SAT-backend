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
  '6a5b61fcc3d08d90637d3291': `<p><strong>The correct answer is 19.</strong></p>
<p>A system of two linear equations in two variables has infinitely many solutions if and only if both equations represent the exact same line.</p>
<p>The first equation is given as:</p>
<p>${f('y = 9x + 19')}</p>
<p>For the second equation ${f('y = mx + b')} to have infinitely many solutions with the first, the slopes and ${f('y')}-intercepts must be identical:</p>
<p>${f('m = 9 \\quad \\text{and} \\quad b = 19')}</p>
<p>Thus, the value of constant ${f('b')} is <strong>19</strong>.</p>`,

  // Q2
  '6a5fad8ac3d08d90637d32da': `<p><strong>Choice D is correct.</strong></p>
<p>Notice that each term in the expression ${f('50x + 20')} is 10 times the corresponding term in the given equation ${f('5x + 2 = 32')}:</p>
<p>${f('50x + 20 = 10(5x + 2)')}</p>
<p>Substitute the value ${f('5x + 2 = 32')}:</p>
<p>${f('50x + 20 = 10(32) = 320')}</p>
<p>Alternatively, solving for ${f('x')}:</p>
<p>${f('5x = 30 \\implies x = 6')}</p>
<p>Then ${f('50(6) + 20 = 300 + 20 = 320')}.</p>
<p><strong>Choice A is incorrect</strong> because 6 is the value of ${f('x')}, not ${f('50x + 20')}.</p>
<p><strong>Choices B and C are incorrect</strong> and reflect arithmetic calculation errors.</p>`,

  // Q3
  '6a5fade2c3d08d90637d32e6': `<p><strong>Choice D is correct.</strong></p>
<p>Standard deviation measures how spread out the values in a data set are around their mean.</p>
<p>In each option, the mean of the 5 values is ${f('p')}. The data set with values furthest away from ${f('p')} has the largest standard deviation.</p>
<p>For the set ${f('\\{p - 5, p - 4, p, p + 4, p + 5\\}')}, the squared deviations from ${f('p')} are:</p>
<p>${f('(-5)^2 + (-4)^2 + 0^2 + 4^2 + 5^2 = 25 + 16 + 0 + 16 + 25 = 82')}</p>
<p>This sum of squared deviations is greater than any other option, so it has the largest standard deviation.</p>
<p><strong>Choice A is incorrect</strong> because its squared deviations sum to ${f('16 + 0 + 0 + 0 + 16 = 32')}.</p>
<p><strong>Choice B is incorrect</strong> because its squared deviations sum to ${f('1 + 1 + 0 + 1 + 1 = 4')}.</p>
<p><strong>Choice C is incorrect</strong> because all values are equal to ${f('p')}, giving a standard deviation of 0.</p>`,

  // Q4
  '6a5fae3fc3d08d90637d32ec': `<p><strong>Choice A is correct.</strong></p>
<p>To find the number of blue marbles, calculate 20% of 430:</p>
<p>${f('0.20 \\times 430 = \\frac{1}{5} \\times 430 = 86')}</p>
<p><strong>Choice B is incorrect</strong> because 172 is 40% of 430.</p>
<p><strong>Choice C is incorrect</strong> because 215 is 50% of 430.</p>
<p><strong>Choice D is incorrect</strong> because 410 is ${f('430 - 20')}.</p>`,

  // Q5
  '6a5fae8ac3d08d90637d32f2': `<p><strong>Choice A is correct.</strong></p>
<p>We need all pairs ${f('(r, g)')} in the table to satisfy the strict inequality ${f('r + g < 56')}:</p>
<ul>
  <li>For ${f('r = 0, g = 55')}: ${f('0 + 55 = 55 < 56')} (True)</li>
  <li>For ${f('r = 2, g = 53')}: ${f('2 + 53 = 55 < 56')} (True)</li>
  <li>For ${f('r = 4, g = 51')}: ${f('4 + 51 = 55 < 56')} (True)</li>
</ul>
<p>Since all pairs satisfy the inequality, this table is correct.</p>
<p><strong>Choices B, C, and D are incorrect</strong> because each contains pairs such as ${f('(2, 55)')} where ${f('2 + 55 = 57 \\not< 56')}, or ${f('(4, 55)')} where ${f('4 + 55 = 59 \\not< 56')}.</p>`,

  // Q6
  '6a5faed2c3d08d90637d32f6': `<p><strong>Choice C is correct.</strong></p>
<p>The horizontal axis represents the store square footage (in thousands of square feet), and the vertical axis represents annual sales (in millions of dollars).</p>
<p>Looking at the scatterplot, a store with 4 thousand square feet (${f('x = 4')}) lies halfway between the cluster of stores around 3 thousand sq ft (sales 4 to 7 million) and stores around 5 thousand sq ft (sales 8 to 11 million).</p>
<p>Following the linear upward trend of the data, the predicted annual sales at ${f('x = 4')} is approximately <strong>7.5</strong> million dollars.</p>
<p><strong>Choices A and B are incorrect</strong> because 4.1 and 5.4 lie well below the line of best fit for a 4,000 sq ft store.</p>
<p><strong>Choice D is incorrect</strong> because 10.2 corresponds to stores that are 5,000 sq ft or larger.</p>`,

  // Q7
  '6a5faf20c3d08d90637d3302': `<p><strong>The correct answer is 20.</strong></p>
<p>The given system of equations is:</p>
<p>${f('x + y = 165')}</p>
<p>${f('x + y + y = 185')}</p>
<p>Rewrite the second equation by grouping ${f('(x + y)')}:</p>
<p>${f('(x + y) + y = 185')}</p>
<p>Substitute ${f('x + y = 165')} from the first equation into this equation:</p>
<p>${f('165 + y = 185')}</p>
<p>Subtract 165 from both sides:</p>
<p>${f('y = 185 - 165 = 20')}</p>`,

  // Q8
  '6a5faf94c3d08d90637d3312': `<p><strong>Choice A is correct.</strong></p>
<p>The ${f('y')}-intercept of the graph of ${f('y = f(x)')} occurs where ${f('x = 0')}:</p>
<p>${f('f(0) = 6(0) - \\frac{1}{7} = -\\frac{1}{7}')}</p>
<p>Therefore, the coordinates of the ${f('y')}-intercept are ${f('\\left(0, -\\frac{1}{7}\\right)')}.</p>
<p><strong>Choice B is incorrect</strong> because ${f('-6')} is the negative of the slope.</p>
<p><strong>Choice C is incorrect</strong> because 6 is the slope, not the ${f('y')}-intercept.</p>
<p><strong>Choice D is incorrect</strong> because 7 is the reciprocal of ${f('\\frac{1}{7}')}.</p>`,

  // Q9
  '6a5fafe1c3d08d90637d3318': `<p><strong>The correct answer is 0.18 (or 9/50).</strong></p>
<p>From the table, the total number of people attending the conference is 50, and 9 of them chose a vegetarian entree.</p>
<p>The probability of randomly selecting a person who chose a vegetarian entree is:</p>
<p>${f('P = \\frac{9}{50} = 0.18')}</p>`,

  // Q10
  '6a5fb063c3d08d90637d331e': `<p><strong>Choice A is correct.</strong></p>
<p>In the figure, parallel lines ${f('l')} and ${f('k')} are intersected by transversal ${f('t')}.</p>
<p>Angle ${f('x^\\circ')} and angle ${f('y^\\circ')} are supplementary because the corresponding angle to ${f('y^\\circ')} on line ${f('l')} forms a straight line with ${f('x^\\circ')}:</p>
<p>${f('x + y = 180^\\circ \\implies y = 180 - x')}</p>
<p>We are given that ${f('x > 116')}. Subtracting ${f('x')} from 180 reverses the inequality:</p>
<p>${f('x > 116 \\implies -x < -116 \\implies 180 - x < 180 - 116 = 64')}</p>
<p>Since ${f('y = 180 - x')}, it must be true that ${f('y < 64')}.</p>
<p><strong>Choice B is incorrect</strong> because if ${f('x > 116')}, ${f('y')} must be less than 64, not greater.</p>
<p><strong>Choices C and D are incorrect</strong> because ${f('x + y = 180')} exactly.</p>`,

  // Q11
  '6a5fb0efc3d08d90637d332a': `<p><strong>Choice C is correct.</strong></p>
<p>To find the ${f('x')}-coordinates of the intersection points, set the two equations equal to each other:</p>
<p>${f('x^2 - 35 = 2x')}</p>
<p>Rearrange into standard quadratic form:</p>
<p>${f('x^2 - 2x - 35 = 0')}</p>
<p>By Vieta's formulas, the sum of the roots of a quadratic equation ${f('ax^2 + bx + c = 0')} is ${f('-\\frac{b}{a}')}:</p>
<p>${f('\\text{Sum} = -\\frac{-2}{1} = 2')}</p>
<p>Alternatively, factoring gives ${f('(x - 7)(x + 5) = 0')}, so the solutions are ${f('x = 7')} and ${f('x = -5')}. Their sum is ${f('7 + (-5) = 2')}.</p>
<p><strong>Choice A is incorrect</strong> because ${f('-35')} is the product of the solutions, not the sum.</p>
<p><strong>Choices B and D are incorrect</strong> because they are individual solutions (${f('-5')} and ${f('7')}), not their sum.</p>`,

  // Q12
  '6a5fb130c3d08d90637d332e': `<p><strong>The correct answer is 13/4 (or 3.25).</strong></p>
<p>Substitute ${f('x = \\frac{1}{4}')} into the definition of the function:</p>
<p>${f('f\\left(\\frac{1}{4}\\right) = 3 \\left(\\frac{1}{4} - \\frac{1}{4}\\right)^2 + \\frac{13}{4}')}</p>
<p>${f('f\\left(\\frac{1}{4}\\right) = 3(0)^2 + \\frac{13}{4} = 0 + \\frac{13}{4} = \\frac{13}{4} = 3.25')}</p>`,

  // Q13
  '6a5fb1b3c3d08d90637d3340': `<p><strong>Choice B is correct.</strong></p>
<p>The range of a data set shown in a box plot is the difference between the maximum value and the minimum value:</p>
<p>${f('\\text{Range} = \\text{Maximum} - \\text{Minimum}')}</p>
<p>From the given box plot:</p>
<ul>
  <li>The minimum value (left whisker end) is at 34 cm.</li>
  <li>The maximum value (right whisker end) is at 49 cm.</li>
</ul>
<p>Calculating the range:</p>
<p>${f('\\text{Range} = 49 - 34 = 15 \\text{ cm}')}</p>
<p><strong>Choice A is incorrect</strong> because 10 is the interquartile range (${f('Q_3 - Q_1 = 46 - 36 = 10')}).</p>
<p><strong>Choices C and D are incorrect</strong> and result from misreading the scale ticks.</p>`,

  // Q14
  '6a5fb24dc3d08d90637d335a': `<p><strong>Choice C is correct.</strong></p>
<p>The area of a triangle is given by the formula:</p>
<p>${f('\\text{Area} = \\frac{1}{2} b h')}</p>
<p>From the figure, the base ${f('b = 10')} cm and the area is given as 150 square centimeters:</p>
<p>${f('150 = \\frac{1}{2}(10)h')}</p>
<p>${f('150 = 5h \\implies h = \\frac{150}{5} = 30')}</p>
<p>Thus, the height ${f('h')} is 30 centimeters.</p>
<p><strong>Choice A is incorrect</strong> because 10 is the base length.</p>
<p><strong>Choice B is incorrect</strong> because 15 results from forgetting to multiply by 2 (calculating ${f('\\frac{150}{10}')}).</p>
<p><strong>Choice D is incorrect</strong> because 60 results from multiplying by 2 twice.</p>`,

  // Q15
  '6a5fb34bc3d08d90637d3360': `<p><strong>Choice B is correct.</strong></p>
<p>Solve the quadratic equation by completing the square:</p>
<p>${f('x^2 - 2x = 29')}</p>
<p>Add 1 to both sides:</p>
<p>${f('x^2 - 2x + 1 = 29 + 1')}</p>
<p>${f('(x - 1)^2 = 30')}</p>
<p>Take the square root of both sides:</p>
<p>${f('x - 1 = \\pm \\sqrt{30} \\implies x = 1 \\pm \\sqrt{30}')}</p>
<p>The positive solution is ${f('1 + \\sqrt{30}')}.</p>
<p><strong>Choice A is incorrect</strong> because ${f('\\sqrt{29}')} ignores the ${f('-2x')} linear term.</p>
<p><strong>Choices C and D are incorrect</strong> and reflect algebraic manipulation errors.</p>`,

  // Q16
  '6a5fb403c3d08d90637d3366': `<p><strong>The correct answer is 100.</strong></p>
<p>The standard equation of a circle is ${f('(x - h)^2 + (y - k)^2 = r^2')}.</p>
<p>For circle A, ${f('(x + 8)^2 + (y - 8)^2 = 25')}, the radius is:</p>
<p>${f('r_A = \\sqrt{25} = 5')}</p>
<p>The radius of circle B is twice the radius of circle A:</p>
<p>${f('r_B = 2 \\times r_A = 2 \\times 5 = 10')}</p>
<p>The equation for circle B has constant ${f('k = r_B^2')}:</p>
<p>${f('k = 10^2 = 100')}</p>`,

  // Q17
  '6a5fb462c3d08d90637d336a': `<p><strong>Choice D is correct.</strong></p>
<p>The value of ${f('x')} for which ${f('f(x) = 0')} is the ${f('x')}-intercept of the graph of ${f('y = f(x)')}.</p>
<p>Looking at the coordinate plane, the curve crosses the horizontal ${f('x')}-axis at the point ${f('(4, 0)')}.</p>
<p>Therefore, ${f('f(4) = 0')}, so ${f('x = 4')}.</p>
<p><strong>Choice A is incorrect</strong> because at ${f('x = -4')}, the function has a vertical asymptote and is undefined.</p>
<p><strong>Choice B is incorrect</strong> because at ${f('x = 0')}, ${f('f(0) = -1')} (the ${f('y')}-intercept).</p>
<p><strong>Choice C is incorrect</strong> because 1 is the horizontal asymptote as ${f('x \\to \\infty')}.</p>`,

  // Q18
  '6a5fb498c3d08d90637d336e': `<p><strong>Choice C is correct.</strong></p>
<p>Multiply both sides of the equation by 6:</p>
<p>${f('|3x - 30| + 3 = 30')}</p>
<p>Subtract 3 from both sides:</p>
<p>${f('|3x - 30| = 27')}</p>
<p>Factor out 3 from the absolute value:</p>
<p>${f('3|x - 10| = 27 \\implies |x - 10| = 9')}</p>
<p>This splits into two linear cases:</p>
<p>${f('x - 10 = 9 \\implies x = 19')}</p>
<p>${f('x - 10 = -9 \\implies x = 1')}</p>
<p>The sum of the solutions is:</p>
<p>${f('19 + 1 = 20')}</p>
<p><strong>Choice A is incorrect</strong> because 1 is only one of the two solutions.</p>
<p><strong>Choice B is incorrect</strong> because 19 is only one of the two solutions.</p>
<p><strong>Choice D is incorrect</strong> because 30 is the RHS after multiplying by 6.</p>`,

  // Q19
  '6a5fb4ddc3d08d90637d3372': `<p><strong>Choice D is correct.</strong></p>
<p>First, find the slope of line ${f('h')} by converting its equation to slope-intercept form ${f('y = mx + b')}:</p>
<p>${f('\\frac{1}{2}x + \\frac{1}{5}y - 40 = 0')}</p>
<p>${f('\\frac{1}{5}y = -\\frac{1}{2}x + 40')}</p>
<p>Multiply the entire equation by 5:</p>
<p>${f('y = -\\frac{5}{2}x + 200')}</p>
<p>The slope of line ${f('h')} is ${f('m_h = -\\frac{5}{2}')}.</p>
<p>Since line ${f('j')} is perpendicular to line ${f('h')}, its slope is the negative reciprocal of ${f('m_h')}:</p>
<p>${f('m_j = -\\frac{1}{m_h} = -\\frac{1}{-\\frac{5}{2}} = \\frac{2}{5}')}</p>
<p><strong>Choice A is incorrect</strong> because ${f('-\\frac{5}{2}')} is the slope of line ${f('h')}.</p>
<p><strong>Choice B is incorrect</strong> because it has the incorrect sign.</p>
<p><strong>Choice C is incorrect</strong> because ${f('\\frac{5}{2}')} is the negative of the slope without taking the reciprocal.</p>`,

  // Q20
  '6a5fb4ffc3d08d90637d337e': `<p><strong>Choice B is correct.</strong></p>
<p>Let ${f('l')} be the length and ${f('w')} be the width of the rectangle. The problem states that the width is 16 inches less than 2 times the length:</p>
<p>${f('w = 2l - 16')}</p>
<p>The area of the rectangle is 130 square inches:</p>
<p>${f('l \\times w = 130 \\implies l(2l - 16) = 130')}</p>
<p>${f('2l^2 - 16l - 130 = 0')}</p>
<p>Divide the entire equation by 2:</p>
<p>${f('l^2 - 8l - 65 = 0')}</p>
<p>Factor the quadratic equation:</p>
<p>${f('(l - 13)(l + 5) = 0')}</p>
<p>Since side lengths must be positive, ${f('l = 13')}. Now calculate the width ${f('w')}:</p>
<p>${f('w = 2(13) - 16 = 26 - 16 = 10')}</p>
<p><strong>Choice A is incorrect</strong> because 5 is the absolute value of the negative algebraic root.</p>
<p><strong>Choice C is incorrect</strong> because 13 is the length of the rectangle, not the width.</p>
<p><strong>Choice D is incorrect</strong> and reflects an arithmetic error.</p>`,

  // Q21
  '6a5fb5c4c3d08d90637d3382': `<p><strong>Choice D is correct.</strong></p>
<p>Define the number of each type of part made:</p>
<ul>
  <li>Number of 9-inch parts: ${f('n')}</li>
  <li>Number of 8-inch parts: 5 times the number of 9-inch parts, which is ${f('5n')}</li>
  <li>Number of 3-inch parts: 4</li>
</ul>
<p>The total number of parts made is the sum of the parts:</p>
<p>${f('\\text{Total parts} = 5n + n + 4 = 6n + 4')}</p>
<p>Since the machine makes 100 parts total:</p>
<p>${f('6n + 4 = 100')}</p>
<p><strong>Choice A is incorrect</strong> because it multiplies part lengths by their counts, calculating total length rather than the number of parts.</p>
<p><strong>Choice B is incorrect</strong> because it incorrectly uses ${f('n')} for all part counts.</p>
<p><strong>Choice C is incorrect</strong> because it omits the ${f('n')} 9-inch parts (${f('5n + 4')} instead of ${f('6n + 4')}).</p>`,

  // Q22
  '6a5fb60bc3d08d90637d3386': `<p><strong>Choice D is correct.</strong></p>
<p>The initial population in the base year 2003 (${f('t = 0')}) is 200 squirrels.</p>
<p>A quantity that is 120% more than the previous quantity increases by a factor of:</p>
<p>${f('1 + 1.20 = 2.20')}</p>
<p>Since this growth occurs once every 4 years, the number of 4-year periods elapsed after ${f('t')} years is ${f('\\frac{t}{4}')}.</p>
<p>Therefore, the exponential model is:</p>
<p>${f('N = 200(2.20)^{\\frac{t}{4}}')}</p>
<p><strong>Choice A is incorrect</strong> because using exponent ${f('4t')} would model growth happening 4 times per year.</p>
<p><strong>Choices B and C are incorrect</strong> because using base 1.20 represents a 20% increase rather than 120% more (which is a 220% total multiplier).</p>`
};

async function run() {
    console.log('🚀 Injecting Explanations for November 2025 · INT 2 — Module 1...\n');
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
