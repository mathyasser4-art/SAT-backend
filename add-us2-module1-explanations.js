const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';

function updateQuestion(questionId, payload) {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify(payload);
        const req = https.request(`${API_BASE}/question/updateQuestion/${questionId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(data)
            }
        }, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(body));
                } catch (e) {
                    resolve({ raw: body });
                }
            });
        });
        req.on('error', reject);
        req.write(data);
        req.end();
    });
}

function math(tex) {
    return `<span class="ql-formula" data-value="${tex}"></span>`;
}

const explanationsM1 = {
    // Q1
    '6a54b6684d554e04aa1bfe3b':
        `<p><strong>Choice A is correct.</strong> Distribute the factor of ${math('18')} to each term inside the parentheses:</p>` +
        `<p>${math('18(x^2 - 8) = 18(x^2) - 18(8) = 18x^2 - 144')}</p>` +
        `<p><strong>Choice B is incorrect</strong> because it subtracts ${math('8')} from ${math('18')} (${math('18 - 8 = 10')} or ${math('18 + 8 = 26')}) rather than multiplying ${math('18 \\times 8')}.</p>` +
        `<p><strong>Choice C is incorrect</strong> because it fails to multiply the second term ${math('8')} by ${math('18')}.</p>` +
        `<p><strong>Choice D is incorrect</strong> because it adds ${math('18 + (-8) = 10')} instead of multiplying.</p>`,

    // Q2
    '6a54b9b94d554e04aa1bfe47':
        `<p><strong>Choice B is correct.</strong> A vertical translation downward by ${math('3')} units of the graph of ${math('y = f(x)')} corresponds to the transformation ${math('y = f(x) - 3')}. Applying this vertical shift to the exponential function ${math('f(x) = 5^x')} results in the equation ${math('y = 5^x - 3')}.</p>` +
        `<p><strong>Choice A is incorrect</strong> because it represents a vertical translation upward by ${math('3')} units.</p>` +
        `<p><strong>Choice C is incorrect</strong> because it represents a horizontal translation to the left by ${math('3')} units.</p>` +
        `<p><strong>Choice D is incorrect</strong> because it represents a horizontal translation to the right by ${math('3')} units.</p>`,

    // Q3
    '6a54ba384d554e04aa1bfe4d':
        `<p><strong>Choice A is correct.</strong> Notice the algebraic relationship between ${math('5x + 3')} and ${math('50x + 30')}. Factoring out ${math('10')} from ${math('50x + 30')} gives:</p>` +
        `<p>${math('50x + 30 = 10(5x + 3)')}</p>` +
        `<p>Since it is given that ${math('5x + 3 = 38')}, substitute ${math('38')} into the expression:</p>` +
        `<p>${math('10(38) = 380')}</p>` +
        `<p>Alternatively, solving ${math('5x + 3 = 38')} gives ${math('5x = 35')}, so ${math('x = 7')}. Evaluating ${math('50(7) + 30 = 350 + 30 = 380')}.</p>` +
        `<p><strong>Choices B, C, and D are incorrect</strong> and result from computational errors.</p>`,

    // Q4 (Essay)
    '6a54ba8d4d554e04aa1bfe53':
        `<p><strong>The correct answer is 25.</strong> The given equation for the perimeter of the rectangular garden is ${math('66 = 2x + 2y')}, where ${math('x')} is the length and ${math('y')} is the width in feet. Substitute the given width ${math('y = 8')} into the equation:</p>` +
        `<p>${math('66 = 2x + 2(8)')}</p>` +
        `<p>${math('66 = 2x + 16')}</p>` +
        `<p>Subtract ${math('16')} from both sides of the equation:</p>` +
        `<p>${math('50 = 2x')}</p>` +
        `<p>Divide both sides by ${math('2')}:</p>` +
        `<p>${math('x = 25')}</p>` +
        `<p>Therefore, the length of the garden is <strong>25</strong> feet.</p>`,

    // Q5
    '6a54bc9f4d554e04aa1bfe65':
        `<p><strong>Choice C is correct.</strong> Using the definition of the function ${math('f(x) = 6x - 3')}, evaluate ${math('f(a)')}:</p>` +
        `<p>${math('f(a) = 6a - 3')}</p>` +
        `<p>Substitute this expression into the given equation ${math('f(a) + 1 = 5a')}:</p>` +
        `<p>${math('(6a - 3) + 1 = 5a')}</p>` +
        `<p>${math('6a - 2 = 5a')}</p>` +
        `<p>Subtract ${math('5a')} from both sides:</p>` +
        `<p>${math('a - 2 = 0')}</p>` +
        `<p>${math('a = 2')}</p>` +
        `<p><strong>Choice A is incorrect</strong> because substituting ${math('a = -1')} gives ${math('f(-1) + 1 = 6(-1) - 3 + 1 = -8')}, which does not equal ${math('5(-1) = -5')}.</p>` +
        `<p><strong>Choice B is incorrect</strong> because substituting ${math('a = 1')} gives ${math('f(1) + 1 = 6(1) - 3 + 1 = 4')}, which does not equal ${math('5(1) = 5')}.</p>` +
        `<p><strong>Choice D is incorrect</strong> because substituting ${math('a = 3')} gives ${math('f(3) + 1 = 6(3) - 3 + 1 = 16')}, which does not equal ${math('5(3) = 15')}.</p>`,

    // Q6
    '6a54bd3e4d554e04aa1bfe6b':
        `<p><strong>Choice A is correct.</strong> The y-intercept of the graph of any function ${math('y = f(x)')} occurs at the point where ${math('x = 0')}. Evaluating ${math('f(0)')}:</p>` +
        `<p>${math('f(0) = 2(0) - \\frac{1}{8} = -\\frac{1}{8}')}</p>` +
        `<p>Therefore, the y-intercept is the coordinate point ${math('(0, -\\frac{1}{8})')}.</p>` +
        `<p><strong>Choice B is incorrect</strong> because ${math('-2')} is the negative of the slope, not the y-intercept.</p>` +
        `<p><strong>Choice C is incorrect</strong> because ${math('2')} is the slope of the line.</p>` +
        `<p><strong>Choice D is incorrect</strong> because ${math('8')} is the denominator of the constant term.</p>`,

    // Q7
    '6a54bf044d554e04aa1bfe71':
        `<p><strong>Choice A is correct.</strong> In statistical surveys, an estimate of a population proportion accompanied by a margin of error establishes a plausible interval of values for the true population proportion. Here, the estimate is ${math('27\\%')} with an associated margin of error of ${math('6\\%')}. The plausible interval is:</p>` +
        `<p>${math('27\\% - 6\\% = 21\\%')} to ${math('27\\% + 6\\% = 33\\%')}</p>` +
        `<p>Thus, plausible values for the percent of all adult residents of Madison who support the addition of a gas station are between ${math('21\\%')} and ${math('33\\%')}.</p>` +
        `<p><strong>Choice B is incorrect</strong> because values outside the confidence interval are considered less plausible, not more plausible.</p>` +
        `<p><strong>Choice C is incorrect</strong> because the margin of error defines a range of uncertainty, not a claim that the exact population parameter is precisely ${math('21\\%')}.</p>` +
        `<p><strong>Choice D is incorrect</strong> because values above ${math('33\\%')} lie outside the plausible range indicated by the survey data.</p>`,

    // Q8
    '6a54bfbc4d554e04aa1bfe77':
        `<p><strong>Choice B is correct.</strong> By the Alternate Interior Angles Converse Theorem (or Corresponding Angles Converse Theorem), if two lines cut by a transversal form congruent alternate interior angles, then the lines are parallel. In the given figure, angle ${math('w')} and angle ${math('y')} are alternate interior angles. If ${math('y = 118')}, then ${math('w = y = 118')}, which proves that lines ${math('r')} and ${math('s')} are parallel.</p>` +
        `<p><strong>Choice A is incorrect</strong> because angle ${math('x')} and angle ${math('w')} lie on the same intersection with line ${math('r')}, so the value of ${math('x')} provides no information about the relationship between line ${math('r')} and line ${math('s')}.</p>` +
        `<p><strong>Choices C and D are incorrect</strong> because knowing the sum of interior angles on different sides or supplementary relations without parallel alignment is insufficient to prove parallelism.</p>`,

    // Q9
    '6a54c0864d554e04aa1bfe7d':
        `<p><strong>Choice A is correct.</strong> First calculate the slope ${math('m')} of line ${math('q')} using the points ${math('(0, 20)')} and ${math('(1, 44)')}:</p>` +
        `<p>${math('m = \\frac{44 - 20}{1 - 0} = \\frac{24}{1} = 24')}</p>` +
        `<p>Since the line passes through ${math('(0, 20)')}, its y-intercept is ${math('20')}. In slope-intercept form, the equation of the line is:</p>` +
        `<p>${math('y = 24x + 20')}</p>` +
        `<p>Rearranging this equation into standard form by subtracting ${math('y')} from both sides yields:</p>` +
        `<p>${math('24x - y + 20 = 0')}</p>` +
        `<p><strong>Choices B, C, and D are incorrect</strong> because they have incorrect constant terms and do not pass through ${math('(0, 20)')} or ${math('(1, 44)')}.</p>`,

    // Q10 (Essay)
    '6a54c0cf4d554e04aa1bfe89':
        `<p><strong>The correct answer is 255.</strong> Let ${math('w')} represent the width of the rectangle in centimeters, and ${math('l')} represent the length in centimeters. It is given that the length is ${math('11')} centimeters more than ${math('8')} times the width:</p>` +
        `<p>${math('l = 8w + 11')}</p>` +
        `<p>The width of the rectangle is given as ${math('w = 5')} centimeters. Substituting this value gives:</p>` +
        `<p>${math('l = 8(5) + 11 = 40 + 11 = 51\\text{ cm}')}</p>` +
        `<p>The area of a rectangle is calculated as length multiplied by width:</p>` +
        `<p>${math('\\text{Area} = l \\times w = 51 \\times 5 = 255\\text{ cm}^2')}</p>` +
        `<p>Therefore, the area of the rectangle is <strong>255</strong> square centimeters.</p>`,

    // Q11
    '6a54c1904d554e04aa1bfe95':
        `<p><strong>Choice D is correct.</strong> Inspect the values of ${math('f(x)')} as ${math('x')} increases by ${math('1')} from ${math('1')} to ${math('4')}:</p>` +
        `<p>When ${math('x = 1')}, ${math('f(1) = 48')}; when ${math('x = 2')}, ${math('f(2) = 24')}; when ${math('x = 3')}, ${math('f(3) = 12')}; when ${math('x = 4')}, ${math('f(4) = 6')}.</p>` +
        `<p>Each successive output is obtained by multiplying the previous output by a constant factor of ${math('\\frac{1}{2}')}:</p>` +
        `<p>${math('\\frac{24}{48} = \\frac{12}{24} = \\frac{6}{12} = \\frac{1}{2}')}</p>` +
        `<p>A function that changes by a constant multiplicative ratio over equal intervals of ${math('x')} is an exponential function. Because the values of ${math('f(x)')} decrease as ${math('x')} increases, the function is a <strong>decreasing exponential</strong> function.</p>` +
        `<p><strong>Choices A and B are incorrect</strong> because the differences between consecutive outputs (${math('-24, -12, -6')}) are not constant, meaning the function is not linear.</p>` +
        `<p><strong>Choice C is incorrect</strong> because the values are decreasing, not increasing.</p>`,

    // Q12
    '6a54c2834d554e04aa1bfe9b':
        `<p><strong>Choice C is correct.</strong> The actual y-value is greater than the y-value predicted by the line of best fit for any data point that lies strictly <strong>above</strong> the line of best fit in the scatterplot. Examining the ${math('9')} plotted data points:</p>` +
        `<p>There are exactly ${math('5')} data points located strictly above the line of best fit, and ${math('4')} data points located strictly below the line of best fit.</p>` +
        `<p>Therefore, for ${math('5')} data points, the actual y-value is greater than the predicted y-value.</p>` +
        `<p><strong>Choices A, B, and D are incorrect</strong> due to miscounting the points relative to the line of best fit.</p>`,

    // Q13 (Essay)
    '6a54c3ce4d554e04aa1bfea7':
        `<p><strong>The correct answer is 28/3 (or 9.333).</strong> Find the slope ${math('m')} of the line using the points ${math('(0, 4)')} and ${math('(7, 1)')}:</p>` +
        `<p>${math('m = \\frac{1 - 4}{7 - 0} = -\\frac{3}{7}')}</p>` +
        `<p>Since the y-intercept is ${math('(0, 4)')}, the slope-intercept equation of the line is:</p>` +
        `<p>${math('y = -\\frac{3}{7}x + 4')}</p>` +
        `<p>Since the point ${math('(c, 0)')} lies on this line, substitute ${math('x = c')} and ${math('y = 0')}:</p>` +
        `<p>${math('0 = -\\frac{3}{7}c + 4')}</p>` +
        `<p>Subtract ${math('4')} from both sides:</p>` +
        `<p>${math('-4 = -\\frac{3}{7}c')}</p>` +
        `<p>Multiply both sides by ${math('-\\frac{7}{3}')}:</p>` +
        `<p>${math('c = (-4) \\times \\left(-\\frac{7}{3}\\right) = \\frac{28}{3}')}</p>` +
        `<p>Either <strong>28/3</strong> or its decimal equivalent <strong>9.333</strong> is correct.</p>`,

    // Q14
    '6a54c4cf4d554e04aa1bfead':
        `<p><strong>Choice C is correct.</strong> The solutions to the equation ${math('f(x) = 0')} correspond to the x-intercepts of the graph of ${math('y = f(x)')} (the points where the curve intersects the horizontal x-axis). Looking at the graph of this rational function, the curve intersects the x-axis at exactly <strong>one</strong> point. Therefore, there is exactly one value of ${math('x')} for which ${math('f(x) = 0')}.</p>` +
        `<p><strong>Choices A, B, and D are incorrect</strong> because the graph crosses the x-axis neither zero, two, nor three times.</p>`,

    // Q15
    '6a54c6bc4d554e04aa1bfeb3':
        `<p><strong>Choice C is correct.</strong> The area of a triangle is given by the formula:</p>` +
        `<p>${math('\\text{Area} = \\frac{1}{2} \\times \\text{base} \\times \\text{height}')}</p>` +
        `<p>From the figure, the base of triangle ABC is ${math('10')} centimeters, and the height is ${math('h')} centimeters. Substituting the given area of ${math('250')} square centimeters:</p>` +
        `<p>${math('250 = \\frac{1}{2} \\times 10 \\times h')}</p>` +
        `<p>${math('250 = 5h')}</p>` +
        `<p>Dividing both sides by ${math('5')} gives:</p>` +
        `<p>${math('h = 50\\text{ cm}')}</p>` +
        `<p><strong>Choice A is incorrect</strong> because ${math('10')} is the base length, not the height.</p>` +
        `<p><strong>Choice B is incorrect</strong> because a height of ${math('25')} gives an area of ${math('\\frac{1}{2} \\times 10 \\times 25 = 125')}.</p>` +
        `<p><strong>Choice D is incorrect</strong> because it omits the factor of ${math('\\frac{1}{2}')} in the triangle area formula.</p>`,

    // Q16 (Essay)
    '6a54c7354d554e04aa1bfeb9':
        `<p><strong>The correct answer is 27.</strong> Solve the given system of linear equations by substitution. The system is:</p>` +
        `<p>${math('y = 5x - 15')}</p>` +
        `<p>${math('4x + y = 48')}</p>` +
        `<p>Substitute the expression for ${math('y')} from the first equation into the second equation:</p>` +
        `<p>${math('4x + (5x - 15) = 48')}</p>` +
        `<p>${math('9x - 15 = 48')}</p>` +
        `<p>Add ${math('15')} to both sides:</p>` +
        `<p>${math('9x = 63')}</p>` +
        `<p>Divide by ${math('9')}:</p>` +
        `<p>${math('x = 7')}</p>` +
        `<p>Now substitute ${math('x = 7')} back into the first equation to find ${math('y')}:</p>` +
        `<p>${math('y = 5(7) - 15 = 35 - 15 = 20')}</p>` +
        `<p>The question asks for the value of ${math('x + y')}:</p>` +
        `<p>${math('x + y = 7 + 20 = 27')}</p>`,

    // Q17
    '6a54c79d4d554e04aa1bfec5':
        `<p><strong>Choice D is correct.</strong> The standard form equation of a circle in the xy-plane with center ${math('(h, k)')} and radius ${math('r')} is:</p>` +
        `<p>${math('(x - h)^2 + (y - k)^2 = r^2')}</p>` +
        `<p>Given the center ${math('(h, k) = (9, 6)')} and radius ${math('r = 4')}:</p>` +
        `<p>${math('(x - 9)^2 + (y - 6)^2 = 4^2 = 16')}</p>` +
        `<p><strong>Choices A and C are incorrect</strong> because they have center ${math('(-9, -6)')}.</p>` +
        `<p><strong>Choice B is incorrect</strong> because it has ${math('r = 4')} rather than ${math('r^2 = 16')} on the right-hand side.</p>`,

    // Q18
    '6a54c8574d554e04aa1bfed1':
        `<p><strong>Choice C is correct.</strong> In a proportional relationship between ${math('p')} and ${math('t')}, the ratio ${math('\\frac{p}{t}')} is constant:</p>` +
        `<p>${math('\\frac{p}{t} = k')}</p>` +
        `<p>Using the given values ${math('p = 5610')} when ${math('t = 7480')}:</p>` +
        `<p>${math('k = \\frac{5610}{7480} = \\frac{3}{4} = 0.75')}</p>` +
        `<p>To find ${math('t')} when ${math('p = 4488')}, set up the proportion:</p>` +
        `<p>${math('\\frac{4488}{t} = 0.75')}</p>` +
        `<p>${math('t = \\frac{4488}{0.75} = 5984')}</p>` +
        `<p><strong>Choices A, B, and D are incorrect</strong> computational errors.</p>`,

    // Q19
    '6a54c8d84d554e04aa1bfedd':
        `<p><strong>Choice C is correct.</strong> Multiply both sides of the equation by ${math('6')}:</p>` +
        `<p>${math('|4x - 48| + 4 = 48')}</p>` +
        `<p>Subtract ${math('4')} from both sides:</p>` +
        `<p>${math('|4x - 48| = 44')}</p>` +
        `<p>This absolute value equation produces two cases:</p>` +
        `<p><strong>Case 1:</strong> ${math('4x - 48 = 44 \\implies 4x = 92 \\implies x = 23')}</p>` +
        `<p><strong>Case 2:</strong> ${math('4x - 48 = -44 \\implies 4x = 4 \\implies x = 1')}</p>` +
        `<p>The sum of the solutions is:</p>` +
        `<p>${math('23 + 1 = 24')}</p>` +
        `<p><strong>Choices A, B, and D are incorrect</strong> and do not represent the sum of the solutions.</p>`,

    // Q20
    '6a54c9974d554e04aa1bfee3':
        `<p><strong>Choice C is correct.</strong> The data set contains ${math('7')} values in ascending order: ${math('a, 26, 28, b, 33, 49, c')}. The median of ${math('7')} ordered values is the 4th value, which is ${math('b')}. Since the median is given as ${math('28')}, we have ${math('b = 28')}.</p>` +
        `<p>The mean of the ${math('7')} values is ${math('35')}, so their sum is:</p>` +
        `<p>${math('\\text{Sum} = 7 \\times 35 = 245')}</p>` +
        `<p>Summing the known values: ${math('26 + 28 + 28 + 33 + 49 = 164')}. Thus:</p>` +
        `<p>${math('a + c + 164 = 245 \\implies a + c = 81')}</p>` +
        `<p>The range is the difference between the greatest and least values: ${math('c - a = 71')}.</p>` +
        `<p>We have a system of two linear equations:</p>` +
        `<p>${math('c + a = 81')}</p>` +
        `<p>${math('c - a = 71')}</p>` +
        `<p>Adding the two equations yields ${math('2c = 152')}, so ${math('c = 76')}.</p>` +
        `<p><strong>Choices A, B, and D are incorrect</strong> values.</p>`,

    // Q21
    '6a54ca654d554e04aa1bfeef':
        `<p><strong>Choice D is correct.</strong> For the function ${math('f(x) = 55(0.12)^x')}, compare ${math('f(n)')} to ${math('f(n - 1)')}:</p>` +
        `<p>${math('f(n) = 55(0.12)^n = 55(0.12)^{n-1} \\times 0.12 = f(n - 1) \\times 0.12')}</p>` +
        `<p>Since ${math('f(n)')} is equal to ${math('0.12')} (or ${math('12\\%')}) of ${math('f(n - 1)')}, the percent decrease is:</p>` +
        `<p>${math('(1 - 0.12) \\times 100\\% = 0.88 \\times 100\\% = 88\\%')}</p>` +
        `<p>Therefore, ${math('f(n)')} is ${math('88\\%')} less than ${math('f(n - 1)')}, so ${math('p = 88')}.</p>` +
        `<p><strong>Choice A is incorrect</strong> because ${math('12')} is the remaining percentage of the previous value, not the percentage decrease.</p>` +
        `<p><strong>Choices B and C are incorrect</strong> distractors.</p>`,

    // Q22 (Essay)
    '6a54cacf4d554e04aa1bfef5':
        `<p><strong>The correct answer is 0.</strong> For any real number ${math('u')}, the equation ${math('u^2 = a')} has:</p>` +
        `<p>• Exactly two real solutions if ${math('a > 0')} (${math('u = \\pm\\sqrt{a}')});</p>` +
        `<p>• Exactly one real solution if ${math('a = 0')} (${math('u = 0')});</p>` +
        `<p>• No real solutions if ${math('a < 0')} (since the square of any real number cannot be negative).</p>` +
        `<p>Here, ${math('u = 7x - 64')}. For the equation ${math('(7x - 64)^2 = a')} to have exactly one real solution, ${math('a')} must equal <strong>0</strong> (which gives the single solution ${math('7x - 64 = 0 \\implies x = \\frac{64}{7}')}).</p>`
};

async function run() {
    console.log('Uploading explanations for Dec 2025 US 2 Module 1...');
    for (const [id, exp] of Object.entries(explanationsM1)) {
        const res = await updateQuestion(id, { explanation: exp });
        console.log(`Updated M1 Q (${id}):`, res.message);
    }
    console.log('Done Module 1!');
}

run();
