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
    // Q1 (Essay)
    '6a5b22c6c3d08d90637d2f91':
        `<p><strong>The correct answer is 44.</strong> To find the value of ${math('f(10)')}, substitute ${math('x = 10')} into the given function equation ${math('f(x) = 5x - 6')}:</p>` +
        `<p>${math('f(10) = 5(10) - 6')}</p>` +
        `<p>${math('f(10) = 50 - 6 = 44')}</p>`,

    // Q2
    '6a5b2672c3d08d90637d2fa2':
        `<p><strong>Choice D is correct.</strong> The lowest recorded wind speed in the town was ${math('5\\text{ mph}')}, meaning any recorded wind speed ${math('w')} is greater than or equal to ${math('5\\text{ mph}')} (${math('w \\ge 5')}). The highest recorded wind speed was ${math('14\\text{ mph}')}, meaning any recorded wind speed ${math('w')} is less than or equal to ${math('14\\text{ mph}')} (${math('w \\le 14')}). Combining these two conditions into a compound inequality gives:</p>` +
        `<p>${math('5 \\le w \\le 14')}</p>` +
        `<p><strong>Choice A is incorrect</strong> because it only accounts for speeds at or below ${math('5\\text{ mph}')}.</p>` +
        `<p><strong>Choice B is incorrect</strong> because ${math('9')} is the range (${math('14 - 5')}), not the upper bound.</p>` +
        `<p><strong>Choice C is incorrect</strong> because it only accounts for speeds at or above ${math('14\\text{ mph}')}.</p>`,

    // Q3
    '6a5b26c2c3d08d90637d2fa6':
        `<p><strong>Choice A is correct.</strong> Combine like terms on the left side of the equation:</p>` +
        `<p>${math('4p - 5p = 14')}</p>` +
        `<p>${math('-p = 14')}</p>` +
        `<p>Multiply or divide both sides by ${math('-1')}:</p>` +
        `<p>${math('p = -14')}</p>` +
        `<p><strong>Choices B, C, and D are incorrect</strong> computational errors.</p>`,

    // Q4 (Essay)
    '6a5b26ebc3d08d90637d2fb0':
        `<p><strong>The correct answer is 6.</strong> The perimeter of a polygon is the sum of the lengths of all its sides. The polygon has ${math('22')} sides, one of which has length ${math('5')} inches, and the other ${math('21')} sides each have equal length ${math('s')} inches. The total perimeter is ${math('131')} inches:</p>` +
        `<p>${math('5 + 21s = 131')}</p>` +
        `<p>Subtract ${math('5')} from both sides:</p>` +
        `<p>${math('21s = 126')}</p>` +
        `<p>Divide both sides by ${math('21')}:</p>` +
        `<p>${math('s = \\frac{126}{21} = 6\\text{ inches}')}</p>`,

    // Q5
    '6a5b2757c3d08d90637d2fb4':
        `<p><strong>Choice B is correct.</strong> In the linear equation ${math('13,000 = 2,600 + 260t')}, ${math('13,000')} dollars represents the total cost of the car, ${math('2,600')} dollars represents the one-time initial down payment, and ${math('t')} represents the number of fixed monthly payments. The term ${math('260t')} represents the total amount paid across ${math('t')} months. Therefore, the coefficient ${math('260')} represents the amount, in dollars, of each fixed monthly payment.</p>` +
        `<p><strong>Choice A is incorrect</strong> because ${math('2,600')} is the down payment.</p>` +
        `<p><strong>Choice C is incorrect</strong> because ${math('2,600 + 260t')} is the total amount paid after ${math('t')} payments.</p>` +
        `<p><strong>Choice D is incorrect</strong> because ${math('t')} is the number of fixed monthly payments.</p>`,

    // Q6
    '6a5b278ac3d08d90637d2fb8':
        `<p><strong>Choice B is correct.</strong> Notice that the expression to evaluate is ${math('\\frac{1}{6}(3 - 2x)')}. Since it is given that ${math('3 - 2x = 42')}, substitute ${math('42')} directly into the expression:</p>` +
        `<p>${math('\\frac{1}{6}(42) = 7')}</p>` +
        `<p>Alternatively, solving ${math('3 - 2x = 42')} gives ${math('-2x = 39 \\implies x = -\\frac{39}{2}')}. Then ${math('\\frac{1}{6}\\left(3 - 2\\left(-\\frac{39}{2}\\right)\\right) = \\frac{1}{6}(3 + 39) = \\frac{1}{6}(42) = 7')}.</p>` +
        `<p><strong>Choices A, C, and D are incorrect</strong> computational errors.</p>`,

    // Q7
    '6a5b27e8c3d08d90637d2fc9':
        `<p><strong>Choice D is correct.</strong> Set up a proportion stating that the ratio of ${math('72')} to ${math('m')} is equivalent to the ratio of ${math('4')} to ${math('24')}:</p>` +
        `<p>${math('\\frac{72}{m} = \\frac{4}{24}')}</p>` +
        `<p>Simplify the fraction on the right-hand side:</p>` +
        `<p>${math('\\frac{72}{m} = \\frac{1}{6}')}</p>` +
        `<p>Cross-multiply to solve for ${math('m')}:</p>` +
        `<p>${math('m = 72 \\times 6 = 432')}</p>` +
        `<p><strong>Choices A, B, and C are incorrect</strong> computational errors.</p>`,

    // Q8
    '6a5b2865c3d08d90637d2fcf':
        `<p><strong>Choice B is correct.</strong> By the Zero Product Property, if the product of two factors is zero, at least one of the factors must equal zero:</p>` +
        `<p>${math('(x + 4)(x - 6) = 0')}</p>` +
        `<p>Set each factor equal to zero:</p>` +
        `<p><strong>Case 1:</strong> ${math('x + 4 = 0 \\implies x = -4')}</p>` +
        `<p><strong>Case 2:</strong> ${math('x - 6 = 0 \\implies x = 6')}</p>` +
        `<p>Therefore, the possible solutions to the equation are <strong>-4 and 6</strong>.</p>` +
        `<p><strong>Choices A, C, and D are incorrect</strong> because they reverse the signs of one or both solutions.</p>`,

    // Q9 (Essay)
    '6a5b28b8c3d08d90637d2fd3':
        `<p><strong>The correct answer is 6.</strong> Notice that the left side of both equations is identical (${math('7x - 8y')}):</p>` +
        `<p>${math('7x - 8y = x^2')}</p>` +
        `<p>${math('7x - 8y = 36')}</p>` +
        `<p>Setting the right-hand sides equal to each other gives:</p>` +
        `<p>${math('x^2 = 36')}</p>` +
        `<p>Take the square root of both sides:</p>` +
        `<p>${math('x = 6')} or ${math('x = -6')}</p>` +
        `<p>Since the problem specifies that ${math('x')} is positive, the value of ${math('x')} is <strong>6</strong>.</p>`,

    // Q10
    '6a5b291bc3d08d90637d2fd7':
        `<p><strong>Choice A is correct.</strong> Find the slope ${math('m')} of the linear relationship using the points ${math('(-6, 48)')} and ${math('(-3, 39)')}:</p>` +
        `<p>${math('m = \\frac{39 - 48}{-3 - (-6)} = \\frac{-9}{3} = -3')}</p>` +
        `<p>Find the y-intercept ${math('b')} using the point ${math('(3, 21)')}:</p>` +
        `<p>${math('21 = -3(3) + b \\implies 21 = -9 + b \\implies b = 30')}</p>` +
        `<p>Thus, the slope-intercept equation is ${math('y = -3x + 30')}. Rearranging into standard form gives:</p>` +
        `<p>${math('3x + y = 30')}</p>` +
        `<p>Multiplying the entire equation by ${math('3')} yields:</p>` +
        `<p>${math('9x + 3y = 90')}</p>` +
        `<p><strong>Choices B, C, and D are incorrect</strong> because their coefficients or constants do not satisfy the points in the table.</p>`,

    // Q11
    '6a5b29edc3d08d90637d2fdd':
        `<p><strong>Choice C is correct.</strong> Standard deviation is a measure of the spread or dispersion of data values around the mean. The table shows that Group A and Group B have the exact same mean (${math('186\\text{ cm}')}) and the same sample size (${math('2,500')}), but Group B has a standard deviation of ${math('19.1\\text{ cm}')}, which is greater than Group A\'s standard deviation of ${math('12.5\\text{ cm}')}. A larger standard deviation indicates greater variability and a wider spread of values. Therefore, the heights of the men in Group B had a larger spread than the heights of the men in Group A.</p>` +
        `<p><strong>Choice A is incorrect</strong> because differing standard deviations prove the data sets are not identical.</p>` +
        `<p><strong>Choice B is incorrect</strong> because standard deviation does not indicate the single maximum value in a distribution.</p>` +
        `<p><strong>Choice D is incorrect</strong> because standard deviation does not provide information about the medians.</p>`,

    // Q12 (Essay)
    '6a5b2a43c3d08d90637d2fe9':
        `<p><strong>The correct answer is 455.</strong> Calculate the number of attendees step-by-step:</p>` +
        `<p>1. The number of people who attended the first webinar is ${math('3,125')}.</p>` +
        `<p>2. ${math('56\\%')} of those people attended the second webinar:</p>` +
        `<p>${math('0.56 \\times 3,125 = 1,750\\text{ people}')}</p>` +
        `<p>3. ${math('26\\%')} of the people who attended both the first and second webinars attended the third webinar:</p>` +
        `<p>${math('0.26 \\times 1,750 = 455\\text{ people}')}</p>` +
        `<p>Therefore, <strong>455</strong> people attended all three webinars.</p>`,

    // Q13
    '6a5b2ab6c3d08d90637d2ff5':
        `<p><strong>Choice A is correct.</strong> Locate ${math('x = 1')} on the horizontal axis of the scatterplot:</p>` +
        `<p>• The actual data point at ${math('x = 1')} has a y-coordinate of ${math('12')}.</p>` +
        `<p>• The line of best fit passes through approximately ${math('y = 11')} at ${math('x = 1')}.</p>` +
        `<p>The difference between the actual y-coordinate and the predicted y-value is:</p>` +
        `<p>${math('|12 - 11| = 1')}</p>` +
        `<p>Therefore, the difference is closest to <strong>1</strong>.</p>` +
        `<p><strong>Choices B, C, and D are incorrect</strong> estimates.</p>`,

    // Q14 (Essay)
    '6a5b2b11c3d08d90637d2ffb':
        `<p><strong>The correct answer is 97.</strong> In the triangle formed by the intersections of lines ${math('r')}, ${math('s')}, and ${math('t')}:</p>` +
        `<p>1. The interior angle adjacent to the ${math('106^\\circ')} angle is supplementary to it:</p>` +
        `<p>${math('180^\\circ - 106^\\circ = 74^\\circ')}</p>` +
        `<p>2. The interior angle at the far right intersection of lines ${math('r')} and ${math('t')} is given as ${math('23^\\circ')}.</p>` +
        `<p>3. By the Exterior Angle Theorem, an exterior angle of a triangle equals the sum of the two remote interior angles. Here, angle ${math('x^\\circ')} is an exterior angle to the triangle at the bottom-left intersection of lines ${math('r')} and ${math('s')}:</p>` +
        `<p>${math('x = 74 + 23 = 97')}</p>` +
        `<p>(Alternatively, the third interior angle is ${math('180^\\circ - (74^\\circ + 23^\\circ) = 83^\\circ')}, and since ${math('x^\\circ')} and ${math('83^\\circ')} are supplementary on line ${math('s')}, ${math('x = 180 - 83 = 97')}).</p>`,

    // Q15 (Essay)
    '6a5b2b6ec3d08d90637d2fff':
        `<p><strong>The correct answer is 6075.</strong> Expand the given expression by distributing ${math('15x')}:</p>` +
        `<p>${math('15x(x^2 + 9) = 15x(x^2) + 15x(9) = 15x^3 + 135x')}</p>` +
        `<p>Compare this to the given expression ${math('ax^b + cx')}:</p>` +
        `<p>${math('a = 15')}, ${math('b = 3')}, and ${math('c = 135')}.</p>` +
        `<p>Calculate the product ${math('abc')}:</p>` +
        `<p>${math('abc = 15 \\times 3 \\times 135 = 45 \\times 135 = 6,075')}</p>`,

    // Q16 (Essay)
    '6a5b2c05c3d08d90637d3003':
        `<p><strong>The correct answer is 5.</strong> The equation of Circle R is ${math('(x + 8)^2 + (y + 19)^2 = 100')}, which has its center at ${math('(-8, -19)')}.</p>` +
        `<p>Shifting the circle to the right by ${math('3')} units increases the x-coordinate of the center by ${math('3')}:</p>` +
        `<p>${math('-8 + 3 = -5')}</p>` +
        `<p>The new center of Circle S is at ${math('(-5, -19)')}. The equation defining Circle S is:</p>` +
        `<p>${math('(x - (-5))^2 + (y - (-19))^2 = 100 \\implies (x + 5)^2 + (y + 19)^2 = 100')}</p>` +
        `<p>Comparing this to ${math('(x + h)^2 + (y + k)^2 = 100')}, we find that ${math('h = 5')}.</p>`,

    // Q17
    '6a5b2ca8c3d08d90637d3009':
        `<p><strong>Choice D is correct.</strong> On January 1, the initial number of views is ${math('237')}. An increase of ${math('70\\%')} every 2 days corresponds to multiplying by a growth factor of ${math('1 + 0.70 = 1.70')} every 2 days. In ${math('x')} days, the number of 2-day cycles that have elapsed is ${math('\\frac{x}{2}')}. Therefore, the function modeling the number of views is:</p>` +
        `<p>${math('f(x) = 237(1.70)^{\\frac{x}{2}}')}</p>` +
        `<p><strong>Choices A and B are incorrect</strong> because ${math('0.70')} corresponds to a 30% decrease, not a 70% increase.</p>` +
        `<p><strong>Choice C is incorrect</strong> because it assumes the 70% increase happens daily rather than every 2 days.</p>`,

    // Q18
    '6a5b30eac3d08d90637d3015':
        `<p><strong>Choice D is correct.</strong> When two polygons are similar, their corresponding sides are proportional and their corresponding angles are congruent (equal in measure). In similar quadrilaterals ${math('PQRS')} and ${math('WXYZ')}, vertex ${math('S')} corresponds to vertex ${math('Z')}. Since the measure of angle ${math('S')} is ${math('135^\\circ')}, the measure of angle ${math('Z')} must also be <strong>135°</strong>.</p>` +
        `<p><strong>Choices A, B, and C are incorrect</strong> because corresponding angles of similar figures are always equal, not scaled by the side ratio.</p>`,

    // Q19
    '6a5b3139c3d08d90637d3019':
        `<p><strong>Choice B is correct.</strong> The function ${math('h(x)')} is defined as ${math('h(x) = f(x) + 9')}:</p>` +
        `<p>${math('h(x) = (4x^2 + 16x + 22) + 9 = 4x^2 + 16x + 31')}</p>` +
        `<p>Since the parabola opens upward (${math('a = 4 > 0')}), its minimum value occurs at its vertex. The x-coordinate of the vertex is:</p>` +
        `<p>${math('x = -\\frac{b}{2a} = -\\frac{16}{2(4)} = -\\frac{16}{8} = -2')}</p>` +
        `<p>Evaluate ${math('h(-2)')}:</p>` +
        `<p>${math('h(-2) = 4(-2)^2 + 16(-2) + 31 = 4(4) - 32 + 31 = 16 - 32 + 31 = 15')}</p>` +
        `<p>Therefore, the minimum value of ${math('h(x)')} is <strong>15</strong>.</p>` +
        `<p><strong>Choices A, C, and D are incorrect</strong> calculation errors.</p>`,

    // Q20
    '6a5b31b4c3d08d90637d3026':
        `<p><strong>Choice C is correct.</strong> Notice the repeated composite terms ${math('5x')} and ${math('8y')}. Let ${math('u = 5x')} and ${math('v = 8y')}. The system becomes:</p>` +
        `<p>${math('7u + 9v = 189')}</p>` +
        `<p>${math('7u - 9v = -819')}</p>` +
        `<p>Add the two equations to eliminate ${math('v')}:</p>` +
        `<p>${math('14u = -630 \\implies u = -45 \\implies 5x = -45')}</p>` +
        `<p>Subtract the second equation from the first to eliminate ${math('u')}:</p>` +
        `<p>${math('18v = 1008 \\implies v = 56 \\implies 8y = 56')}</p>` +
        `<p>The question asks for the value of ${math('5x + 8y')}, which is ${math('u + v')}:</p>` +
        `<p>${math('5x + 8y = -45 + 56 = 11')}</p>` +
        `<p><strong>Choices A, B, and D are incorrect</strong> results.</p>`,

    // Q21
    '6a5b3225c3d08d90637d302a':
        `<p><strong>Choice D is correct.</strong> According to the Polynomial Remainder Theorem, when a polynomial ${math('f(x)')} is divided by a linear binomial ${math('x - c')}, the remainder is equal to ${math('f(c)')}. Here, when ${math('f(x)')} is divided by ${math('x - 8')}, the remainder is ${math('9')}, which means that:</p>` +
        `<p>${math('f(8) = 9')}</p>` +
        `<p>On the graph of ${math('y = f(x)')}, an input of ${math('x = 8')} yields an output of ${math('y = 9')}. Therefore, the graph must pass through the point <strong>(8, 9)</strong>.</p>` +
        `<p><strong>Choices A, B, and C are incorrect</strong> because they confuse the x and y coordinates or their signs.</p>`,

    // Q22
    '6a5b3275c3d08d90637d302e':
        `<p><strong>Choice D is correct.</strong> Simplify the left side of the equation:</p>` +
        `<p>${math('\\frac{-22x - 29 + m}{2} = -11x + \\frac{m - 29}{2}')}</p>` +
        `<p>Expand the right side of the equation:</p>` +
        `<p>${math('k(x + 5) = kx + 5k')}</p>` +
        `<p>For a linear equation to have infinitely many solutions, the coefficients of ${math('x')} and the constant terms on both sides must be identical:</p>` +
        `<p>1. Matching coefficients of ${math('x')}: ${math('k = -11')}</p>` +
        `<p>2. Matching constant terms: ${math('\\frac{m - 29}{2} = 5k')}</p>` +
        `<p>Substitute ${math('k = -11')} into the constant equation:</p>` +
        `<p>${math('\\frac{m - 29}{2} = 5(-11) = -55')}</p>` +
        `<p>Multiply both sides by ${math('2')}:</p>` +
        `<p>${math('m - 29 = -110')}</p>` +
        `<p>Add ${math('29')} to both sides:</p>` +
        `<p>${math('m = -110 + 29 = -81')}</p>` +
        `<p><strong>Choices A, B, and C are incorrect</strong> values.</p>`
};

async function run() {
    console.log('Uploading explanations for Dec 2025 INT 1 Module 1...');
    for (const [id, exp] of Object.entries(explanationsM1)) {
        const res = await updateQuestion(id, { explanation: exp });
        console.log(`Updated INT 1 M1 Q (${id}):`, res.message);
    }
    console.log('Done Module 1!');
}

run();
