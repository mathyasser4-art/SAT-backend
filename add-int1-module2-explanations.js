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

const explanationsM2 = {
    // Q1 (Essay)
    '6a5b340ac3d08d90637d3049':
        `<p><strong>The correct answer is 78.</strong> The sum of the interior angle measures of any triangle is ${math('180^\\circ')}. In triangle JKL:</p>` +
        `<p>${math('\\angle J + \\angle K + \\angle L = 180^\\circ')}</p>` +
        `<p>Since the measures of ${math('\\angle K')} and ${math('\\angle L')} are each ${math('51^\\circ')}:</p>` +
        `<p>${math('\\angle J + 51^\\circ + 51^\\circ = 180^\\circ')}</p>` +
        `<p>${math('\\angle J + 102^\\circ = 180^\\circ')}</p>` +
        `<p>Subtract ${math('102^\\circ')} from both sides:</p>` +
        `<p>${math('\\angle J = 180^\\circ - 102^\\circ = 78^\\circ')}</p>`,

    // Q2
    '6a5b3473c3d08d90637d304d':
        `<p><strong>Choice B is correct.</strong> In the given table, when ${math('x = 3')}, the value of ${math('y')} is ${math('a')}. Substitute ${math('x = 3')} into the equation ${math('y = 7(2)^x + 8')}:</p>` +
        `<p>${math('a = 7(2)^3 + 8')}</p>` +
        `<p>${math('a = 7(8) + 8 = 56 + 8 = 64')}</p>` +
        `<p><strong>Choices A, C, and D are incorrect</strong> computational errors.</p>`,

    // Q3 (Essay)
    '6a5b348bc3d08d90637d3051':
        `<p><strong>The correct answer is 6.</strong> To determine the minimum number of packages required, divide the total number of hamburger buns needed (${math('65')}) by the number of buns per package (${math('12')}):</p>` +
        `<p>${math('\\frac{65}{12} = 5.416\\dots')}</p>` +
        `<p>Since hamburger buns can only be bought in whole packages, buying ${math('5')} packages would yield only ${math('5 \\times 12 = 60')} buns, which is insufficient. Therefore, at least <strong>6</strong> packages must be purchased (${math('6 \\times 12 = 72')} buns).</p>`,

    // Q4
    '6a5b34c0c3d08d90637d3055':
        `<p><strong>Choice A is correct.</strong> The total surface area of a right circular cylinder consists of the lateral area plus the area of its two circular bases:</p>` +
        `<p>${math('\\text{Total Surface Area} = \\text{Lateral Area} + 2(\\text{Base Area})')}</p>` +
        `<p>1. The circumference of the base is given as ${math('C = 360')} inches. The radius ${math('r')} can be found using ${math('C = 2\\pi r')}:</p>` +
        `<p>${math('2\\pi r = 360 \\implies r = \\frac{360}{2\\pi} = \\frac{180}{\\pi}')}</p>` +
        `<p>2. The lateral area is the circumference times height: ${math('(360)(36) = (36)(360)')}.</p>` +
        `<p>3. The area of the two bases is ${math('2\\pi r^2 = 2\\pi \\left(\\frac{180}{\\pi}\\right)^2')}.</p>` +
        `<p>Adding these components yields ${math('(36)(360) + 2\\pi \\left(\\frac{180}{\\pi}\\right)^2')}.</p>` +
        `<p><strong>Choice B is incorrect</strong> because it only includes one base.</p>` +
        `<p><strong>Choice C is incorrect</strong> because it represents the volume of the cylinder.</p>` +
        `<p><strong>Choice D is incorrect</strong> because it represents only the lateral surface area.</p>`,

    // Q5
    '6a5b3528c3d08d90637d3065':
        `<p><strong>Choice A is correct.</strong> In statistical sampling, the margin of error is inversely proportional to the square root of the sample size (${math('\\text{Margin of Error} \\propto \\frac{1}{\\sqrt{n}}')}). Increasing the random sample size from ${math('90')} to ${math('180')} students reduces the standard error of the estimate, which results in a smaller (lower) margin of error.</p>` +
        `<p><strong>Choice B is incorrect</strong> because larger samples decrease variability, thereby lowering the margin of error.</p>` +
        `<p><strong>Choices C and D are incorrect</strong> because increasing the sample size makes the sample mean a more precise estimator of the population mean, but does not systematically increase or decrease the average itself.</p>`,

    // Q6
    '6a5b3acdc3d08d90637d3071':
        `<p><strong>Choice D is correct.</strong> Add the two equations in the system directly:</p>` +
        `<p>${math('2x + 5y = 260')}</p>` +
        `<p>${math('-2x + 3y = 260')}</p>` +
        `<p>Adding the left sides eliminates the ${math('x')} terms:</p>` +
        `<p>${math('(2x - 2x) + (5y + 3y) = 260 + 260')}</p>` +
        `<p>${math('8y = 520')}</p>` +
        `<p>Since the question asks directly for the value of ${math('8y')}, the answer is <strong>520</strong>.</p>` +
        `<p><strong>Choice B is incorrect</strong> because ${math('65')} is the value of ${math('y')} (${math('520 / 8 = 65')}), not ${math('8y')}.</p>` +
        `<p><strong>Choices A and C are incorrect</strong> computational errors.</p>`,

    // Q7
    '6a5b3b16c3d08d90637d3075':
        `<p><strong>Choice C is correct.</strong> Given the equation:</p>` +
        `<p>${math('\\frac{9x}{2} - 11 = \\frac{45}{2} - 11')}</p>` +
        `<p>Add ${math('11')} to both sides of the equation:</p>` +
        `<p>${math('\\frac{9x}{2} = \\frac{45}{2}')}</p>` +
        `<p>Multiply both sides by ${math('2')}:</p>` +
        `<p>${math('9x = 45')}</p>` +
        `<p>The question asks for the value of ${math('9x')}, which is <strong>45</strong>.</p>` +
        `<p><strong>Choice A is incorrect</strong> because ${math('5')} is the value of ${math('x')} (${math('45 / 9 = 5')}), not ${math('9x')}.</p>` +
        `<p><strong>Choices B and D are incorrect</strong> distractors.</p>`,

    // Q8 (Essay)
    '6a5b3baec3d08d90637d3087':
        `<p><strong>The correct answer is 35/12 (or 105/36).</strong> Solve the system of linear equations:</p>` +
        `<p>1) ${math('8x - 7y = 5')}</p>` +
        `<p>2) ${math('4x + y = 8')}</p>` +
        `<p>Multiply the second equation by ${math('2')} so the coefficients of ${math('x')} match:</p>` +
        `<p>${math('8x + 2y = 16')}</p>` +
        `<p>Subtract the first equation from this new equation:</p>` +
        `<p>${math('(8x + 2y) - (8x - 7y) = 16 - 5')}</p>` +
        `<p>${math('9y = 11 \\implies y = \\frac{11}{9}')}</p>` +
        `<p>Substitute ${math('y = \\frac{11}{9}')} into the second equation to find ${math('x')}:</p>` +
        `<p>${math('4x + \\frac{11}{9} = 8 \\implies 4x = \\frac{72}{9} - \\frac{11}{9} = \\frac{61}{9} \\implies x = \\frac{61}{36}')}</p>` +
        `<p>Calculate the value of ${math('x + y')}:</p>` +
        `<p>${math('x + y = \\frac{61}{36} + \\frac{11}{9} = \\frac{61}{36} + \\frac{44}{36} = \\frac{105}{36} = \\frac{35}{12}')}</p>` +
        `<p>Either <strong>35/12</strong> or <strong>105/36</strong> is accepted.</p>`,

    // Q9
    '6a5b3c50c3d08d90637d3093':
        `<p><strong>Choice A is correct.</strong> In the linear model ${math('H = 2.419L + 22.83')}, ${math('H')} represents the estimated height and ${math('L')} represents the femur length, both in inches. In any linear equation of the form ${math('y = mx + b')}, the slope ${math('m')} represents the change in the dependent variable for every unit increase in the independent variable. Here, the slope is ${math('2.419')}, which means that for each increase of 1 inch in femur length, the student\'s estimated height increases by <strong>2.419 inches</strong>.</p>` +
        `<p><strong>Choice B is incorrect</strong> because it inverts the roles of independent and dependent variables.</p>` +
        `<p><strong>Choice C is incorrect</strong> because ${math('22.83')} is the y-intercept, not the step size.</p>` +
        `<p><strong>Choice D is incorrect</strong> because it describes the value of ${math('H')} rather than the rate of change.</p>`,

    // Q10 (Essay)
    '6a5b3c8fc3d08d90637d3097':
        `<p><strong>The correct answer is 175.</strong> Substitute ${math('x = 75.0')} into the given mixture equation:</p>` +
        `<p>${math('0.10(75.0) + 0.20y = 0.17(75.0 + y)')}</p>` +
        `<p>${math('7.5 + 0.20y = 12.75 + 0.17y')}</p>` +
        `<p>Subtract ${math('0.17y')} from both sides:</p>` +
        `<p>${math('7.5 + 0.03y = 12.75')}</p>` +
        `<p>Subtract ${math('7.5')} from both sides:</p>` +
        `<p>${math('0.03y = 5.25')}</p>` +
        `<p>Divide both sides by ${math('0.03')}:</p>` +
        `<p>${math('y = \\frac{5.25}{0.03} = 175')}</p>` +
        `<p>Therefore, <strong>175</strong> gallons of the 20% solution must be mixed.</p>`,

    // Q11 (Essay)
    '6a5b3cdec3d08d90637d309b':
        `<p><strong>The correct answer is 552.</strong> Translate each statement into an algebraic equation:</p>` +
        `<p>1. "${math('0.1242')} is ${math('0.09\\%')} of ${math('b')}":</p>` +
        `<p>Note that ${math('0.09\\% = \\frac{0.09}{100} = 0.0009')}. Thus:</p>` +
        `<p>${math('0.1242 = 0.0009b \\implies b = \\frac{0.1242}{0.0009} = 138')}</p>` +
        `<p>2. "The number ${math('b')} is ${math('25\\%')} of the number ${math('c')}":</p>` +
        `<p>${math('138 = 0.25c \\implies c = \\frac{138}{0.25} = 138 \\times 4 = 552')}</p>` +
        `<p>Therefore, the value of ${math('c')} is <strong>552</strong>.</p>`,

    // Q12
    '6a5b3d43c3d08d90637d309f':
        `<p><strong>Choice B is correct.</strong> First determine the slope of the given line by rewriting ${math('-3x + y = 20')} in slope-intercept form:</p>` +
        `<p>${math('y = 3x + 20')}</p>` +
        `<p>The slope of this line is ${math('3')}. Since line ${math('h')} is perpendicular to this line, its slope must be the negative reciprocal of ${math('3')}, which is ${math('-\\frac{1}{3}')}.</p>` +
        `<p>Line ${math('h')} passes through ${math('(0, 0)')}, so its equation is ${math('y = -\\frac{1}{3}x')}.</p>` +
        `<p>Line ${math('h')} also passes through ${math('(18, t)')}. Substituting ${math('x = 18')} and ${math('y = t')}:</p>` +
        `<p>${math('t = -\\frac{1}{3}(18) = -6')}</p>` +
        `<p><strong>Choices A, C, and D are incorrect</strong> calculation errors.</p>`,

    // Q13
    '6a5b3da3c3d08d90637d30a3':
        `<p><strong>Choice D is correct.</strong> A system of two linear equations in two variables has no solution if and only if the lines are parallel and distinct (having identical slopes but different y-intercepts).</p>` +
        `<p>Examine the system in Choice D:</p>` +
        `<p>Equation 1: ${math('-3x + 9y = 2 \\implies 9y = 3x + 2 \\implies y = \\frac{1}{3}x + \\frac{2}{9}')}</p>` +
        `<p>Equation 2: ${math('6x - 18y = 4 \\implies -18y = -6x + 4 \\implies y = \\frac{1}{3}x - \\frac{2}{9}')}</p>` +
        `<p>Both lines have slope ${math('\\frac{1}{3}')}, but their y-intercepts are ${math('\\frac{2}{9}')} and ${math('-\\frac{2}{9}')}. Because the slopes are equal and the y-intercepts are unequal, the lines are parallel and never intersect, meaning the system has <strong>no solution</strong>.</p>` +
        `<p><strong>Choices A and C are incorrect</strong> because the equations are multiples of each other, yielding infinitely many solutions.</p>` +
        `<p><strong>Choice B is incorrect</strong> because the lines have different slopes, yielding exactly one unique solution.</p>`,

    // Q14
    '6a5b3e0bc3d08d90637d30a7':
        `<p><strong>Choice C is correct.</strong> In the exponential function ${math('f(x) = 6000(1.003)^{2x}')}, ${math('x')} is the number of years. Rewrite the exponent as ${math('2x = \\frac{x}{0.5}')}, where ${math('0.5')} years represents 6 months. In one year, there are two 6-month compounding intervals. The base ${math('1.003 = 1 + 0.003')} corresponds to a growth factor of ${math('0.003 = 0.3\\%')}. Thus, at the end of every 6-month interval, the account balance increases by about <strong>0.3%</strong> of the balance at the beginning of that 6-month interval.</p>` +
        `<p><strong>Choices A and B are incorrect</strong> because the increase is a percentage of the balance, not a constant 3 dollars.</p>` +
        `<p><strong>Choice D is incorrect</strong> because ${math('2x')} represents two intervals per year (every 6 months), not an interval of 2 years.</p>`,

    // Q15
    '6a5b3e80c3d08d90637d30ab':
        `<p><strong>Choice C is correct.</strong> Factor the quadratic expression ${math('2x^2 + (18r + 5)x + 45r')}:</p>` +
        `<p>Distribute the middle term:</p>` +
        `<p>${math('2x^2 + 18rx + 5x + 45r')}</p>` +
        `<p>Group terms in pairs:</p>` +
        `<p>${math('(2x^2 + 18rx) + (5x + 45r)')}</p>` +
        `<p>Factor out the greatest common factor from each pair:</p>` +
        `<p>${math('2x(x + 9r) + 5(x + 9r)')}</p>` +
        `<p>Factor out the common binomial factor ${math('(x + 9r)')}:</p>` +
        `<p>${math('(2x + 5)(x + 9r)')}</p>` +
        `<p>Both Statement I (${math('x + 9r')}) and Statement II (${math('2x + 5')}) are factors of the expression. Therefore, <strong>I and II</strong> is correct.</p>` +
        `<p><strong>Choices A, B, and D are incorrect</strong> because both factors are valid.</p>`,

    // Q16
    '6a5b3eecc3d08d90637d30c6':
        `<p><strong>Choice C is correct.</strong> Isolate the absolute value expression by dividing both sides by ${math('5')}:</p>` +
        `<p>${math('|x - 8| = \\frac{k}{5}')}</p>` +
        `<p>For any absolute value equation of the form ${math('|u| = c')}:</p>` +
        `<p>• If ${math('c > 0')}, there are two distinct real solutions;</p>` +
        `<p>• If ${math('c < 0')}, there are no real solutions;</p>` +
        `<p>• If ${math('c = 0')}, there is exactly one real solution (${math('u = 0')}).</p>` +
        `<p>Because the problem specifies that the equation has exactly one solution, ${math('\\frac{k}{5}')} must equal <strong>0 only</strong>.</p>` +
        `<p><strong>Choices A, B, and D are incorrect</strong> because setting ${math('\\frac{k}{5}')} to 8 or -8 results in either two solutions or no solutions.</p>`,

    // Q17
    '6a5b3f21c3d08d90637d30ca':
        `<p><strong>Choice A is correct.</strong> Isolate the absolute value term in the equation ${math('8|7 - x| + 2 = 82')}:</p>` +
        `<p>Subtract ${math('2')} from both sides:</p>` +
        `<p>${math('8|7 - x| = 80')}</p>` +
        `<p>Divide both sides by ${math('8')}:</p>` +
        `<p>${math('|7 - x| = 10')}</p>` +
        `<p>This gives two linear cases:</p>` +
        `<p><strong>Case 1:</strong> ${math('7 - x = 10 \\implies -x = 3 \\implies x = -3')}</p>` +
        `<p><strong>Case 2:</strong> ${math('7 - x = -10 \\implies -x = -17 \\implies x = 17')}</p>` +
        `<p>The sum of the solutions is:</p>` +
        `<p>${math('-3 + 17 = 14')}</p>` +
        `<p>(Alternatively, since solutions are symmetric around ${math('7')}, their sum is ${math('2 \\times 7 = 14')}).</p>` +
        `<p><strong>Choices B, C, and D are incorrect</strong> calculation errors.</p>`,

    // Q18 (Essay)
    '6a5b3f76c3d08d90637d30d0':
        `<p><strong>The correct answer is 341.</strong> The seal\'s depth is modeled by a quadratic function ${math('g(t)')}. The seal reaches its maximum depth of ${math('396.8')} meters at ${math('t = 8')} minutes, so the vertex of the parabola is ${math('(8, 396.8)')}. In vertex form:</p>` +
        `<p>${math('g(t) = a(t - 8)^2 + 396.8')}</p>` +
        `<p>The seal returns to the surface (${math('g(t) = 0')}) at ${math('t = 16')} minutes. Substitute ${math('t = 16')} and ${math('g(16) = 0')}:</p>` +
        `<p>${math('0 = a(16 - 8)^2 + 396.8')}</p>` +
        `<p>${math('0 = 64a + 396.8 \\implies 64a = -396.8 \\implies a = -6.2')}</p>` +
        `<p>Thus, the function is ${math('g(t) = -6.2(t - 8)^2 + 396.8')}.</p>` +
        `<p>To find the estimated depth ${math('11')} minutes after entering the water, evaluate ${math('g(11)')}:</p>` +
        `<p>${math('g(11) = -6.2(11 - 8)^2 + 396.8 = -6.2(9) + 396.8 = -55.8 + 396.8 = 341.0\\text{ meters}')}</p>` +
        `<p>Rounded to the nearest meter, the estimated depth is <strong>341</strong> meters.</p>`,

    // Q19
    '6a5b40e9c3d08d90637d30d4':
        `<p><strong>Choice D is correct.</strong> In triangle XYZ with right angle at X, point W lies on segment XZ and segment WV is perpendicular to segment YZ at point V. Triangle ZVW is a right triangle with right angle at V.</p>` +
        `<p>In right triangle ZVW, angle Z is an acute angle. The tangent of angle Z is defined as the ratio of the length of the opposite leg to the length of the adjacent leg:</p>` +
        `<p>${math('\\tan Z = \\frac{\\text{opposite}}{\\text{adjacent}} = \\frac{WV}{ZV}')}</p>` +
        `<p>Substitute the given side lengths ${math('WV = 668')} and ${math('ZV = 501')}:</p>` +
        `<p>${math('\\tan Z = \\frac{668}{501}')}</p>` +
        `<p>Both numbers are divisible by ${math('167')} (${math('668 = 4 \\times 167')} and ${math('501 = 3 \\times 167')}):</p>` +
        `<p>${math('\\tan Z = \\frac{4}{3}')}</p>` +
        `<p><strong>Choices A, B, and C are incorrect</strong> ratios.</p>`,

    // Q20
    '6a5b42dfc3d08d90637d30da':
        `<p><strong>Choice D is correct.</strong> Let ${math('M')} be the initial mass of chemical A and chemical B in the mixture.</p>` +
        `<p>1. The mass of chemical A increased by ${math('2,600\\%')}:</p>` +
        `<p>${math('M_A = M + 26M = 27M')}</p>` +
        `<p>2. The mass of chemical B increased by ${math('380\\%')}:</p>` +
        `<p>${math('M_B = M + 3.8M = 4.8M')}</p>` +
        `<p>3. To find how many times greater the mass of chemical A was than chemical B at the end of the study, calculate the ratio:</p>` +
        `<p>${math('\\frac{M_A}{M_B} = \\frac{27M}{4.8M} = \\frac{27}{4.8} = 5.625')}</p>` +
        `<p>Rounding to two decimal places gives approximately <strong>5.63</strong>.</p>` +
        `<p><strong>Choices A, B, and C are incorrect</strong> calculation errors.</p>`,

    // Q21 (Essay)
    '6a5b431ac3d08d90637d30de':
        `<p><strong>The correct answer is 10.</strong> Rewrite the quadratic equation in standard form ${math('Ar^2 + Br + C = 0')}:</p>` +
        `<p>${math('r^2 - qr = 8r - 87')}</p>` +
        `<p>${math('r^2 - (q + 8)r + 87 = 0')}</p>` +
        `<p>A quadratic equation has no real solutions if and only if its discriminant ${math('\\Delta = B^2 - 4AC')} is strictly negative (${math('\\Delta < 0')}):</p>` +
        `<p>${math('(-(q + 8))^2 - 4(1)(87) < 0')}</p>` +
        `<p>${math('(q + 8)^2 - 348 < 0')}</p>` +
        `<p>${math('(q + 8)^2 < 348')}</p>` +
        `<p>Taking the square root of both sides gives ${math('-\\sqrt{348} < q + 8 < \\sqrt{348}')}.</p>` +
        `<p>Since ${math('\\sqrt{348} \\approx 18.6547')}:</p>` +
        `<p>${math('q + 8 < 18.6547 \\implies q < 10.6547')}</p>` +
        `<p>Since ${math('q')} is an integer constant, the largest possible integer value for ${math('q')} is <strong>10</strong>.</p>`,

    // Q22
    '6a5b434ec3d08d90637d30e2':
        `<p><strong>Choice B is correct.</strong> In an isosceles right triangle, the two legs have equal length ${math('x')}, and by the Pythagorean theorem, the hypotenuse has length ${math('x\\sqrt{2}')}.</p>` +
        `<p>The perimeter is the sum of the three side lengths:</p>` +
        `<p>${math('\\text{Perimeter} = x + x + x\\sqrt{2} = 2x + x\\sqrt{2} = x(2 + \\sqrt{2})')}</p>` +
        `<p>Set this equal to the given perimeter ${math('34 + 34\\sqrt{2}')}:</p>` +
        `<p>${math('x(2 + \\sqrt{2}) = 34(1 + \\sqrt{2})')}</p>` +
        `<p>Notice that ${math('2 + \\sqrt{2} = \\sqrt{2}(\\sqrt{2} + 1)')}. Therefore:</p>` +
        `<p>${math('x \\cdot \\sqrt{2}(1 + \\sqrt{2}) = 34(1 + \\sqrt{2})')}</p>` +
        `<p>Divide both sides by ${math('(1 + \\sqrt{2})')}:</p>` +
        `<p>${math('x\\sqrt{2} = 34')}</p>` +
        `<p>Divide by ${math('\\sqrt{2}')}:</p>` +
        `<p>${math('x = \\frac{34}{\\sqrt{2}} = \\frac{34\\sqrt{2}}{2} = 17\\sqrt{2}')}</p>` +
        `<p>Therefore, the length of one leg of the triangle is <strong>17√2</strong> inches.</p>` +
        `<p><strong>Choice A is incorrect</strong> because it would give a perimeter of ${math('34 + 17\\sqrt{2}')}.</p>` +
        `<p><strong>Choice C is incorrect</strong> because ${math('34')} is the hypotenuse length.</p>` +
        `<p><strong>Choice D is incorrect</strong> because it is double the required leg length.</p>`
};

async function run() {
    console.log('Uploading explanations for Dec 2025 INT 1 Module 2...');
    for (const [id, exp] of Object.entries(explanationsM2)) {
        const res = await updateQuestion(id, { explanation: exp });
        console.log(`Updated INT 1 M2 Q (${id}):`, res.message);
    }
    console.log('Done Module 2!');
}

run();
