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
    '6a54d0784d554e04aa1bff0d':
        `<p><strong>The correct answer is 13.</strong> The given system of equations is:</p>` +
        `<p>${math('x + 7y = 26')}</p>` +
        `<p>${math('7y = 13')}</p>` +
        `<p>Notice that the term ${math('7y')} appears directly in both equations. Substitute ${math('7y = 13')} into the first equation:</p>` +
        `<p>${math('x + 13 = 26')}</p>` +
        `<p>Subtract ${math('13')} from both sides:</p>` +
        `<p>${math('x = 13')}</p>`,

    // Q2
    '6a54d1374d554e04aa1bff13':
        `<p><strong>Choice A is correct.</strong> Calculate the slope ${math('m')} of line ${math('q')} using the points ${math('(0, 10)')} and ${math('(1, 23)')}:</p>` +
        `<p>${math('m = \\frac{23 - 10}{1 - 0} = \\frac{13}{1} = 13')}</p>` +
        `<p>Since the line passes through ${math('(0, 10)')}, its y-intercept is ${math('10')}. In slope-intercept form, the equation is:</p>` +
        `<p>${math('y = 13x + 10')}</p>` +
        `<p>Rearranging the equation to standard form by subtracting ${math('y')} from both sides gives:</p>` +
        `<p>${math('13x - y + 10 = 0')}</p>` +
        `<p><strong>Choices B, C, and D are incorrect</strong> because they have incorrect constant terms and do not pass through ${math('(0, 10)')} and ${math('(1, 23)')}.</p>`,

    // Q3
    '6a54d1c94d554e04aa1bff19':
        `<p><strong>Choice C is correct.</strong> The solutions to the equation ${math('f(x) = 0')} are the x-intercepts of the graph of ${math('y = f(x)')} (the points where the curve intersects the horizontal x-axis). Inspecting the graph shown, the curve crosses the x-axis at exactly <strong>three</strong> distinct points. Therefore, there are three values of ${math('x')} for which ${math('f(x) = 0')}.</p>` +
        `<p><strong>Choices A, B, and D are incorrect</strong> counts of the x-intercepts.</p>`,

    // Q4
    '6a54d2404d554e04aa1bff29':
        `<p><strong>Choice B is correct.</strong> Factor the polynomial by grouping terms in pairs:</p>` +
        `<p>${math('9x^3 + 108x^2y + xy^2 + 12y^3 = (9x^3 + 108x^2y) + (xy^2 + 12y^3)')}</p>` +
        `<p>Factor out the greatest common factor from each pair:</p>` +
        `<p>${math('9x^2(x + 12y) + y^2(x + 12y)')}</p>` +
        `<p>Now factor out the common binomial term ${math('(x + 12y)')}:</p>` +
        `<p>${math('(9x^2 + y^2)(x + 12y)')}</p>` +
        `<p><strong>Choices A, C, and D are incorrect</strong> because expanding them does not produce the original four-term polynomial.</p>`,

    // Q5
    '6a54d3524d554e04aa1bff35':
        `<p><strong>Choice D is correct.</strong> The graph exhibits exponential growth with a horizontal asymptote at ${math('y = 2')} as ${math('x \\to -\\infty')}. This indicates an equation of the form ${math('y = b^x + 2')} with ${math('b > 1')}.</p>` +
        `<p>Checking the points from the graph:</p>` +
        `<p>• When ${math('x = 0')}, ${math('y = 4^0 + 2 = 1 + 2 = 3')}, matching the y-intercept ${math('(0, 3)')}.</p>` +
        `<p>• When ${math('x = 1')}, ${math('y = 4^1 + 2 = 4 + 2 = 6')}, matching the point ${math('(1, 6)')}.</p>` +
        `<p>Therefore, the equation of the graph is ${math('y = 4^x + 2')}.</p>` +
        `<p><strong>Choices A and C are incorrect</strong> because negative exponents indicate exponential decay towards positive infinity.</p>` +
        `<p><strong>Choice B is incorrect</strong> because it has a horizontal asymptote at ${math('y = 3')} and passes through ${math('(0, 4)')}.</p>`,

    // Q6
    '6a73f839fb6980734c71c210':
        `<p><strong>Choice B is correct.</strong> The phrase "at least 160" means greater than or equal to 160 (${math('\\ge 160')}). The total number of signatures collected is the sum of the signatures collected on Monday (${math('45')}) and the additional signatures collected on Tuesday (${math('s')}), which is ${math('s + 45')}. Setting this total to be at least ${math('160')} gives:</p>` +
        `<p>${math('s + 45 \\ge 160')}</p>` +
        `<p><strong>Choice A is incorrect</strong> because ${math('\\le')} means "at most", not "at least".</p>` +
        `<p><strong>Choices C and D are incorrect</strong> because they subtract ${math('45')} from ${math('s')} instead of adding.</p>`,

    // Q7
    '6a73f87efb6980734c71c216':
        `<p><strong>Choice A is correct.</strong> First, determine the y-intercept of the original line ${math('9x + 10y = 24')} by setting ${math('x = 0')}:</p>` +
        `<p>${math('9(0) + 10y = 24 \\implies 10y = 24 \\implies y = \\frac{24}{10} = \\frac{12}{5}')}</p>` +
        `<p>Shifting the graph upward by ${math('5')} units increases the y-coordinate of every point by ${math('5')}. The new y-intercept is:</p>` +
        `<p>${math('\\frac{12}{5} + 5 = \\frac{12}{5} + \\frac{25}{5} = \\frac{37}{5}')}</p>` +
        `<p>Thus, the y-intercept of the resulting graph is ${math('(0, \\frac{37}{5})')}.</p>` +
        `<p><strong>Choice B is incorrect</strong> because ${math('(0, \\frac{12}{5})')} is the original y-intercept before the vertical shift.</p>` +
        `<p><strong>Choices C and D are incorrect</strong> calculations.</p>`,

    // Q8
    '6a73f8cdfb6980734c71c21a':
        `<p><strong>Choice C is correct.</strong> In a proportional relationship between ${math('p')} and ${math('t')}, the ratio ${math('\\frac{p}{t} = k')} is constant. Using the given values ${math('p = 2310')} and ${math('t = 3080')}:</p>` +
        `<p>${math('k = \\frac{2310}{3080} = \\frac{231}{308} = \\frac{3}{4} = 0.75')}</p>` +
        `<p>To find the value of ${math('t')} when ${math('p = 1848')}, solve the proportion:</p>` +
        `<p>${math('\\frac{1848}{t} = 0.75 \\implies t = \\frac{1848}{0.75} = 2464')}</p>` +
        `<p><strong>Choices A, B, and D are incorrect</strong> computational errors.</p>`,

    // Q9
    '6a73f912fb6980734c71c21e':
        `<p><strong>Choice B is correct.</strong> The quadratic equation ${math('y = -4.9(x - 9.1)^2 + 12400')} is given in vertex form, ${math('y = a(x - h)^2 + k')}, where the vertex of the parabola is ${math('(h, k) = (9.1, 12400)')}. Because the leading coefficient ${math('a = -4.9')} is negative, the parabola opens downward, meaning the vertex represents the maximum point on the graph. In this real-world context, ${math('x')} represents the time in seconds and ${math('y')} represents the plane's height in meters. Therefore, the vertex indicates that the plane reached an estimated maximum height of ${math('12,400')} meters ${math('9.1')} seconds after starting the maneuver.</p>` +
        `<p><strong>Choice A is incorrect</strong> because it mistakenly interprets the coefficient ${math('-4.9')} as the time.</p>` +
        `<p><strong>Choices C and D are incorrect</strong> because they swap the values of time and height.</p>`,

    // Q10
    '6a73f942fb6980734c71c222':
        `<p><strong>Choice B is correct.</strong> Expand and rearrange the given equation:</p>` +
        `<p>${math('a(9 - x) = 36 - 4x')}</p>` +
        `<p>${math('9a - ax = 36 - 4x')}</p>` +
        `<p>Rearranging terms with ${math('x')} on one side gives:</p>` +
        `<p>${math('4x - ax = 36 - 9a')}</p>` +
        `<p>${math('(4 - a)x = 9(4 - a)')}</p>` +
        `<p>If ${math('a = 4')}, the equation becomes ${math('0x = 0')}, which is satisfied by all real numbers (infinitely many solutions). For any value of ${math('a \\ne 4')}, we can divide both sides by ${math('(4 - a)')} to obtain exactly one solution, ${math('x = 9')}. Since the problem states that the equation has exactly one solution, ${math('a')} CANNOT be <strong>4</strong>.</p>` +
        `<p><strong>Choices A, C, and D are incorrect</strong> because substituting ${math('a = 1')}, ${math('9')}, or ${math('36')} gives exactly one unique solution (${math('x = 9')}).</p>`,

    // Q11
    '6a73f975fb6980734c71c226':
        `<p><strong>Choice D is correct.</strong> Let ${math('n')} represent the number of 7-inch parts. It is given that:</p>` +
        `<p>• The number of 4-inch parts is ${math('5')} times ${math('n')}, which is ${math('5n')};</p>` +
        `<p>• The number of 7-inch parts is ${math('n')};</p>` +
        `<p>• The number of 9-inch parts is ${math('4')}.</p>` +
        `<p>The total number of parts made during the day is ${math('100')}. Summing the parts gives:</p>` +
        `<p>${math('5n + n + 4 = 100')}</p>` +
        `<p>${math('6n + 4 = 100')}</p>` +
        `<p><strong>Choice A is incorrect</strong> because it multiplies part sizes by quantities instead of counting parts.</p>` +
        `<p><strong>Choice B is incorrect</strong> because it assigns ${math('n')} to all part sizes.</p>` +
        `<p><strong>Choice C is incorrect</strong> because it omits the ${math('n')} 7-inch parts.</p>`,

    // Q12 (Essay)
    '6a73f9b0fb6980734c71c22a':
        `<p><strong>The correct answer is 42.</strong> The length of an arc of a circle is given by the formula:</p>` +
        `<p>${math('\\text{Arc Length} = 2\\pi r \\left(\\frac{\\theta}{360^\\circ}\\right)')}</p>` +
        `<p>Substitute the given arc length ${math('7\\pi')} and central angle ${math('\\theta = 30^\\circ')}:</p>` +
        `<p>${math('7\\pi = 2\\pi r \\left(\\frac{30}{360}\\right)')}</p>` +
        `<p>${math('7\\pi = 2\\pi r \\left(\\frac{1}{12}\\right) = \\frac{\\pi r}{6}')}</p>` +
        `<p>Divide both sides by ${math('\\pi')}:</p>` +
        `<p>${math('7 = \\frac{r}{6}')}</p>` +
        `<p>Multiply both sides by ${math('6')}:</p>` +
        `<p>${math('r = 42')}</p>`,

    // Q13
    '6a73f9e9fb6980734c71c22e':
        `<p><strong>Choice D is correct.</strong> The initial population in the base year (2003) is ${math('200')}. An increase of ${math('120\\%')} every 4 years means the population is multiplied by a growth factor of ${math('1 + 1.20 = 2.2')} at the end of each 4-year cycle. In ${math('t')} years after 2003, the number of 4-year intervals that have passed is ${math('\\frac{t}{4}')}. Therefore, the exponential model is:</p>` +
        `<p>${math('N = 200(2.2)^{\\frac{t}{4}}')}</p>` +
        `<p><strong>Choice A is incorrect</strong> because it uses ${math('4t')} instead of ${math('\\frac{t}{4}')} in the exponent.</p>` +
        `<p><strong>Choices B and C are incorrect</strong> because they use a growth factor of ${math('1.2')} (which represents a 20% increase, not 120%).</p>`,

    // Q14
    '6a73fa30fb6980734c71c232':
        `<p><strong>Choice C is correct.</strong> In triangle RST, ${math('RS = ST')}, so triangle RST is an isosceles triangle with base ${math('RT = 76')}. An altitude drawn from vertex ${math('S')} perpendicular to base ${math('RT')} bisects the base into two segments of length ${math('\\frac{76}{2} = 38')}.</p>` +
        `<p>Let ${math('h')} be the height of the triangle (the length of this altitude). In the right triangle formed by the altitude, half the base, and side ${math('RS')}:</p>` +
        `<p>${math('\\tan R = \\frac{\\text{opposite}}{\\text{adjacent}} = \\frac{h}{38}')}</p>` +
        `<p>It is given that ${math('\\tan R = \\frac{9}{38}')}, which implies ${math('\\frac{h}{38} = \\frac{9}{38} \\implies h = 9')}.</p>` +
        `<p>The area of triangle RST is:</p>` +
        `<p>${math('\\text{Area} = \\frac{1}{2} \\times \\text{base} \\times \\text{height} = \\frac{1}{2} \\times 76 \\times 9 = 38 \\times 9 = 342')}</p>` +
        `<p><strong>Choices A, B, and D are incorrect</strong> calculation errors.</p>`,

    // Q15
    '6a741074fb6980734c71c238':
        `<p><strong>Choice A is correct.</strong> The given system of equations is:</p>` +
        `<p>${math('x^2 + y^2 = 49')}</p>` +
        `<p>${math('y = mx + \\frac{b}{3}')}</p>` +
        `<p>The intersection point ${math('(-4, y)')} lies on the circle ${math('x^2 + y^2 = 49')}. Substitute ${math('x = -4')}:</p>` +
        `<p>${math('(-4)^2 + y^2 = 49 \\implies 16 + y^2 = 49 \\implies y^2 = 33')}</p>` +
        `<p>Since it is given that ${math('y < 0')}, we have ${math('y = -\\sqrt{33}')}.</p>` +
        `<p>The point ${math('(-4, -\\sqrt{33})')} also satisfies the linear equation ${math('y = mx + \\frac{b}{3}')}:</p>` +
        `<p>${math('-\\sqrt{33} = m(-4) + \\frac{b}{3} = -4m + \\frac{b}{3}')}</p>` +
        `<p>Add ${math('4m')} to both sides:</p>` +
        `<p>${math('4m - \\sqrt{33} = \\frac{b}{3}')}</p>` +
        `<p>Multiply both sides by ${math('3')}:</p>` +
        `<p>${math('b = 3(4m - \\sqrt{33}) = 12m - 3\\sqrt{33}')}</p>` +
        `<p><strong>Choices B, C, and D are incorrect</strong> algebraic variations.</p>`,

    // Q16 (Essay)
    '6a7410f1fb6980734c71c23c':
        `<p><strong>The correct answer is 0.</strong> For any real number ${math('u')}, the equation ${math('u^2 = a')} has:</p>` +
        `<p>• Exactly two real solutions if ${math('a > 0')} (${math('u = \\pm\\sqrt{a}')});</p>` +
        `<p>• Exactly one real solution if ${math('a = 0')} (${math('u = 0')});</p>` +
        `<p>• No real solutions if ${math('a < 0')}.</p>` +
        `<p>Setting ${math('u = 2x - 36')}, the equation ${math('(2x - 36)^2 = a')} has exactly one real solution if and only if ${math('a = 0')} (giving ${math('2x - 36 = 0 \\implies x = 18')}).</p>`,

    // Q17
    '6a7411d6fb6980734c71c240':
        `<p><strong>Choice B is correct.</strong> List the ${math('11')} data values of data set A in ascending order based on the frequency table:</p>` +
        `<p>${math('0, 0, 3, 3, 4, 4, 5, 5, 6, 7, 14')}</p>` +
        `<p>Since there are ${math('11')} values, the median of data set A is the 6th value, which is <strong>4</strong>.</p>` +
        `<p>When the value ${math('14')} is removed to create data set B, the remaining ${math('10')} values in ascending order are:</p>` +
        `<p>${math('0, 0, 3, 3, 4, 4, 5, 5, 6, 7')}</p>` +
        `<p>For ${math('10')} values, the median is the average of the 5th and 6th values:</p>` +
        `<p>${math('\\frac{4 + 4}{2} = 4')}</p>` +
        `<p>Therefore, the median of data set B is equal to the median of data set A.</p>` +
        `<p><strong>Choices A, C, and D are incorrect</strong> statements.</p>`,

    // Q18 (Essay)
    '6a74120efb6980734c71c244':
        `<p><strong>The correct answer is 33.</strong> Rewrite the given quadratic equation in standard form ${math('Ax^2 + Bx + C = 0')}:</p>` +
        `<p>${math('6x^2 + 11 = nx \\implies 6x^2 - nx + 11 = 0')}</p>` +
        `<p>A quadratic equation has exactly one real solution if and only if its discriminant ${math('\\Delta = B^2 - 4AC')} is equal to 0:</p>` +
        `<p>${math('(-n)^2 - 4(6)(11) = 0')}</p>` +
        `<p>${math('n^2 - 264 = 0')}</p>` +
        `<p>${math('n^2 = 264')}</p>` +
        `<p>The question asks for the value of ${math('\\frac{n^2}{8}')}:</p>` +
        `<p>${math('\\frac{n^2}{8} = \\frac{264}{8} = 33')}</p>`,

    // Q19
    '6a741242fb6980734c71c248':
        `<p><strong>Choice A is correct.</strong> For similar two-dimensional figures, the ratio of their areas is equal to the square of the ratio of their perimeters (scale factor ${math('k')}):</p>` +
        `<p>${math('\\frac{\\text{Area}_B}{\\text{Area}_A} = \\left(\\frac{\\text{Perimeter}_B}{\\text{Perimeter}_A}\\right)^2')}</p>` +
        `<p>Substitute the given areas:</p>` +
        `<p>${math('\\frac{4440}{1110} = 4')}</p>` +
        `<p>Therefore, the scale factor ${math('k')} is:</p>` +
        `<p>${math('k = \\sqrt{4} = 2')}</p>` +
        `<p>The perimeter of Rectangle B is ${math('2')} times the perimeter of Rectangle A:</p>` +
        `<p>${math('n = 2 \\times 370 = 740\\text{ inches}')}</p>` +
        `<p><strong>Choices B, C, and D are incorrect</strong> scale applications.</p>`,

    // Q20 (Essay)
    '6a7412f0fb6980734c71c24c':
        `<p><strong>The correct answer is 40/9 (or 4.444).</strong> In right triangle ABC with altitude ${math('AD')} drawn perpendicular to hypotenuse ${math('BC')}:</p>` +
        `<p>Triangles ABD and CAD are both right triangles and are similar to each other (${math('\\triangle ABD \\sim \\triangle CAD')}).</p>` +
        `<p>In right triangle ABD, angle B and angle BAD (${math('w^\\circ')}) are complementary: ${math('\\angle B = 90^\\circ - w^\\circ')}.</p>` +
        `<p>In right triangle ABC, angle B and angle C (${math('z^\\circ')}) are complementary: ${math('z^\\circ = 90^\\circ - \\angle B = 90^\\circ - (90^\\circ - w^\\circ) = w^\\circ')}.</p>` +
        `<p>Therefore, ${math('z = w')}.</p>` +
        `<p>We are given ${math('\\cos w = \\frac{9}{41}')}. Using the Pythagorean identity ${math('\\sin^2 w + \\cos^2 w = 1')}:</p>` +
        `<p>${math('\\sin w = \\sqrt{1 - \\left(\\frac{9}{41}\\right)^2} = \\sqrt{1 - \\frac{81}{1681}} = \\sqrt{\\frac{1600}{1681}} = \\frac{40}{41}')}</p>` +
        `<p>Since ${math('z = w')}, calculate ${math('\\tan z^\\circ')}:</p>` +
        `<p>${math('\\tan z^\\circ = \\tan w^\\circ = \\frac{\\sin w}{\\cos w} = \\frac{40/41}{9/41} = \\frac{40}{9}')}</p>` +
        `<p>Either <strong>40/9</strong> or its decimal form <strong>4.444</strong> is correct.</p>`,

    // Q21
    '6a741399fb6980734c71c250':
        `<p><strong>Choice D is correct.</strong> In triangle XYZ, the sum of the interior angle measures is ${math('180^\\circ')}:</p>` +
        `<p>${math('x + y + 17 = 180 \\implies x + y = 163')}</p>` +
        `<p>To determine the individual values of ${math('x')} and ${math('y')}, any additional information must provide a second linear equation in ${math('x')} and ${math('y')} that is independent of ${math('x + y = 163')}.</p>` +
        `<p>In Choice D, the expression is ${math('17 - 3x - 3y = 17 - 3(x + y)')}. Since ${math('x + y')} is already known to be ${math('163')}, this expression is always equal to ${math('17 - 3(163) = -472')}. Therefore, knowing the value of this expression provides no new information about ${math('x')} and ${math('y')}, making it <strong>NOT sufficient</strong>.</p>` +
        `<p>In Choices A, B, and C, the coefficients of ${math('x')} and ${math('y')} are not equal multiples of ${math('(1, 1)')}, each yielding an independent linear equation that uniquely determines ${math('x')} and ${math('y')}.</p>`,

    // Q22
    '6a7413defb6980734c71c254':
        `<p><strong>Choice C is correct.</strong> Let ${math('E_{2006}')} be Elijah\'s earnings in 2006.</p>` +
        `<p>In 2007, Elijah earned ${math('17\\%')} more than in 2006:</p>` +
        `<p>${math('E_{2007} = 1.17 \\times E_{2006}')}</p>` +
        `<p>In 2008, Elijah earned ${math('3\\%')} more than in 2007:</p>` +
        `<p>${math('E_{2008} = 1.03 \\times E_{2007} = 1.03 \\times (1.17 \\times E_{2006}) = 1.2051 \\times E_{2006}')}</p>` +
        `<p>It is given that Elijah earned ${math('y')} times as much in 2006 as in 2008:</p>` +
        `<p>${math('E_{2006} = y \\times E_{2008}')}</p>` +
        `<p>Solving for ${math('y')}:</p>` +
        `<p>${math('y = \\frac{E_{2006}}{E_{2008}} = \\frac{1}{1.2051} \\approx 0.8298066')}</p>` +
        `<p>Rounded to four decimal places, ${math('y \\approx 0.8298')}.</p>` +
        `<p><strong>Choices A, B, and D are incorrect</strong> numerical values.</p>`
};

async function run() {
    console.log('Uploading explanations for Dec 2025 US 2 Module 2...');
    for (const [id, exp] of Object.entries(explanationsM2)) {
        const res = await updateQuestion(id, { explanation: exp });
        console.log(`Updated M2 Q (${id}):`, res.message);
    }
    console.log('Done Module 2!');
}

run();
