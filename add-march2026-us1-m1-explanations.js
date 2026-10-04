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

const explanationsM1 = {
    // Q1 (6a518ce14d554e04aa1bec40) - Choice B
    '6a518ce14d554e04aa1bec40': `<p><strong>Correct Answer: B</strong></p><p>First, find the equation of the dashed boundary line. The line passes through the <span class="ql-formula" data-value="x"></span>-intercept <span class="ql-formula" data-value="(-4, 0)"></span> and the <span class="ql-formula" data-value="y"></span>-intercept <span class="ql-formula" data-value="(0, 12)"></span>.</p><p>Calculate the slope <span class="ql-formula" data-value="m"></span> of the line:</p><p><span class="ql-formula" data-value="m = \\frac{12 - 0}{0 - (-4)} = \\frac{12}{4} = 3"></span></p><p>With a <span class="ql-formula" data-value="y"></span>-intercept of 12, the equation of the boundary line is <span class="ql-formula" data-value="y = 3x + 12"></span>.</p><p>Because the boundary line is dashed, the inequality is strict (<span class="ql-formula" data-value="<"></span> or <span class="ql-formula" data-value=">"></span>). Testing the origin <span class="ql-formula" data-value="(0, 0)"></span>, which is located in the shaded region:</p><p><span class="ql-formula" data-value="0 < 3(0) + 12 \\implies 0 < 12"></span> (True).</p><p>Therefore, the inequality is <span class="ql-formula" data-value="y < 3x + 12"></span>.</p>`,

    // Q2 (6a518f184d554e04aa1bec48) - Grid-in 96
    '6a518f184d554e04aa1bec48': `<p><strong>Correct Answer: 96</strong></p><p>The sum of the interior angle measures of triangle <span class="ql-formula" data-value="DEF"></span> is <span class="ql-formula" data-value="180^\\circ"></span>:</p><p><span class="ql-formula" data-value="42 + x + (2x + 12) = 180"></span></p><p><span class="ql-formula" data-value="3x + 54 = 180"></span></p><p>Subtract 54 from both sides:</p><p><span class="ql-formula" data-value="3x = 126 \\implies x = 42"></span></p><p>Now find the measure of angle <span class="ql-formula" data-value="F"></span>:</p><p><span class="ql-formula" data-value="\\text{Angle } F = 2(42) + 12 = 84 + 12 = 96^\\circ"></span></p><p>Because the side lengths of triangle <span class="ql-formula" data-value="QRS"></span> are proportional to triangle <span class="ql-formula" data-value="DEF"></span> (<span class="ql-formula" data-value="ke, kf, kd"></span> with <span class="ql-formula" data-value="k = 2"></span>), triangle <span class="ql-formula" data-value="QRS"></span> is similar to triangle <span class="ql-formula" data-value="DEF"></span>. In similar triangles, corresponding angles are equal. Side <span class="ql-formula" data-value="QS = ke"></span> corresponds to <span class="ql-formula" data-value="DF = e"></span> and side <span class="ql-formula" data-value="RS = kd"></span> corresponds to <span class="ql-formula" data-value="EF = d"></span>, meaning angle <span class="ql-formula" data-value="S"></span> corresponds to angle <span class="ql-formula" data-value="F"></span>.</p><p>Therefore, the measure of angle <span class="ql-formula" data-value="S"></span> is <span class="ql-formula" data-value="96^\\circ"></span>.</p>`,

    // Q3 (6a5190284d554e04aa1bec60) - Choice A
    '6a5190284d554e04aa1bec60': `<p><strong>Correct Answer: A</strong></p><p>To determine the number of distinct real solutions of the quadratic equation <span class="ql-formula" data-value="3x^2 - 13x + 19 = 0"></span>, calculate its discriminant <span class="ql-formula" data-value="D = b^2 - 4ac"></span>:</p><p>Here, <span class="ql-formula" data-value="a = 3"></span>, <span class="ql-formula" data-value="b = -13"></span>, and <span class="ql-formula" data-value="c = 19"></span>:</p><p><span class="ql-formula" data-value="D = (-13)^2 - 4(3)(19) = 169 - 228 = -59"></span></p><p>Because the discriminant is negative (<span class="ql-formula" data-value="D = -59 < 0"></span>), the equation has <strong>zero</strong> distinct real solutions.</p>`,

    // Q4 (6a5190c54d554e04aa1bec66) - Choice C
    '6a5190c54d554e04aa1bec66': `<p><strong>Correct Answer: C</strong></p><p>The solution to a system of equations graphed in the <span class="ql-formula" data-value="xy"></span>-plane corresponds to the point(s) of intersection of the two graphs.</p><p>The horizontal line is <span class="ql-formula" data-value="y = 3"></span>, which intersects the downward-opening parabola at its vertex. Observing the grid, the vertex of the parabola is located at <span class="ql-formula" data-value="(-5, 3)"></span>.</p><p>Therefore, the solution to the system is <span class="ql-formula" data-value="(-5, 3)"></span>.</p>`,

    // Q5 (6a5191724d554e04aa1bec70) - Choice B
    '6a5191724d554e04aa1bec70': `<p><strong>Correct Answer: B</strong></p><p>The function is defined by <span class="ql-formula" data-value="h(x) = 8x"></span>. To find the value of <span class="ql-formula" data-value="h(x)"></span> when <span class="ql-formula" data-value="x = 48"></span>, substitute 48 into the function:</p><p><span class="ql-formula" data-value="h(48) = 8(48) = 384"></span></p><p>Thus, the value of <span class="ql-formula" data-value="h(48)"></span> is 384.</p>`,

    // Q6 (6a5191ea4d554e04aa1bec92) - Grid-in 66
    '6a5191ea4d554e04aa1bec92': `<p><strong>Correct Answer: 66</strong></p><p>Distance is equal to speed multiplied by time:</p><p><span class="ql-formula" data-value="\\text{Distance} = \\text{Speed} \\times \\text{Time} = 22\\text{ m/s} \\times 3\\text{ s} = 66\\text{ meters}"></span></p>`,

    // Q7 (6a5192e94d554e04aa1bec9c) - Grid-in 91/6 or 15.167
    '6a5192e94d554e04aa1bec9c': `<p><strong>Correct Answer: 91/6 (or 15.167)</strong></p><p>Subtract 1 from both sides of the equation:</p><p><span class="ql-formula" data-value="\\frac{13}{x} = \\frac{13}{7} - 1"></span></p><p><span class="ql-formula" data-value="\\frac{13}{x} = \\frac{13 - 7}{7} = \\frac{6}{7}"></span></p><p>Cross-multiply to solve for <span class="ql-formula" data-value="x"></span>:</p><p><span class="ql-formula" data-value="6x = 13 \\times 7 = 91"></span></p><p><span class="ql-formula" data-value="x = \\frac{91}{6} \\approx 15.167"></span></p>`,

    // Q8 (6a51955e4d554e04aa1becca) - Grid-in 52
    '6a51955e4d554e04aa1becca': `<p><strong>Correct Answer: 52</strong></p><p>When two straight lines intersect, opposite angles are vertical angles. Vertical angles are congruent and have equal measures:</p><p><span class="ql-formula" data-value="s^\\circ = r^\\circ"></span></p><p>Since we are given <span class="ql-formula" data-value="r = 52"></span>, the value of <span class="ql-formula" data-value="s"></span> is 52.</p>`,

    // Q9 (6a519bf74d554e04aa1bed14) - Choice B
    '6a519bf74d554e04aa1bed14': `<p><strong>Correct Answer: B</strong></p><p>Let <span class="ql-formula" data-value="h"></span> be the number of hardcover books and <span class="ql-formula" data-value="p"></span> be the number of paperback books. The total number of books purchased is 21, so:</p><p><span class="ql-formula" data-value="h + p = 21"></span></p><p>Each hardcover book costs 3 dollars and each paperback book costs 2 dollars, and the total expenditure is 49 dollars:</p><p><span class="ql-formula" data-value="3h + 2p = 49"></span></p><p>Combining these gives the system in Choice B.</p>`,

    // Q10 (6a519cbc4d554e04aa1bed4a) - Choice D
    '6a519cbc4d554e04aa1bed4a': `<p><strong>Correct Answer: D</strong></p><p>Half of the number <span class="ql-formula" data-value="a"></span> is represented by <span class="ql-formula" data-value="\\frac{a}{2}"></span>. 15 more than half of <span class="ql-formula" data-value="a"></span> is <span class="ql-formula" data-value="\\frac{a}{2} + 15"></span>.</p><p>Since <span class="ql-formula" data-value="b"></span> is equal to this quantity:</p><p><span class="ql-formula" data-value="b = \\frac{a}{2} + 15"></span></p>`,

    // Q11 (6a519cee4d554e04aa1bed56) - Grid-in 60
    '6a519cee4d554e04aa1bed56': `<p><strong>Correct Answer: 60</strong></p><p>First, calculate the total number of disposable cups used to reduce the inventory from 8,900 to 1,700:</p><p><span class="ql-formula" data-value="8,900 - 1,700 = 7,200\\text{ cups}"></span></p><p>Since 120 cups are used each day, divide the total cups used by 120:</p><p><span class="ql-formula" data-value="\\text{Number of days} = \\frac{7,200}{120} = 60\\text{ days}"></span></p>`,

    // Q12 (6a519d914d554e04aa1bed62) - Grid-in 16
    '6a519d914d554e04aa1bed62': `<p><strong>Correct Answer: 16</strong></p><p>Both points <span class="ql-formula" data-value="(9, 0)"></span> and <span class="ql-formula" data-value="(c, 0)"></span> lie on the <span class="ql-formula" data-value="x"></span>-axis. The distance between two points on the <span class="ql-formula" data-value="x"></span>-axis is given by <span class="ql-formula" data-value="|c - 9|"></span>.</p><p>We are given that the distance is 7 units and that <span class="ql-formula" data-value="c > 9"></span>:</p><p><span class="ql-formula" data-value="c - 9 = 7 \\implies c = 9 + 7 = 16"></span></p>`,

    // Q13 (6a519f4a4d554e04aa1bed8e) - Choice C
    '6a519f4a4d554e04aa1bed8e': `<p><strong>Correct Answer: C</strong></p><p>The inequality is <span class="ql-formula" data-value="y \\le -\\frac{1}{4}x + 7"></span>.</p><ul><li><strong>Boundary Line:</strong> The equation <span class="ql-formula" data-value="y = -\\frac{1}{4}x + 7"></span> has a <span class="ql-formula" data-value="y"></span>-intercept of 7 and a negative slope of <span class="ql-formula" data-value="-\\frac{1}{4}"></span> (sloping downward from left to right). Because the inequality includes <span class="ql-formula" data-value="\\le"></span>, the line must be solid.</li><li><strong>Shaded Region:</strong> The symbol <span class="ql-formula" data-value="\\le"></span> indicates that the region below or to the left of the line is shaded. Testing <span class="ql-formula" data-value="(0, 0)"></span> gives <span class="ql-formula" data-value="0 \\le 7"></span>, which is true, meaning the shaded region contains the origin.</li></ul><p>Graph C correctly shows a downward-sloping line with <span class="ql-formula" data-value="y"></span>-intercept 7 shaded below the line.</p>`,

    // Q14 (6a51a0204d554e04aa1beda6) - Choice A
    '6a51a0204d554e04aa1beda6': `<p><strong>Correct Answer: A</strong></p><p>Evaluate the exponential function <span class="ql-formula" data-value="q(x) = 28(2^x)"></span> at the given values of <span class="ql-formula" data-value="x"></span>:</p><ul><li>For <span class="ql-formula" data-value="x = -1"></span>: <span class="ql-formula" data-value="q(-1) = 28(2^{-1}) = 28 \\left(\\frac{1}{2}\\right) = 14"></span></li><li>For <span class="ql-formula" data-value="x = 0"></span>: <span class="ql-formula" data-value="q(0) = 28(2^0) = 28(1) = 28"></span></li><li>For <span class="ql-formula" data-value="x = 1"></span>: <span class="ql-formula" data-value="q(1) = 28(2^1) = 28(2) = 56"></span></li></ul><p>The table in Choice A lists these exact values: <span class="ql-formula" data-value="(-1, 14)"></span>, <span class="ql-formula" data-value="(0, 28)"></span>, and <span class="ql-formula" data-value="(1, 56)"></span>.</p>`,

    // Q15 (6a51a2be4d554e04aa1bedd4) - Choice B
    '6a51a2be4d554e04aa1bedd4': `<p><strong>Correct Answer: B</strong></p><p>Simplify both sides of the given equation:</p><p><span class="ql-formula" data-value="3x - 13 = 8x - 5"></span></p><p>Subtract <span class="ql-formula" data-value="3x"></span> from both sides:</p><p><span class="ql-formula" data-value="-13 = 5x - 5"></span></p><p>Add 5 to both sides:</p><p><span class="ql-formula" data-value="5x = -8 \\implies x = -\\frac{8}{5}"></span></p><p>Now evaluate the requested expression <span class="ql-formula" data-value="x - 9"></span>:</p><p><span class="ql-formula" data-value="x - 9 = -\\frac{8}{5} - 9 = -\\frac{8}{5} - \\frac{45}{5} = -\\frac{53}{5}"></span></p>`,

    // Q16 (6a51a94f4d554e04aa1bedf8) - Choice A
    '6a51a94f4d554e04aa1bedf8': `<p><strong>Correct Answer: A</strong></p><p>The sample estimate for the percentage of inaccurate scales is 7%, with a margin of error of 2.8%. The plausible range of percentages for the population is:</p><p><span class="ql-formula" data-value="7\\% - 2.8\\% = 4.2\\%"></span> to <span class="ql-formula" data-value="7\\% + 2.8\\% = 9.8\\%"></span></p><p>Multiply these percentages by the total population size of 8,000 scales:</p><ul><li>Lower bound: <span class="ql-formula" data-value="0.042 \\times 8,000 = 336"></span></li><li>Upper bound: <span class="ql-formula" data-value="0.098 \\times 8,000 = 784"></span></li></ul><p>Therefore, it is plausible that between 336 and 784 scales in the population are inaccurate.</p>`,

    // Q17 (6a51acfb4d554e04aa1bee59) - Choice C
    '6a51acfb4d554e04aa1bee59': `<p><strong>Correct Answer: C</strong></p><p>The student needs at least 120 credit hours and has completed 42 credit hours. Subtract the completed credit hours from the total required:</p><p><span class="ql-formula" data-value="120 - 42 = 78\\text{ credit hours}"></span></p><p>Therefore, the minimum number of additional credit hours required is 78.</p>`,

    // Q18 (6a51ad784d554e04aa1bee5d) - Choice D
    '6a51ad784d554e04aa1bee5d': `<p><strong>Correct Answer: D</strong></p><p>The solution to a system of equations graphed in the <span class="ql-formula" data-value="xy"></span>-plane corresponds to any point where the graphs intersect.</p><p>Examining the intersection point of the parabola and the line on the grid, the two curves intersect at <span class="ql-formula" data-value="x = 6"></span> and <span class="ql-formula" data-value="y = 7"></span>.</p><p>Thus, <span class="ql-formula" data-value="(6, 7)"></span> is a solution to the system.</p>`,

    // Q19 (6a51ae0c4d554e04aa1bee67) - Choice D
    '6a51ae0c4d554e04aa1bee67': `<p><strong>Correct Answer: D</strong></p><p>There are 60 seconds in 1 minute. To convert speed from feet per second to feet per minute, multiply by 60:</p><p><span class="ql-formula" data-value="48 \\frac{\\text{feet}}{\\text{second}} \\times 60 \\frac{\\text{seconds}}{\\text{minute}} = 2,880\\text{ feet per minute}"></span></p>`,

    // Q20 (6a51ae874d554e04aa1bee71) - Choice A
    '6a51ae874d554e04aa1bee71': `<p><strong>Correct Answer: A</strong></p><p>From the bar graph:</p><ul><li>Number of students in hockey: 40</li><li>Number of students in volleyball: 30</li></ul><p>Subtract to find how many more students are in hockey than volleyball:</p><p><span class="ql-formula" data-value="40 - 30 = 10\\text{ students}"></span></p>`,

    // Q21 (6a51af064d554e04aa1bee77) - Choice D
    '6a51af064d554e04aa1bee77': `<p><strong>Correct Answer: D</strong></p><p>The <span class="ql-formula" data-value="x"></span>-intercepts of a parabola occur where <span class="ql-formula" data-value="y = 0"></span>. Factoring the quadratic displays the <span class="ql-formula" data-value="x"></span>-intercepts as constants:</p><p><span class="ql-formula" data-value="y = 5(x^2 - 8x + 7) = 5(x - 1)(x - 7)"></span></p><p>In the factored form <span class="ql-formula" data-value="y = 5(x - 1)(x - 7)"></span>, the constants 1 and 7 represent the <span class="ql-formula" data-value="x"></span>-intercepts <span class="ql-formula" data-value="(1, 0)"></span> and <span class="ql-formula" data-value="(7, 0)"></span>.</p>`,

    // Q22 (6a72aa91fb6980734c71b5e4) - Choice A
    '6a72aa91fb6980734c71b5e4': `<p><strong>Correct Answer: A</strong></p><p>The recorded values of pinching force <span class="ql-formula" data-value="c"></span> satisfy <span class="ql-formula" data-value="86.2 \\le c \\le 121.4"></span>.</p><p>Find the midpoint (center) of this range:</p><p><span class="ql-formula" data-value="\\text{Midpoint} = \\frac{86.2 + 121.4}{2} = \\frac{207.6}{2} = 103.8"></span></p><p>Find the half-range (distance from midpoint to either endpoint):</p><p><span class="ql-formula" data-value="\\text{Distance} = \\frac{121.4 - 86.2}{2} = \\frac{35.2}{2} = 17.6"></span></p><p>The absolute value inequality describing all points within distance 17.6 of the center 103.8 is:</p><p><span class="ql-formula" data-value="|c - 103.8| \\le 17.6"></span></p>`
};

async function run() {
    console.log('🚀 Uploading explanations for March 2026 US 1 Module 1 (22 questions)...\n');

    let count = 0;
    for (const [id, exp] of Object.entries(explanationsM1)) {
        count++;
        process.stdout.write(`Updating M1 Q${count} (${id})... `);
        const res = await updateQuestionExplanation(id, exp);
        if (res.message === 'success') {
            console.log('✅ Success');
        } else {
            console.log('❌ Result:', res);
        }
    }

    console.log(`\n🎉 Finished Module 1 explanations (${count} questions updated).`);
}

run().catch(console.error);
