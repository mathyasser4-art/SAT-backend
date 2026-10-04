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
    // Q1 (6a4c4f638a8c6f71bf226144) - Choice A
    '6a4c4f638a8c6f71bf226144': `<p><strong>Correct Answer: A</strong></p><p>To find the equivalent expression, apply the distributive property by multiplying each term inside the parentheses by <span class="ql-formula" data-value="13"></span>:</p><p><span class="ql-formula" data-value="13(x^2 - 7) = 13 \\cdot x^2 - 13 \\cdot 7 = 13x^2 - 91"></span></p><p>Therefore, the expression is equivalent to <span class="ql-formula" data-value="13x^2 - 91"></span>.</p>`,

    // Q2 (6a4c506c8a8c6f71bf226152) - Choice C
    '6a4c506c8a8c6f71bf226152': `<p><strong>Correct Answer: C</strong></p><p>The probability of selecting a participant with an average of more than 120 minutes of REM sleep per night is the number of participants who met this criterion divided by the total number of participants in the study:</p><p><span class="ql-formula" data-value="P = \\frac{\\text{favorable outcomes}}{\\text{total outcomes}} = \\frac{53}{59}"></span></p><p>Thus, the correct probability is <span class="ql-formula" data-value="\\frac{53}{59}"></span>.</p>`,

    // Q3 (6a4c526c8a8c6f71bf22615f) - Grid-in 14
    '6a4c526c8a8c6f71bf22615f': `<p><strong>Correct Answer: 14</strong></p><p>Locate the row in the table where the air temperature is <span class="ql-formula" data-value="26^\\circ\\text{F}"></span>. Then, look at the column corresponding to a wind speed of 15 mph. The value in this cell is <span class="ql-formula" data-value="14^\\circ\\text{F}"></span>.</p><p>Therefore, the wind chill temperature is 14.</p>`,

    // Q4 (6a4d66e78a8c6f71bf2261e2) - Choice D
    '6a4d66e78a8c6f71bf2261e2': `<p><strong>Correct Answer: D</strong></p><p>The team earns 12 dollars for each coupon book sold. If the team sells <span class="ql-formula" data-value="n"></span> coupon books, the total earnings are represented by <span class="ql-formula" data-value="12n"></span> dollars.</p><p>The goal is to earn <em>at least</em> 1,320 dollars, which means the total earnings must be greater than or equal to 1,320 dollars:</p><p><span class="ql-formula" data-value="12n \\ge 1,320"></span></p><p>Therefore, Choice D correctly describes all possible values of <span class="ql-formula" data-value="n"></span>.</p>`,

    // Q5 (6a4d9d388a8c6f71bf22621d) - Choice A
    '6a4d9d388a8c6f71bf22621d': `<p><strong>Correct Answer: A</strong></p><p>Substitute <span class="ql-formula" data-value="d = 12"></span> into the given equation:</p><p><span class="ql-formula" data-value="2.5c + 5(12) = 60"></span></p><p><span class="ql-formula" data-value="2.5c + 60 = 60"></span></p><p>Subtract 60 from both sides:</p><p><span class="ql-formula" data-value="2.5c = 0"></span></p><p><span class="ql-formula" data-value="c = 0"></span></p><p>Thus, the business can care for 0 cats during this week.</p>`,

    // Q6 (6a4d9e788a8c6f71bf22622d) - Choice C
    '6a4d9e788a8c6f71bf22622d': `<p><strong>Correct Answer: C</strong></p><p>For any real number <span class="ql-formula" data-value="x"></span>, the squared term <span class="ql-formula" data-value="(3x - 7)^2 \\ge 0"></span>. Multiplying by <span class="ql-formula" data-value="-1"></span> gives:</p><p><span class="ql-formula" data-value="-(3x - 7)^2 \\le 0"></span></p><p>Therefore, the left-hand side of the equation has a maximum possible value of 0 (which occurs when <span class="ql-formula" data-value="x = \\frac{7}{3}"></span>).</p><p>For the equation <span class="ql-formula" data-value="-(3x - 7)^2 = p + 17"></span> to have <strong>no real solution</strong>, the right-hand side must be strictly greater than this maximum value:</p><p><span class="ql-formula" data-value="p + 17 > 0 \\implies p > -17"></span></p><p>Since <span class="ql-formula" data-value="p"></span> is an integer, the least possible integer strictly greater than <span class="ql-formula" data-value="-17"></span> is <span class="ql-formula" data-value="-16"></span>.</p>`,

    // Q7 (6a4dc0448a8c6f71bf226290) - Choice C
    '6a4dc0448a8c6f71bf226290': `<p><strong>Correct Answer: C</strong></p><p>A dilation is a geometric transformation that preserves angle measures while scaling side lengths proportionally. Because triangle <span class="ql-formula" data-value="XYZ"></span> is a dilation of triangle <span class="ql-formula" data-value="ABC"></span>, the two triangles are similar (<span class="ql-formula" data-value="\\triangle ABC \\sim \\triangle XYZ"></span>).</p><p>Corresponding angles in similar triangles are congruent. Since angle <span class="ql-formula" data-value="X"></span> corresponds to angle <span class="ql-formula" data-value="A"></span>, and the measure of angle <span class="ql-formula" data-value="A"></span> is <span class="ql-formula" data-value="60^\\circ"></span>, the measure of angle <span class="ql-formula" data-value="X"></span> must also be <span class="ql-formula" data-value="60^\\circ"></span>.</p>`,

    // Q8 (6a50be684d554e04aa1beb79) - Choice C
    '6a50be684d554e04aa1beb79': `<p><strong>Correct Answer: C</strong></p><p>The area of a triangle is given by the formula:</p><p><span class="ql-formula" data-value="\\text{Area} = \\frac{1}{2} \\cdot b \\cdot h"></span></p><p>We are given that the area is 220 square centimeters and the base <span class="ql-formula" data-value="b = 10\\text{ cm}"></span>. Substituting these values gives:</p><p><span class="ql-formula" data-value="220 = \\frac{1}{2} (10) h"></span></p><p><span class="ql-formula" data-value="220 = 5h"></span></p><p>Divide both sides by 5:</p><p><span class="ql-formula" data-value="h = \\frac{220}{5} = 44\\text{ cm}"></span></p>`,

    // Q9 (6a50c0a84d554e04aa1beb95) - Choice B
    '6a50c0a84d554e04aa1beb95': `<p><strong>Correct Answer: B</strong></p><p>In a right triangle, the tangent of an acute angle is defined as the ratio of the length of the opposite leg to the length of the adjacent leg:</p><p><span class="ql-formula" data-value="\\tan(x) = \\frac{\\text{Opposite}}{\\text{Adjacent}}"></span></p><p>In the given right triangle, the leg opposite angle <span class="ql-formula" data-value="x"></span> has length 40, and the leg adjacent to angle <span class="ql-formula" data-value="x"></span> has length 39. Therefore:</p><p><span class="ql-formula" data-value="\\tan(x) = \\frac{40}{39}"></span></p><p>We are given that <span class="ql-formula" data-value="\\tan(x) = \\frac{c}{39}"></span>. Comparing the two expressions gives <span class="ql-formula" data-value="c = 40"></span>.</p>`,

    // Q10 (6a50c2234d554e04aa1beba1) - Choice C
    '6a50c2234d554e04aa1beba1': `<p><strong>Correct Answer: C</strong></p><p>An <span class="ql-formula" data-value="x"></span>-intercept of the graph of <span class="ql-formula" data-value="y = f(x)"></span> is a point where the graph crosses or touches the <span class="ql-formula" data-value="x"></span>-axis, meaning <span class="ql-formula" data-value="y = 0"></span>.</p><p>Since <span class="ql-formula" data-value="(-5, 0)"></span> is an <span class="ql-formula" data-value="x"></span>-intercept, when <span class="ql-formula" data-value="x = -5"></span>, the value of the function is <span class="ql-formula" data-value="f(-5) = 0"></span>. Thus, Choice C must be true.</p>`,

    // Q11 (6a50c39f4d554e04aa1beba7) - Grid-in 10 or 16
    '6a50c39f4d554e04aa1beba7': `<p><strong>Correct Answer: 10 (or 16)</strong></p><p>Set each factor equal to zero using the zero-product property:</p><p><span class="ql-formula" data-value="x - 16 = 0 \\implies x = 16"></span></p><p><span class="ql-formula" data-value="x - 10 = 0 \\implies x = 10"></span></p><p><span class="ql-formula" data-value="x + 7 = 0 \\implies x = -7"></span></p><p><span class="ql-formula" data-value="x + 17 = 0 \\implies x = -17"></span></p><p>The question asks for a positive solution. The positive solutions are 10 and 16. Entering either 10 or 16 is correct.</p>`,

    // Q12 (6a50c6414d554e04aa1bebb9) - Grid-in 2
    '6a50c6414d554e04aa1bebb9': `<p><strong>Correct Answer: 2</strong></p><p>Substitute the coordinates of the point <span class="ql-formula" data-value="(12, c)"></span> into the circle's equation:</p><p><span class="ql-formula" data-value="(12 - 6)^2 + (c - 2)^2 = 36"></span></p><p><span class="ql-formula" data-value="6^2 + (c - 2)^2 = 36"></span></p><p><span class="ql-formula" data-value="36 + (c - 2)^2 = 36"></span></p><p>Subtract 36 from both sides:</p><p><span class="ql-formula" data-value="(c - 2)^2 = 0 \\implies c - 2 = 0 \\implies c = 2"></span></p>`,

    // Q13 (6a50c7b74d554e04aa1bebd5) - Grid-in 5500
    '6a50c7b74d554e04aa1bebd5': `<p><strong>Correct Answer: 5500</strong></p><p>We are given that 1 meter is equal to 10 decimeters. To convert 550 meters to decimeters, multiply by 10:</p><p><span class="ql-formula" data-value="550 \\text{ meters} \\times 10 \\frac{\\text{decimeters}}{\\text{meter}} = 5,500\\text{ decimeters}"></span></p>`,

    // Q14 (6a50c89d4d554e04aa1bebdb) - Grid-in 6/5 or 1.2
    '6a50c89d4d554e04aa1bebdb': `<p><strong>Correct Answer: 6/5 (or 1.2)</strong></p><p>Let <span class="ql-formula" data-value="u = x - 4"></span>. Substituting <span class="ql-formula" data-value="u"></span> into the equation gives:</p><p><span class="ql-formula" data-value="6u = u + 6"></span></p><p>Subtract <span class="ql-formula" data-value="u"></span> from both sides:</p><p><span class="ql-formula" data-value="5u = 6"></span></p><p><span class="ql-formula" data-value="u = \\frac{6}{5} = 1.2"></span></p><p>Since <span class="ql-formula" data-value="u = x - 4"></span>, the value of <span class="ql-formula" data-value="x - 4"></span> is <span class="ql-formula" data-value="\\frac{6}{5}"></span> (or 1.2).</p>`,

    // Q15 (6a50c9794d554e04aa1bebe1) - Choice D
    '6a50c9794d554e04aa1bebe1': `<p><strong>Correct Answer: D</strong></p><p>We are given the system of equations:</p><p>(1) <span class="ql-formula" data-value="\\frac{5}{4}x + 2y = 17"></span></p><p>(2) <span class="ql-formula" data-value="\\frac{3}{4}x + 2y = 15"></span></p><p>Subtract equation (2) from equation (1) to eliminate <span class="ql-formula" data-value="2y"></span>:</p><p><span class="ql-formula" data-value="\\left(\\frac{5}{4} - \\frac{3}{4}\\right)x = 17 - 15 \\implies \\frac{2}{4}x = 2 \\implies \\frac{1}{2}x = 2 \\implies x = 4"></span></p><p>Substitute <span class="ql-formula" data-value="x = 4"></span> into equation (2):</p><p><span class="ql-formula" data-value="\\frac{3}{4}(4) + 2y = 15 \\implies 3 + 2y = 15 \\implies 2y = 12 \\implies y = 6"></span></p><p>Now evaluate the requested expression <span class="ql-formula" data-value="\\frac{11}{4}x + 6y"></span>:</p><p><span class="ql-formula" data-value="\\frac{11}{4}(4) + 6(6) = 11 + 36 = 47"></span></p>`,

    // Q16 (6a50cbd34d554e04aa1bebe7) - Choice B
    '6a50cbd34d554e04aa1bebe7': `<p><strong>Correct Answer: B</strong></p><p>Substitute <span class="ql-formula" data-value="x = 3"></span> into the definition of <span class="ql-formula" data-value="h(x)"></span>:</p><p><span class="ql-formula" data-value="h(3) = 14(2)^{-3} + 7"></span></p><p>Since <span class="ql-formula" data-value="2^{-3} = \\frac{1}{2^3} = \\frac{1}{8}"></span>:</p><p><span class="ql-formula" data-value="h(3) = 14 \\cdot \\frac{1}{8} + 7 = \\frac{14}{8} + 7 = \\frac{7}{4} + \\frac{28}{4} = \\frac{35}{4}"></span></p>`,

    // Q17 (6a50cdd34d554e04aa1bebed) - Grid-in 28/3
    '6a50cdd34d554e04aa1bebed': `<p><strong>Correct Answer: 28/3</strong></p><p>First, find the slope of the line passing through <span class="ql-formula" data-value="(1, 8)"></span> and <span class="ql-formula" data-value="(7, 0)"></span>:</p><p><span class="ql-formula" data-value="m = \\frac{0 - 8}{7 - 1} = \\frac{-8}{6} = -\\frac{4}{3}"></span></p><p>Using the point-slope form with <span class="ql-formula" data-value="(7, 0)"></span>:</p><p><span class="ql-formula" data-value="y - 0 = -\\frac{4}{3}(x - 7) \\implies y = -\\frac{4}{3}x + \\frac{28}{3"></span></p><p>The line crosses the <span class="ql-formula" data-value="y"></span>-axis at <span class="ql-formula" data-value="(0, b)"></span>, which is the <span class="ql-formula" data-value="y"></span>-intercept. Setting <span class="ql-formula" data-value="x = 0"></span> gives <span class="ql-formula" data-value="b = \\frac{28}{3}"></span>.</p>`,

    // Q18 (6a50cf0a4d554e04aa1bebf3) - Grid-in -6
    '6a50cf0a4d554e04aa1bebf3': `<p><strong>Correct Answer: -6</strong></p><p>Calculate the slope <span class="ql-formula" data-value="m"></span> of the linear relationship using the points <span class="ql-formula" data-value="(0, 31)"></span> and <span class="ql-formula" data-value="(2, 43)"></span>:</p><p><span class="ql-formula" data-value="m = \\frac{43 - 31}{2 - 0} = \\frac{12}{2} = 6"></span></p><p>In slope-intercept form, the line is <span class="ql-formula" data-value="y = 6x + 31"></span>.</p><p>Rearranging this into standard form <span class="ql-formula" data-value="Ax + By = C"></span>:</p><p><span class="ql-formula" data-value="-6x + y = 31"></span></p><p>Here, <span class="ql-formula" data-value="A = -6"></span> and <span class="ql-formula" data-value="B = 1"></span>, so:</p><p><span class="ql-formula" data-value="\\frac{A}{B} = \\frac{-6}{1} = -6"></span></p><p>(Alternatively, rearranging <span class="ql-formula" data-value="Ax + By = C \\implies y = -\\frac{A}{B}x + \\frac{C}{B}"></span> shows that the slope is <span class="ql-formula" data-value="m = -\\frac{A}{B}"></span>, so <span class="ql-formula" data-value="\\frac{A}{B} = -m = -6"></span>.)</p>`,

    // Q19 (6a50d0184d554e04aa1bebf9) - Choice A
    '6a50d0184d554e04aa1bebf9': `<p><strong>Correct Answer: A</strong></p><p>Notice that multiplying the first equation <span class="ql-formula" data-value="5x + 8y = 9"></span> by 3 yields:</p><p><span class="ql-formula" data-value="3(5x + 8y) = 3(9) \\implies 15x + 24y = 27"></span></p><p>This is identical to the second equation, meaning both equations represent the exact same line and have infinitely many shared solutions.</p><p>For any real number <span class="ql-formula" data-value="r"></span>, let <span class="ql-formula" data-value="x = r"></span>. Substitute <span class="ql-formula" data-value="r"></span> into <span class="ql-formula" data-value="5x + 8y = 9"></span> and solve for <span class="ql-formula" data-value="y"></span>:</p><p><span class="ql-formula" data-value="5r + 8y = 9 \\implies 8y = -5r + 9 \\implies y = -\\frac{5r}{8} + \\frac{9}{8}"></span></p><p>Thus, the point <span class="ql-formula" data-value="\\left(r, -\\frac{5r}{8} + \\frac{9}{8}\\right)"></span> lies on the graph of each equation.</p>`,

    // Q20 (6a50d0b44d554e04aa1bebff) - Choice C
    '6a50d0b44d554e04aa1bebff': `<p><strong>Correct Answer: C</strong></p><p>To find the length of fencing used, calculate 60% of the total 800 feet of fencing:</p><p><span class="ql-formula" data-value="0.60 \\times 800 = 480\\text{ feet}"></span></p><p>Therefore, Julia used 480 feet of fencing.</p>`,

    // Q21 (6a50d15c4d554e04aa1bec0b) - Choice B
    '6a50d15c4d554e04aa1bec0b': `<p><strong>Correct Answer: B</strong></p><p>The mean of a data set is calculated by dividing the sum of all values by the number of values:</p><p><span class="ql-formula" data-value="\\text{Mean} = \\frac{1 + 4 + 7 + 10 + 33}{5} = \\frac{55}{5} = 11"></span></p><p>Thus, the mean is 11.</p>`,

    // Q22 (6a50d2724d554e04aa1bec17) - Choice A
    '6a50d2724d554e04aa1bec17': `<p><strong>Correct Answer: A</strong></p><p>The <span class="ql-formula" data-value="y"></span>-intercept of a graph occurs where <span class="ql-formula" data-value="x = 0"></span>. Substitute <span class="ql-formula" data-value="x = 0"></span> into the given equation:</p><p><span class="ql-formula" data-value="y = 16^{0 + 3} = 16^3 = 4,096"></span></p><p>Therefore, the coordinates of the <span class="ql-formula" data-value="y"></span>-intercept are <span class="ql-formula" data-value="(0, 4096)"></span>.</p>`
};

async function run() {
    console.log('🚀 Uploading explanations for May 2026 INT 1 Module 1 (22 questions)...\n');

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
