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

const explanationsM2 = {
    // Q1 (6a51fb394d554e04aa1bf06e) - Grid-in -6
    '6a51fb394d554e04aa1bf06e': `<p><strong>Correct Answer: -6</strong></p><p>Find the slope <span class="ql-formula" data-value="m"></span> of the linear relationship using the points <span class="ql-formula" data-value="(0, 31)"></span> and <span class="ql-formula" data-value="(2, 43)"></span> from the table:</p><p><span class="ql-formula" data-value="m = \\frac{43 - 31}{2 - 0} = \\frac{12}{2} = 6"></span></p><p>The linear equation can be written in slope-intercept form as <span class="ql-formula" data-value="y = 6x + 31"></span>. Rearranging this into standard form <span class="ql-formula" data-value="Ax + By = C"></span> gives:</p><p><span class="ql-formula" data-value="-6x + y = 31"></span></p><p>Here, <span class="ql-formula" data-value="A = -6"></span> and <span class="ql-formula" data-value="B = 1"></span>. Therefore:</p><p><span class="ql-formula" data-value="\\frac{A}{B} = \\frac{-6}{1} = -6"></span></p>`,

    // Q2 (6a51fc3b4d554e04aa1bf07a) - Choice B
    '6a51fc3b4d554e04aa1bf07a': `<p><strong>Correct Answer: B</strong></p><p>Set the function <span class="ql-formula" data-value="g(x)"></span> equal to <span class="ql-formula" data-value="-216"></span>:</p><p><span class="ql-formula" data-value="-18 - 9x = -216"></span></p><p>Add 18 to both sides:</p><p><span class="ql-formula" data-value="-9x = -216 + 18"></span></p><p><span class="ql-formula" data-value="-9x = -198"></span></p><p>Divide both sides by <span class="ql-formula" data-value="-9"></span>:</p><p><span class="ql-formula" data-value="x = \\frac{-198}{-9} = 22"></span></p>`,

    // Q3 (6a51fca74d554e04aa1bf080) - Choice A
    '6a51fca74d554e04aa1bf080': `<p><strong>Correct Answer: A</strong></p><p>The time elapsed between 1660 and 1760 is <span class="ql-formula" data-value="1760 - 1660 = 100"></span> years. Since the population doubled every 25 years, the number of doubling periods that occurred is:</p><p><span class="ql-formula" data-value="n = \\frac{100}{25} = 4"></span></p><p>Let <span class="ql-formula" data-value="P_0"></span> be the population in 1660. The population in 1760 is given by:</p><p><span class="ql-formula" data-value="P(1760) = P_0 \\cdot 2^4 = 16 P_0"></span></p><p>We are given that <span class="ql-formula" data-value="P(1760) = 208,000"></span>. Solving for <span class="ql-formula" data-value="P_0"></span>:</p><p><span class="ql-formula" data-value="P_0 = \\frac{208,000}{16} = 13,000"></span></p>`,

    // Q4 (6a51fd4e4d554e04aa1bf086) - Choice B
    '6a51fd4e4d554e04aa1bf086': `<p><strong>Correct Answer: B</strong></p><p>To solve the linear equation, add <span class="ql-formula" data-value="7x"></span> to both sides:</p><p><span class="ql-formula" data-value="14x - 19 = 19"></span></p><p>Add 19 to both sides:</p><p><span class="ql-formula" data-value="14x = 38"></span></p><p>Divide both sides by 14:</p><p><span class="ql-formula" data-value="x = \\frac{38}{14} = \\frac{19}{7}"></span></p><p>Since this yields a single unique numerical solution, the equation has <strong>exactly one</strong> solution.</p>`,

    // Q5 (6a51ff124d554e04aa1bf0ba) - Choice D
    '6a51ff124d554e04aa1bf0ba': `<p><strong>Correct Answer: D</strong></p><p>We are given that the point <span class="ql-formula" data-value="(x, 54)"></span> is a solution to the system. First, checking the inequality <span class="ql-formula" data-value="y > 17"></span> with <span class="ql-formula" data-value="y = 54"></span>:</p><p><span class="ql-formula" data-value="54 > 17"></span> (which is true).</p><p>Next, substitute <span class="ql-formula" data-value="y = 54"></span> into the second inequality <span class="ql-formula" data-value="4x + y < 21"></span>:</p><p><span class="ql-formula" data-value="4x + 54 < 21"></span></p><p>Subtract 54 from both sides:</p><p><span class="ql-formula" data-value="4x < 21 - 54 \\implies 4x < -33"></span></p><p>Divide by 4:</p><p><span class="ql-formula" data-value="x < -8.25"></span></p><p>Among the given choices (<span class="ql-formula" data-value="9, 5, -5, -9"></span>), only <span class="ql-formula" data-value="-9"></span> satisfies <span class="ql-formula" data-value="x < -8.25"></span>.</p>`,

    // Q6 (6a51ffe04d554e04aa1bf0c6) - Choice D
    '6a51ffe04d554e04aa1bf0c6': `<p><strong>Correct Answer: D</strong></p><p>The function <span class="ql-formula" data-value="f(x)"></span> is linear and passes through the points <span class="ql-formula" data-value="(4, 190)"></span> and <span class="ql-formula" data-value="(10, 670)"></span>. First, calculate the slope <span class="ql-formula" data-value="m"></span>:</p><p><span class="ql-formula" data-value="m = \\frac{670 - 190}{10 - 4} = \\frac{480}{6} = 80"></span></p><p>Using the point-slope form with <span class="ql-formula" data-value="(4, 190)"></span>:</p><p><span class="ql-formula" data-value="f(x) - 190 = 80(x - 4)"></span></p><p><span class="ql-formula" data-value="f(x) - 190 = 80x - 320"></span></p><p>Add 190 to both sides:</p><p><span class="ql-formula" data-value="f(x) = 80x - 130"></span></p>`,

    // Q7 (6a5200524d554e04aa1bf0d2) - Choice D
    '6a5200524d554e04aa1bf0d2': `<p><strong>Correct Answer: D</strong></p><p>A quadratic equation <span class="ql-formula" data-value="ax^2 + bx + c = 0"></span> has no real solutions when its discriminant is strictly negative: <span class="ql-formula" data-value="D = b^2 - 4ac < 0"></span>.</p><p>Evaluate the discriminant for Choice D, <span class="ql-formula" data-value="-2x^2 + 2x - 2 = 0"></span>, where <span class="ql-formula" data-value="a = -2"></span>, <span class="ql-formula" data-value="b = 2"></span>, and <span class="ql-formula" data-value="c = -2"></span>:</p><p><span class="ql-formula" data-value="D = 2^2 - 4(-2)(-2) = 4 - 16 = -12"></span></p><p>Since <span class="ql-formula" data-value="D = -12 < 0"></span>, this quadratic equation has no real solutions.</p>`,

    // Q8 (6a5201b94d554e04aa1bf0de) - Choice C
    '6a5201b94d554e04aa1bf0de': `<p><strong>Correct Answer: C</strong></p><p>The circumference of the circular base is given by <span class="ql-formula" data-value="C = 2\\pi r = 6\\pi"></span>. Dividing both sides by <span class="ql-formula" data-value="2\\pi"></span> gives the radius:</p><p><span class="ql-formula" data-value="r = \\frac{6\\pi}{2\\pi} = 3\\text{ meters}"></span></p><p>The volume of a right circular cylinder is given by <span class="ql-formula" data-value="V = \\pi r^2 h"></span>. Substituting <span class="ql-formula" data-value="r = 3"></span> and <span class="ql-formula" data-value="h = 19"></span> gives:</p><p><span class="ql-formula" data-value="V = \\pi (3^2)(19) = \\pi (9)(19) = 171\\pi\\text{ cubic meters}"></span></p>`,

    // Q9 (6a5202d34d554e04aa1bf0ea) - Grid-in 380
    '6a5202d34d554e04aa1bf0ea': `<p><strong>Correct Answer: 380</strong></p><p>Let <span class="ql-formula" data-value="a"></span> be the number of adult tickets sold and <span class="ql-formula" data-value="c"></span> be the number of child tickets sold. The total revenue equation is:</p><p><span class="ql-formula" data-value="10a + 5c = 4,100"></span></p><p>We are given that <span class="ql-formula" data-value="a = 220"></span> adult tickets were sold. Substitute <span class="ql-formula" data-value="a = 220"></span> into the equation:</p><p><span class="ql-formula" data-value="10(220) + 5c = 4,100"></span></p><p><span class="ql-formula" data-value="2,200 + 5c = 4,100"></span></p><p>Subtract 2,200 from both sides:</p><p><span class="ql-formula" data-value="5c = 1,900"></span></p><p>Divide by 5:</p><p><span class="ql-formula" data-value="c = \\frac{1,900}{5} = 380"></span></p><p>Thus, 380 child admission tickets were sold.</p>`,

    // Q10 (6a52f9b84d554e04aa1bf4ca) - Choice D
    '6a52f9b84d554e04aa1bf4ca': `<p><strong>Correct Answer: D</strong></p><p>From the first equation <span class="ql-formula" data-value="y - x = 32"></span>, express <span class="ql-formula" data-value="y"></span> in terms of <span class="ql-formula" data-value="x"></span>:</p><p><span class="ql-formula" data-value="y = x + 32"></span></p><p>Substitute this into the second equation <span class="ql-formula" data-value="y = x^2 - 30x"></span>:</p><p><span class="ql-formula" data-value="x + 32 = x^2 - 30x"></span></p><p>Rearrange into a standard quadratic equation:</p><p><span class="ql-formula" data-value="x^2 - 31x - 32 = 0"></span></p><p>Factor the quadratic equation:</p><p><span class="ql-formula" data-value="(x - 32)(x + 1) = 0"></span></p><p>Thus, the possible <span class="ql-formula" data-value="x"></span>-values are <span class="ql-formula" data-value="x = 32"></span> or <span class="ql-formula" data-value="x = -1"></span>.</p><p>Find the corresponding <span class="ql-formula" data-value="y"></span>-values using <span class="ql-formula" data-value="y = x + 32"></span>:</p><ul><li>If <span class="ql-formula" data-value="x = 32"></span>, then <span class="ql-formula" data-value="y = 32 + 32 = 64"></span>.</li><li>If <span class="ql-formula" data-value="x = -1"></span>, then <span class="ql-formula" data-value="y = -1 + 32 = 31"></span>.</li></ul><p>Among the given choices, 64 is an option (Choice D).</p>`,

    // Q11 (6a52fa924d554e04aa1bf4d6) - Grid-in 72/5
    '6a52fa924d554e04aa1bf4d6': `<p><strong>Correct Answer: 72/5</strong></p><p>The given function is <span class="ql-formula" data-value="c(r) = \\frac{2}{5}(2\\pi r) = \\frac{4\\pi}{5} r"></span>.</p><p>Since this is a linear function with respect to <span class="ql-formula" data-value="r"></span>, the change in <span class="ql-formula" data-value="c(r)"></span>, denoted <span class="ql-formula" data-value="\\Delta c"></span>, when <span class="ql-formula" data-value="r"></span> increases by <span class="ql-formula" data-value="\\Delta r = 18"></span> is:</p><p><span class="ql-formula" data-value="\\Delta c = \\frac{4\\pi}{5} \\Delta r = \\frac{4\\pi}{5} (18) = \\frac{72\\pi}{5} = \\frac{72}{5} \\pi"></span></p><p>We are given that this increase equals <span class="ql-formula" data-value="k\\pi"></span>. Comparing the two gives <span class="ql-formula" data-value="k = \\frac{72}{5}"></span>.</p>`,

    // Q12 (6a52fb124d554e04aa1bf4dc) - Choice A
    '6a52fb124d554e04aa1bf4dc': `<p><strong>Correct Answer: A</strong></p><p>Substitute <span class="ql-formula" data-value="x = 10"></span> into <span class="ql-formula" data-value="f(x) = 25(1.40)^{\\frac{x}{6}}"></span>:</p><p><span class="ql-formula" data-value="f(10) = 25(1.40)^{\\frac{10}{6}} = 25(1.40)^{\\frac{5}{3}}"></span></p><p>Calculating the exponent:</p><p><span class="ql-formula" data-value="1.40^{\\frac{5}{3}} \\approx 1.7521"></span></p><p>Now multiply by 25:</p><p><span class="ql-formula" data-value="f(10) \\approx 25 \\times 1.7521 \\approx 43.80"></span></p><p>Comparing this value to the available options (40, 49, 80, 96):</p><p><span class="ql-formula" data-value="|43.80 - 40| = 3.80"></span> vs. <span class="ql-formula" data-value="|43.80 - 49| = 5.20"></span>.</p><p>The value closest to <span class="ql-formula" data-value="f(10)"></span> is 40.</p>`,

    // Q13 (6a52fce74d554e04aa1bf4e2) - Grid-in 55
    '6a52fce74d554e04aa1bf4e2': `<p><strong>Correct Answer: 55</strong></p><p>We are given <span class="ql-formula" data-value="k(s) = \\sqrt{s + 110}"></span> and <span class="ql-formula" data-value="k(53p) = p"></span>. Substitute <span class="ql-formula" data-value="s = 53p"></span> into the function:</p><p><span class="ql-formula" data-value="\\sqrt{53p + 110} = p"></span></p><p>Square both sides to eliminate the square root:</p><p><span class="ql-formula" data-value="53p + 110 = p^2"></span></p><p>Rearrange into standard quadratic form:</p><p><span class="ql-formula" data-value="p^2 - 53p - 110 = 0"></span></p><p>Factor the quadratic by finding two numbers whose product is <span class="ql-formula" data-value="-110"></span> and whose sum is <span class="ql-formula" data-value="-53"></span>. These numbers are <span class="ql-formula" data-value="-55"></span> and <span class="ql-formula" data-value="2"></span>:</p><p><span class="ql-formula" data-value="(p - 55)(p + 2) = 0"></span></p><p>Because the principal square root must be non-negative (<span class="ql-formula" data-value="p = \\sqrt{53p + 110} \\ge 0"></span>), <span class="ql-formula" data-value="p = -2"></span> is extraneous. Therefore, the only valid solution is <span class="ql-formula" data-value="p = 55"></span>.</p>`,

    // Q14 (6a52fed04d554e04aa1bf4e8) - Choice D
    '6a52fed04d554e04aa1bf4e8': `<p><strong>Correct Answer: D</strong></p><p>An increase of 158% every 5 weeks corresponds to a growth factor of:</p><p><span class="ql-formula" data-value="1 + \\frac{158}{100} = 1 + 1.58 = 2.58"></span></p><p>Because this increase occurs every 5-week period, the model has the form:</p><p><span class="ql-formula" data-value="M = M_0 (2.58)^{\\frac{t}{5}}"></span></p><p>At <span class="ql-formula" data-value="t = 15"></span> weeks, the number of 5-week periods elapsed is <span class="ql-formula" data-value="\\frac{15}{5} = 3"></span>, and the total mass is given as 627.7 grams:</p><p><span class="ql-formula" data-value="627.7 = M_0 (2.58)^3"></span></p><p>Calculate <span class="ql-formula" data-value="2.58^3 \\approx 17.1735"></span>:</p><p><span class="ql-formula" data-value="M_0 = \\frac{627.7}{17.1735} \\approx 36.55\\text{ grams}"></span></p><p>Thus, the equation that best represents this model is <span class="ql-formula" data-value="M = 36.55(2.58)^{\\frac{t}{5}}"></span>.</p>`,

    // Q15 (6a53003d4d554e04aa1bf4f4) - Choice A
    '6a53003d4d554e04aa1bf4f4': `<p><strong>Correct Answer: A</strong></p><p>Let <span class="ql-formula" data-value="V_0 = 100"></span> represent the baseline value at the end of 2012.</p><p>An increase of 178% from 2012 to 2013 multiplies the value by <span class="ql-formula" data-value="1 + 1.78 = 2.78"></span>:</p><p><span class="ql-formula" data-value="V_{2013} = 100 \\times 2.78 = 278"></span></p><p>A decrease of 21% from 2013 to 2014 multiplies the value by <span class="ql-formula" data-value="1 - 0.21 = 0.79"></span>:</p><p><span class="ql-formula" data-value="V_{2014} = 278 \\times 0.79 = 219.62"></span></p><p>The net percentage increase from the original value of 100 is:</p><p><span class="ql-formula" data-value="219.62 - 100 = 119.62\\%"></span></p>`,

    // Q16 (6a53023e4d554e04aa1bf500) - Grid-in 0.75 or 3/4
    '6a53023e4d554e04aa1bf500': `<p><strong>Correct Answer: 0.75 (or 3/4)</strong></p><p>Rewrite the radicals in exponential form:</p><p><span class="ql-formula" data-value="\\sqrt[3]{n^5} = n^{\\frac{5}{3}}"></span> and <span class="ql-formula" data-value="\\sqrt[3]{k^2} = k^{\\frac{2}{3}}"></span></p><p>We are given that <span class="ql-formula" data-value="n^{\\frac{5}{3}} = k^{\\frac{2}{3}}"></span>. Raise both sides to the power of <span class="ql-formula" data-value="\\frac{3}{2}"></span> to solve for <span class="ql-formula" data-value="k"></span>:</p><p><span class="ql-formula" data-value="k = \\left(n^{\\frac{5}{3}}\\right)^{\\frac{3}{2}} = n^{\\frac{5}{3} \\cdot \\frac{3}{2}} = n^{\\frac{5}{2}}"></span></p><p>We are also given that <span class="ql-formula" data-value="n^{2a+1} = k"></span>, which means:</p><p><span class="ql-formula" data-value="n^{2a+1} = n^{\\frac{5}{2}}"></span></p><p>Since the base <span class="ql-formula" data-value="n > 1"></span>, equate the exponents:</p><p><span class="ql-formula" data-value="2a + 1 = \\frac{5}{2} = 2.5"></span></p><p><span class="ql-formula" data-value="2a = 1.5 \\implies a = 0.75 = \\frac{3}{4}"></span></p>`,

    // Q17 (6a5303c24d554e04aa1bf50c) - Grid-in 28/17
    '6a5303c24d554e04aa1bf50c': `<p><strong>Correct Answer: 28/17</strong></p><p>In right triangle <span class="ql-formula" data-value="ABC"></span> with right angle at <span class="ql-formula" data-value="B"></span>, the hypotenuse is <span class="ql-formula" data-value="AC = 28"></span>. The problem states that <span class="ql-formula" data-value="AB"></span> is 11 less than <span class="ql-formula" data-value="AC"></span>:</p><p><span class="ql-formula" data-value="AB = 28 - 11 = 17"></span></p><p>Point <span class="ql-formula" data-value="D"></span> lies on <span class="ql-formula" data-value="AC"></span> such that <span class="ql-formula" data-value="BD \\perp AC"></span>. In the smaller right triangle <span class="ql-formula" data-value="BDC"></span> (with right angle at <span class="ql-formula" data-value="D"></span>), angle <span class="ql-formula" data-value="C"></span> is shared with right triangle <span class="ql-formula" data-value="ABC"></span>.</p><p>By angle-angle similarity, <span class="ql-formula" data-value="\\triangle BDC \\sim \\triangle ABC"></span>. Using the definition of <span class="ql-formula" data-value="\\sin(C)"></span>:</p><ul><li>In <span class="ql-formula" data-value="\\triangle BDC"></span>: <span class="ql-formula" data-value="\\sin(C) = \\frac{\\text{opposite}}{\\text{hypotenuse}} = \\frac{BD}{BC}"></span></li><li>In <span class="ql-formula" data-value="\\triangle ABC"></span>: <span class="ql-formula" data-value="\\sin(C) = \\frac{\\text{opposite}}{\\text{hypotenuse}} = \\frac{AB}{AC}"></span></li></ul><p>Therefore:</p><p><span class="ql-formula" data-value="\\frac{BD}{BC} = \\frac{AB}{AC}"></span></p><p>Taking the reciprocal of both sides gives:</p><p><span class="ql-formula" data-value="\\frac{BC}{BD} = \\frac{AC}{AB} = \\frac{28}{17}"></span></p>`,

    // Q18 (6a5304864d554e04aa1bf512) - Choice A
    '6a5304864d554e04aa1bf512': `<p><strong>Correct Answer: A</strong></p><p>To convert 280 square feet per hour into square meters per minute, apply unit conversion factors:</p><p>Since <span class="ql-formula" data-value="1\\text{ meter} = 3.28\\text{ feet}"></span>, <span class="ql-formula" data-value="1\\text{ square meter} = (3.28)^2 = 10.7584\\text{ square feet}"></span>.</p><p>Since <span class="ql-formula" data-value="1\\text{ hour} = 60\\text{ minutes}"></span>:</p><p><span class="ql-formula" data-value="\\text{Rate} = 280 \\frac{\\text{ft}^2}{\\text{hr}} \\times \\frac{1\\text{ m}^2}{10.7584\\text{ ft}^2} \\times \\frac{1\\text{ hr}}{60\\text{ min}} = \\frac{280}{10.7584 \\times 60} = \\frac{280}{645.504} \\approx 0.4338"></span></p><p>The value closest to this result is 0.43.</p>`,

    // Q19 (6a5305af4d554e04aa1bf51e) - Choice C
    '6a5305af4d554e04aa1bf51e': `<p><strong>Correct Answer: C</strong></p><p>In the function <span class="ql-formula" data-value="f(x) = 600(0.5)^{\\frac{x}{2}}"></span>, <span class="ql-formula" data-value="x"></span> represents the distance in millimeters below the surface of the material, and <span class="ql-formula" data-value="f(x)"></span> represents the predicted intensity in number of photons.</p><p>Therefore, the statement <span class="ql-formula" data-value="f(11) = 300"></span> means that when the distance below the surface is <span class="ql-formula" data-value="x = 11"></span> millimeters, the predicted beam intensity is 300 photons.</p>`,

    // Q20 (6a53065c4d554e04aa1bf524) - Choice A
    '6a53065c4d554e04aa1bf524': `<p><strong>Correct Answer: A</strong></p><p>The linear function passes through <span class="ql-formula" data-value="(0, 0)"></span> and <span class="ql-formula" data-value="(11, 5)"></span>. Calculate the slope <span class="ql-formula" data-value="m"></span>:</p><p><span class="ql-formula" data-value="m = \\frac{5 - 0}{11 - 0} = \\frac{5}{11}"></span></p><p>Because <span class="ql-formula" data-value="h(0) = 0"></span>, the <span class="ql-formula" data-value="y"></span>-intercept is 0. Thus, the equation defining <span class="ql-formula" data-value="h"></span> is:</p><p><span class="ql-formula" data-value="h(x) = \\frac{5}{11}x"></span></p>`,

    // Q21 (6a5306f74d554e04aa1bf530) - Choice A
    '6a5306f74d554e04aa1bf530': `<p><strong>Correct Answer: A</strong></p><p>Fencing along each edge of a rectangular garden represents the perimeter of the rectangle. The perimeter of a rectangle with length <span class="ql-formula" data-value="x"></span> and width <span class="ql-formula" data-value="y"></span> is:</p><p><span class="ql-formula" data-value="P = 2x + 2y"></span></p><p>We are given that the total length of fencing is 44 feet, so:</p><p><span class="ql-formula" data-value="2x + 2y = 44"></span></p>`,

    // Q22 (6a5307564d554e04aa1bf536) - Grid-in 9
    '6a5307564d554e04aa1bf536': `<p><strong>Correct Answer: 9</strong></p><p>Rearrange the given equation by moving terms to one side:</p><p><span class="ql-formula" data-value="121x^2 + 110x = 56"></span></p><p>Notice that <span class="ql-formula" data-value="(11x + 5)^2"></span> expands to:</p><p><span class="ql-formula" data-value="(11x + 5)^2 = (11x)^2 + 2(11x)(5) + 5^2 = 121x^2 + 110x + 25"></span></p><p>Add 25 to both sides of the equation <span class="ql-formula" data-value="121x^2 + 110x = 56"></span>:</p><p><span class="ql-formula" data-value="121x^2 + 110x + 25 = 56 + 25"></span></p><p><span class="ql-formula" data-value="(11x + 5)^2 = 81"></span></p><p>Take the square root of both sides. Since we are given that <span class="ql-formula" data-value="11x + 5 > 0"></span>:</p><p><span class="ql-formula" data-value="11x + 5 = \\sqrt{81} = 9"></span></p>`
};

async function run() {
    console.log('🚀 Uploading explanations for May 2026 INT 1 Module 2 (22 questions)...\n');

    let count = 0;
    for (const [id, exp] of Object.entries(explanationsM2)) {
        count++;
        process.stdout.write(`Updating M2 Q${count} (${id})... `);
        const res = await updateQuestionExplanation(id, exp);
        if (res.message === 'success') {
            console.log('✅ Success');
        } else {
            console.log('❌ Result:', res);
        }
    }

    console.log(`\n🎉 Finished Module 2 explanations (${count} questions updated).`);
}

run().catch(console.error);
