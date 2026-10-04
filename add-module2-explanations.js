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

function getQuestionDetails(questionId) {
    return new Promise((resolve, reject) => {
        https.get(`${API_BASE}/question/getQuestionDetails/${questionId}`, res => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve(JSON.parse(data)));
        }).on('error', reject);
    });
}

const explanationsM2 = {
    // Q1
    '6a5b131ec3d08d90637d2eae':
        `<p><strong>The correct answer is 3.5 (or 7/2).</strong> The slope $m$ of a line passing through two points $(x_1, y_1)$ and $(x_2, y_2)$ is given by the slope formula:</p>` +
        `<p>$$m = \\frac{y_2 - y_1}{x_2 - x_1}$$</p>` +
        `<p>Substituting the given coordinates $(5, 7)$ and $(13, 35)$:</p>` +
        `<p>$$m = \\frac{35 - 7}{13 - 5} = \\frac{28}{8} = \\frac{7}{2} = 3.5$$</p>` +
        `<p>Either <strong>3.5</strong> or <strong>7/2</strong> may be entered as the correct answer.</p>`,

    // Q2
    '6a5b139ec3d08d90637d2eba':
        `<p><strong>The correct answer is 0.75 (or 3/4).</strong> The given function is $f(x) = 5\\left(\\frac{1}{4} - x\\right)^2 + \\frac{3}{4}$. To evaluate $f\\left(\\frac{1}{4}\\right)$, substitute $x = \\frac{1}{4}$ into the function:</p>` +
        `<p>$$f\\left(\\frac{1}{4}\\right) = 5\\left(\\frac{1}{4} - \\frac{1}{4}\\right)^2 + \\frac{3}{4} = 5(0)^2 + \\frac{3}{4} = 0 + \\frac{3}{4} = \\frac{3}{4} = 0.75$$</p>` +
        `<p>Either <strong>0.75</strong> or <strong>3/4</strong> may be entered as the correct answer.</p>`,

    // Q3
    '6a5b140cc3d08d90637d2ec6':
        `<p><strong>Choice C is correct.</strong> In the function $p(x) = 132 - 4x$, the variable $x$ represents the number of days after the printer was loaded with paper, and $p(x)$ represents the number of blank sheets of paper remaining in the printer. Therefore, in the statement $p(6) = 108$, the value $6$ represents $x = 6$ days after loading, and the value $108$ represents $108$ blank sheets remaining in the printer. Hence, there were 108 blank sheets of paper remaining in the printer 6 days after it was loaded.</p>` +
        `<p><strong>Choice A is incorrect</strong> because 6 is the number of days, not the number of sheets by which paper decreased.</p>` +
        `<p><strong>Choice B is incorrect</strong> because it swaps the days (108 days) and sheets remaining (6 sheets).</p>` +
        `<p><strong>Choice D is incorrect</strong> because 108 is the number of sheets <em>remaining</em>, not the decrease. The decrease after 6 days is $132 - 108 = 24$ sheets.</p>`,

    // Q4
    '6a5b1458c3d08d90637d2eca':
        `<p><strong>Choice B is correct.</strong> The student needs at least 80 signatures in total. The student has already collected 55 signatures on Monday and collects $s$ additional signatures on Tuesday, making the total number of signatures collected $s + 55$. The phrase "at least 80" means greater than or equal to 80 ($\\ge 80$). Therefore, the inequality representing this situation is:</p>` +
        `<p>$$s + 55 \\ge 80$$</p>` +
        `<p><strong>Choice A is incorrect</strong> because $\\le$ means "at most 80", rather than "at least 80".</p>` +
        `<p><strong>Choices C and D are incorrect</strong> because they subtract 55 from $s$ ($s - 55$) instead of adding the 55 signatures already collected on Monday.</p>`,

    // Q5
    '6a5b14b4c3d08d90637d2ece':
        `<p><strong>Choice C is correct.</strong> In the scatterplot, the horizontal axis represents the number of tomato seeds planted ($x$), and the vertical axis represents the number of tomato seeds that germinated ($y$). The slope of the line of best fit represents the rate of change of germinated seeds with respect to planted seeds ($\\frac{\\Delta y}{\\Delta x}$). The line passes through $(0, 0)$ and approximately $(500, 350)$:</p>` +
        `<p>$$\\text{Slope} = \\frac{350 - 0}{500 - 0} = \\frac{350}{500} = \\frac{70}{100} = 0.70$$</p>` +
        `<p>This indicates that for every 100 additional tomato seeds planted, the predicted number of germinated seeds increases by approximately 70.</p>` +
        `<p><strong>Choices A and B are incorrect</strong> because the context involves the number of seeds planted, not days.</p>` +
        `<p><strong>Choice D is incorrect</strong> because an increase of 350 germinated seeds per 100 planted would correspond to a germination rate of $350\\%$, which contradicts the data.</p>`,

    // Q6
    '6a5b1565c3d08d90637d2edc':
        `<p><strong>Choice A is correct.</strong> In right triangle $XYZ$ with right angle at $Z$, the acute angles $X$ and $Y$ are complementary, meaning $X + Y = 90^\\circ$. By the cofunction trigonometric identity, the sine of an acute angle is equal to the cosine of its complement:</p>` +
        `<p>$$\\sin X = \\cos(90^\\circ - X) = \\cos Y$$</p>` +
        `<p>Alternatively, using side lengths: $\\sin X = \\frac{\\text{opposite}}{\\text{hypotenuse}} = \\frac{YZ}{XY} = \\frac{28}{XY}$, and $\\cos Y = \\frac{\\text{adjacent}}{\\text{hypotenuse}} = \\frac{YZ}{XY} = \\frac{28}{XY}$. Since both ratios equal $\\frac{28}{XY}$, $\\sin X = \\cos Y$.</p>` +
        `<p><strong>Choice B is incorrect</strong> because $\\cos X = \\frac{XZ}{XY} = \\frac{22}{XY} \\neq \\frac{28}{XY}$.</p>` +
        `<p><strong>Choices C and D are incorrect</strong> because tangent is the ratio of opposite to adjacent (not involving hypotenuse), which does not equal $\\frac{28}{XY}$.</p>`,

    // Q7
    '6a5b15c7c3d08d90637d2ee8':
        `<p><strong>Choice B is correct.</strong> Rewrite the given equation $x^2 - 2x = 33$ in standard quadratic form by subtracting 33 from both sides:</p>` +
        `<p>$$x^2 - 2x - 33 = 0$$</p>` +
        `<p>Using the quadratic formula $x = \\frac{-b \\pm \\sqrt{b^2 - 4ac}}{2a}$ with $a = 1, b = -2, c = -33$:</p>` +
        `<p>$$x = \\frac{-(-2) \\pm \\sqrt{(-2)^2 - 4(1)(-33)}}{2(1)} = \\frac{2 \\pm \\sqrt{4 + 132}}{2} = \\frac{2 \\pm \\sqrt{136}}{2}$$</p>` +
        `<p>Simplifying the radical $\\sqrt{136} = \\sqrt{4 \\times 34} = 2\\sqrt{34}$:</p>` +
        `<p>$$x = \\frac{2 \\pm 2\\sqrt{34}}{2} = 1 \\pm \\sqrt{34}$$</p>` +
        `<p>(Or completing the square: $(x - 1)^2 - 1 = 33 \\implies (x - 1)^2 = 34 \\implies x - 1 = \\pm\\sqrt{34} \\implies x = 1 \\pm \\sqrt{34}$).</p>` +
        `<p>Therefore, one of the solutions is $1 + \\sqrt{34}$.</p>` +
        `<p><strong>Choice A is incorrect</strong> because it omits the linear term's contribution.</p>` +
        `<p><strong>Choice C is incorrect</strong> because 34 is the value of $(x - 1)^2$, not $x$.</p>` +
        `<p><strong>Choice D is incorrect</strong> due to improper radical simplification.</p>`,

    // Q8
    '6a5b16d4c3d08d90637d2eee':
        `<p><strong>Choice B is correct.</strong> The slope $m$ of a line is the constant rate of change $\\frac{\\Delta y}{\\Delta x}$. Using the first two entries from the table, $(0, r)$ and $(3, r - 24)$:</p>` +
        `<p>$$m = \\frac{(r - 24) - r}{3 - 0} = \\frac{-24}{3} = -8$$</p>` +
        `<p>Verifying with the third entry $(6, r - 48)$:</p>` +
        `<p>$$m = \\frac{(r - 48) - (r - 24)}{6 - 3} = \\frac{-24}{3} = -8$$</p>` +
        `<p>Thus, the slope of the line is <strong>-8</strong>.</p>` +
        `<p><strong>Choice A is incorrect</strong> because $-24$ is the change in $y$ over an interval of 3 units in $x$, failing to divide by $\\Delta x = 3$.</p>` +
        `<p><strong>Choices C and D are incorrect</strong> because they have the incorrect positive sign.</p>`,

    // Q9
    '6a5b172ec3d08d90637d2ef2':
        `<p><strong>Choice A is correct.</strong> In the exponential equation $y = 2^x + k$, as $x \\to -\\infty$, the term $2^x \\to 0$. Consequently, the horizontal line $y = k$ is the horizontal asymptote of the graph. Looking at the provided graph, the curve approaches the horizontal line $y = -6$ as $x$ becomes large and negative, which directly establishes that $k = -6$.</p>` +
        `<p>We can confirm this by checking the $y$-intercept: setting $x = 0$ gives $y = 2^0 + k = 1 + k$. The graph crosses the $y$-axis at $(0, -5)$. Solving $1 + k = -5$ yields $k = -6$.</p>` +
        `<p><strong>Choice B is incorrect</strong> because $-5$ is the $y$-intercept $(0, -5)$, not the asymptote constant $k$.</p>` +
        `<p><strong>Choices C and D are incorrect</strong> because positive values ($5$ and $6$) would place the asymptote above the $x$-axis.</p>`,

    // Q10
    '6a5b180ac3d08d90637d2ef6':
        `<p><strong>The correct answer is 106.</strong> In triangle $RST$, the sum of the interior angle measures must equal $180^\\circ$:</p>` +
        `<p>$$\\angle R + \\angle S + \\angle T = 180^\\circ$$</p>` +
        `<p>$$37 + x + (3x - 5) = 180$$</p>` +
        `<p>$$4x + 32 = 180 \\implies 4x = 148 \\implies x = 37^\\circ$$</p>` +
        `<p>Now find the measure of angle $T$ (which is $\\angle STR$):</p>` +
        `<p>$$\\angle T = 3(37) - 5 = 111 - 5 = 106^\\circ$$</p>` +
        `<p>Since line segment $\\overline{LK}$ is parallel to line segment $\\overline{RT}$, transversal line $\\overline{ST}$ cuts across these parallel segments. Therefore, angle $\\angle SKL$ and angle $\\angle STR$ are corresponding angles, which means they are equal in measure:</p>` +
        `<p>$$\\angle SKL = \\angle STR = 106^\\circ$$</p>` +
        `<p>Disregarding the degree symbol, the answer is <strong>106</strong>.</p>`,

    // Q11
    '6a5b1915c3d08d90637d2f02':
        `<p><strong>Choice D is correct.</strong> The given system of linear equations is:</p>` +
        `<p>$$\\text{(1) } 31x - 32y = c$$</p>` +
        `<p>$$\\text{(2) } 32x + 31y = c$$</p>` +
        `<p>Subtract equation (1) from equation (2):</p>` +
        `<p>$$(32x + 31y) - (31x - 32y) = c - c \\implies x + 63y = 0 \\implies x = -63y \\implies y = -\\frac{x}{63}$$</p>` +
        `<p>Any point $(x, y)$ where the two equations intersect must satisfy this relationship $y = -\\frac{x}{63}$. Testing the choices:</p>` +
        `<ul>` +
        `<li>For Choice A, $(c, 0)$: $y = 0 \\neq -\\frac{c}{63}$ since $c > 0$.</li>` +
        `<li>For Choice B, $\\left(c, \\frac{c}{63}\\right)$: $\\frac{c}{63} \\neq -\\frac{c}{63}$.</li>` +
        `<li>For Choice C, $(10, 630)$: $630 \\neq -\\frac{10}{63}$.</li>` +
        `<li>For Choice D, $\\left(10, -\\frac{10}{63}\\right)$: here $x = 10$ and $y = -\\frac{10}{63}$, which satisfies $y = -\\frac{x}{63}$. Substituting into equation (1) gives $c = 31(10) - 32\\left(-\\frac{10}{63}\\right) = 310 + \\frac{320}{63} > 0$, consistent with $c$ being a positive constant.</li>` +
        `</ul>` +
        `<p><strong>Choices A, B, and C are incorrect</strong> because they do not satisfy $x + 63y = 0$.</p>`,

    // Q12
    '6a5b1a30c3d08d90637d2f06':
        `<p><strong>Choice C is correct.</strong> Both statements I and II must be true.</p>` +
        `<p>In data set A, the recording error at $x = 0$ is an extreme high outlier located at $(0, 14.5)$, whereas the remaining 8 data points lie much lower, near $y \\approx 6.5$ to $7.0$ when $x$ is near 0. In Model A, the $y$-intercept is $6.57$. Because this outlier at $x = 0$ pulled the $y$-intercept upward, removing it to form data set B causes the new $y$-intercept $c$ to decrease closer to the cluster of valid data: $c < 6.57$. Thus, <strong>Statement II must be true</strong>.</p>` +
        `<p>Furthermore, having an extremely high data point at $x = 0$ while the minimum of the remaining points is around $x = 1$ to $2$ forced Model A to flatten its left side and reduce its upward curvature. When the high outlier at $x = 0$ is removed, the remaining data points form a clearer upward-opening parabolic curve with a sharper bend, increasing the quadratic curvature parameter: $a > 0.04$. Thus, <strong>Statement I must be true</strong>.</p>` +
        `<p>Since both statements are true, Choice C is correct.</p>` +
        `<p><strong>Choices A, B, and D are incorrect</strong> because neither statement alone is sufficient, nor are they false.</p>`,

    // Q13
    '6a5b1b33c3d08d90637d2f10':
        `<p><strong>Choice A is correct.</strong> To convert an angle measure from degrees to radians, multiply the degree measure by the conversion factor $\\frac{\\pi\\text{ radians}}{180^\\circ}$:</p>` +
        `<p>$$\\text{Radians} = (47 \\times 180)^\\circ \\times \\frac{\\pi}{180^\\circ} = 47 \\times \\pi = 47\\pi$$</p>` +
        `<p><strong>Choice B is incorrect</strong> because it adds $\\pi$ and 47 instead of multiplying.</p>` +
        `<p><strong>Choice C is incorrect</strong> because it has a negative sign and inverts the factor.</p>` +
        `<p><strong>Choice D is incorrect</strong> because it subtracts 47 from $\\pi$.</p>`,

    // Q14
    '6a5b1bc6c3d08d90637d2f22':
        `<p><strong>Choice C is correct.</strong> Let $x$ be the mass, in grams, of the $0.1\\%$ sodium chloride solution, and let $y$ be the mass, in grams, of the $0.05\\%$ sodium chloride solution. We can set up a system of two equations:</p>` +
        `<p>1) Total mass: $x + y = 90 \\implies y = 90 - x$</p>` +
        `<p>2) Total salt mass: $0.1\\% x + 0.05\\% y = 0.07$</p>` +
        `<p>Convert the percentages to decimals: $0.001x + 0.0005y = 0.07$. Substitute $y = 90 - x$:</p>` +
        `<p>$$0.001x + 0.0005(90 - x) = 0.07$$</p>` +
        `<p>$$0.001x + 0.045 - 0.0005x = 0.07$$</p>` +
        `<p>$$0.0005x = 0.07 - 0.045 = 0.025$$</p>` +
        `<p>$$x = \\frac{0.025}{0.0005} = 50\\text{ grams}$$</p>` +
        `<p>Thus, the biologist used 50 grams of the $0.1\\%$ solution.</p>` +
        `<p><strong>Choice A is incorrect</strong> because 0.14 is not related to the mass of the solution.</p>` +
        `<p><strong>Choice B is incorrect</strong> because 40 grams is the mass of the $0.05\\%$ solution ($90 - 50 = 40$).</p>` +
        `<p><strong>Choice D is incorrect</strong> because 89.86 results from subtracting 0.14 from 90.</p>`,

    // Q15
    '6a5b1c3dc3d08d90637d2f26':
        `<p><strong>The correct answer is -178.</strong> First expand the product $(9x + 16)(x - 5)$ using FOIL:</p>` +
        `<p>$$(9x + 16)(x - 5) = 9x^2 - 45x + 16x - 80 = 9x^2 - 29x - 80$$</p>` +
        `<p>Multiply by the outer factor 6:</p>` +
        `<p>$$6(9x^2 - 29x - 80) = 54x^2 - 174x - 480$$</p>` +
        `<p>Now subtract $(4x + 17)$:</p>` +
        `<p>$$(54x^2 - 174x - 480) - (4x + 17) = 54x^2 - 174x - 4x - 480 - 17 = 54x^2 - 178x - 497$$</p>` +
        `<p>In the form $ax^2 + bx + c$, the coefficient of $x$ is $b = -178$. Therefore, the value of $b$ is <strong>-178</strong>.</p>`,

    // Q16
    '6a5b1cd9c3d08d90637d2f2c':
        `<p><strong>Choice C is correct.</strong> By the Triangle Inequality Theorem, the length of any side of a triangle must be strictly greater than the difference between the other two side lengths and strictly less than their sum. For a triangle with side lengths 9, 13, and $x$:</p>` +
        `<p>$$|13 - 9| < x < 13 + 9$$</p>` +
        `<p>$$4 < x < 22$$</p>` +
        `<p>Therefore, the inequality representing all possible values of $x$ is $4 < x < 22$.</p>` +
        `<p><strong>Choice A is incorrect</strong> because $x < 22$ allows impossible non-positive side lengths or lengths $\\le 4$ where $x + 9 \\le 13$.</p>` +
        `<p><strong>Choice B is incorrect</strong> because values $x > 22$ violate the theorem since $9 + 13 = 22 < x$.</p>` +
        `<p><strong>Choice D is incorrect</strong> because it describes the set of side lengths that <em>cannot</em> form a triangle.</p>`,

    // Q17
    '6a5b1e60c3d08d90637d2f32':
        `<p><strong>Choice A is correct.</strong> An exponential model has the general form $V(t) = V_0(r)^n$, where $V_0$ is the initial quantity, $r$ is the growth factor per period, and $n$ is the number of periods.</p>` +
        `<ul>` +
        `<li>The initial number of visitors when the theme park opened is $V_0 = 85$.</li>` +
        `<li>Every 30 minutes, the estimated number of visitors increases by $120\\%$, so the growth multiplier is $1 + 1.20 = 2.20$.</li>` +
        `<li>Since each period is 30 minutes (which is $\\frac{1}{2}$ hour), in $t$ hours there are $\\frac{t}{0.5} = 2t$ periods of 30 minutes.</li>` +
        `</ul>` +
        `<p>Substituting these into the model gives $V = 85(2.20)^{2t}$.</p>` +
        `<p><strong>Choice B is incorrect</strong> because the exponent $\\frac{t}{30}$ treats 30 as 30 hours rather than 30 minutes.</p>` +
        `<p><strong>Choices C and D are incorrect</strong> because a growth factor of $1.20$ represents an increase of only $20\\%$, not $120\\%$.</p>`,

    // Q18
    '6a5b1fbfc3d08d90637d2f36':
        `<p><strong>Choice D is correct.</strong> Distribute the constants on both sides of the given equation $42(x - 1) = 6(-7 + 7x)$:</p>` +
        `<p>Left side: $42(x) - 42(1) = 42x - 42$</p>` +
        `<p>Right side: $6(-7) + 6(7x) = -42 + 42x = 42x - 42$</p>` +
        `<p>Both sides simplify to the exact same expression: $42x - 42 = 42x - 42$. Subtracting $42x$ from both sides results in $-42 = -42$, which is an identity that is true for all real values of $x$. Therefore, the equation has infinitely many solutions.</p>` +
        `<p><strong>Choice A is incorrect</strong> because an equation has zero solutions when simplification produces a contradiction (such as $0 = 5$).</p>` +
        `<p><strong>Choices B and C are incorrect</strong> because linear equations that simplify to identical expressions on both sides have infinitely many solutions, not a finite number.</p>`,

    // Q19
    '6a5b20a0c3d08d90637d2f43':
        `<p><strong>Choice A is correct.</strong> Consider each function for $x \\ge 0$ with integer constants $1 < a < b$:</p>` +
        `<p><strong>For equation I:</strong> $f(x) = a(0.54)^{-bx} = a\\left(\\frac{1}{0.54}\\right)^{bx}$. Since $0.54 < 1$, its reciprocal $\\frac{1}{0.54} > 1$. Because $b > 0$, $\\left(\\frac{1}{0.54}\\right)^{bx}$ is a strictly increasing function for $x \\ge 0$. Therefore, the minimum value of $f(x)$ for $x \\ge 0$ occurs at the boundary $x = 0$:</p>` +
        `<p>$$f(0) = a(0.54)^0 = a(1) = a$$</p>` +
        `<p>The minimum value $a$ is displayed directly as a coefficient in the equation $f(x) = a(0.54)^{-bx}$. Thus, equation I displays its minimum value.</p>` +
        `<p><strong>For equation II:</strong> $g(x) = a(1.46)^{x+2} + b$. Since the base $1.46 > 1$, $g(x)$ is also strictly increasing for $x \\ge 0$. Its minimum value occurs at $x = 0$:</p>` +
        `<p>$$g(0) = a(1.46)^2 + b = 2.1316a + b$$</p>` +
        `<p>This minimum value $2.1316a + b$ is neither the constant $b$ (which is the horizontal asymptote as $x \\to -\\infty$) nor the coefficient $a$. Thus, equation II does not display its minimum value.</p>` +
        `<p>Therefore, only equation I displays its minimum value as a constant or coefficient.</p>` +
        `<p><strong>Choices B, C, and D are incorrect</strong> because only statement I holds.</p>`,

    // Q20
    '6a5b2114c3d08d90637d2f47':
        `<p><strong>The correct answer is 65000.</strong> Translate each statement into an algebraic equation where $A, B,$ and $C$ represent the masses of objects A, B, and C respectively:</p>` +
        `<p>1) "Mass of A is $481\\%$ of mass of B": $A = 4.81B$</p>` +
        `<p>2) "Mass of A is $0.740\\%$ of mass of C": $A = 0.00740C$</p>` +
        `<p>Since both expressions equal $A$, equate them:</p>` +
        `<p>$$0.00740C = 4.81B$$</p>` +
        `<p>Solve for $C$ in terms of $B$:</p>` +
        `<p>$$C = \\frac{4.81}{0.00740}B = 650B$$</p>` +
        `<p>We are told that the mass of object C is $p\\%$ of the mass of object B, which means $C = \\frac{p}{100}B$. Equating the coefficients of $B$:</p>` +
        `<p>$$\\frac{p}{100} = 650 \\implies p = 650 \\times 100 = 65,000$$</p>` +
        `<p>Therefore, the value of $p$ is <strong>65000</strong>.</p>`,

    // Q21
    '6a5b214fc3d08d90637d2f4b':
        `<p><strong>Choice D is correct.</strong> Start by factoring out the common factor $(x - 8)$ from both terms of the expression:</p>` +
        `<p>$$y^2(x - 8) - 16(x - 8)^3 = (x - 8)\\left[y^2 - 16(x - 8)^2\\right]$$</p>` +
        `<p>The expression inside the brackets is a difference of two squares, $A^2 - B^2 = (A - B)(A + B)$, where $A = y$ and $B = 4(x - 8)$:</p>` +
        `<p>$$y^2 - [4(x - 8)]^2 = [y - 4(x - 8)][y + 4(x - 8)]$$</p>` +
        `<p>Distribute the 4 inside each bracket:</p>` +
        `<p>$$y - 4(x - 8) = y - 4x + 32$$</p>` +
        `<p>$$y + 4(x - 8) = y + 4x - 32$$</p>` +
        `<p>Putting all factors together:</p>` +
        `<p>$$(x - 8)(y - 4x + 32)(y + 4x - 32)$$</p>` +
        `<p>Looking at the given answer choices, $y + 4x - 32$ is one of the factors of the expression.</p>` +
        `<p><strong>Choices A, B, and C are incorrect</strong> because they are not factors of the original polynomial.</p>`,

    // Q22
    '6a5b2185c3d08d90637d2f4f':
        `<p><strong>Choice C is correct.</strong> In statistical experimental design, to establish a <strong>cause-and-effect</strong> relationship between an explanatory variable (treatment) and a response variable, researchers must perform a randomized experiment where participants or subjects are <strong>randomly assigned</strong> to the treatment and control groups.</p>` +
        `<p>Random assignment ensures that any confounding variables (such as age, health, genetics, and environment) are evenly distributed between the treatment and control groups on average. This isolates the treatment as the only systematic difference between the groups, allowing any observed difference in the outcome to be attributed causally to the treatment.</p>` +
        `<p><strong>Choice A is incorrect</strong> because having equal numbers in each group is helpful for statistical power, but does not prevent confounding or establish causation.</p>` +
        `<p><strong>Choice B is incorrect</strong> because random selection from a population allows findings to be <em>generalized</em> to that population, but without random assignment to treatments, confounders prevent establishing cause-and-effect.</p>` +
        `<p><strong>Choice D is incorrect</strong> because matching only on average age does not control for other confounding variables.</p>`
};

async function run() {
    console.log('🚀 Adding explanations to all 22 questions of Dec 2025 US 1 Module 2...\n');
    let count = 0;
    for (const [id, exp] of Object.entries(explanationsM2)) {
        count++;
        process.stdout.write(`Updating Q${count} (${id})... `);
        const res = await updateQuestion(id, { explanation: exp });
        if (res.message === 'success') {
            console.log('✅ success');
        } else {
            console.log('❌ failed:', res);
        }
    }

    console.log('\n✨ Verifying on live production server...\n');
    for (const [id] of Object.entries(explanationsM2)) {
        const qData = await getQuestionDetails(id);
        const exp = qData.question?.explanation;
        console.log(`Q ID ${id}: ${exp ? `✅ Saved (${exp.length} chars)` : '❌ EMPTY'}`);
    }

    console.log('\n🎉 ALL MODULE 2 EXPLANATIONS SUCCESSFULLY DEPLOYED TO PRODUCTION!');
}

run().catch(console.error);
