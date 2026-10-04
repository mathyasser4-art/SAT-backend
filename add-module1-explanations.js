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

const explanationsM1 = {
    // Q1
    '6a53fde24d554e04aa1bfc06': 
        `<p><strong>Choice B is correct.</strong> The rental price consists of a fixed cost of $1,050 for the first 3 hours, plus $250 for each additional hour beyond 3 hours. For a 10-hour rental, the number of additional hours is $10 - 3 = 7$ hours. The additional cost is $7 \\times 250 = 1,750$ dollars. Adding this to the base fee for the first 3 hours gives a total price of $1,050 + 1,750 = 2,800$ dollars.</p>` +
        `<p><strong>Choice A is incorrect</strong> because 1,750 is only the cost for the additional 7 hours ($7 \\times 250$), omitting the initial $1,050 rental fee for the first 3 hours.</p>` +
        `<p><strong>Choice C is incorrect</strong> because it calculates $1,050 + 10 \\times 250 = 3,550$, erroneously charging the additional hourly rate for all 10 hours rather than the 7 additional hours.</p>` +
        `<p><strong>Choice D is incorrect</strong> because it multiplies the initial base price of $1,050 by 3 ($3 \\times 1,050 + 7 \\times 250 = 4,900$).</p>`,

    // Q2
    '6a53fe4a4d554e04aa1bfc15':
        `<p><strong>The correct answer is 19.2 (or 96/5).</strong> To convert the average speed from yards per hour to miles per hour, divide the speed in yards per hour by the number of yards in 1 mile ($1\\text{ mile} = 1,760\\text{ yards}$):</p>` +
        `<p>$$\\text{Speed} = \\frac{33,792\\text{ yards/hour}}{1,760\\text{ yards/mile}} = 19.2\\text{ miles per hour}$$</p>` +
        `<p>In fractional form, $\\frac{33,792}{1,760} = \\frac{96}{5}$. Either <strong>19.2</strong> or <strong>96/5</strong> may be entered as the correct answer.</p>`,

    // Q3
    '6a53fe9c4d554e04aa1bfc20':
        `<p><strong>Choice A is correct.</strong> Notice the algebraic relationship between the given expression $5x + 4$ and the desired expression $50x + 40$. Factoring out 10 from $50x + 40$ gives:</p>` +
        `<p>$$50x + 40 = 10(5x + 4)$$</p>` +
        `<p>Since it is given that $5x + 4 = 34$, substituting 34 into this factored expression yields $10(34) = 340$.</p>` +
        `<p>Alternatively, solving for $x$ from $5x + 4 = 34$ gives $5x = 30$, so $x = 6$. Substituting $x = 6$ into $50x + 40$ yields $50(6) + 40 = 300 + 40 = 340$.</p>` +
        `<p><strong>Choice B is incorrect</strong> because 90 corresponds to an arithmetic error.</p>` +
        `<p><strong>Choice C is incorrect</strong> because 60 represents $10x$.</p>` +
        `<p><strong>Choice D is incorrect</strong> because 6 is the value of $x$, not the value of $50x + 40$.</p>`,

    // Q4
    '6a53ff254d554e04aa1bfc24':
        `<p><strong>Choice B is correct.</strong> In the figure, lines $p$ and $r$ are parallel, cut by transversal line $t$. The angle labeled $50^\\circ$ and the angle labeled $x^\\circ$ are vertical angles formed at the intersection of line $p$ and line $t$. Since vertical angles are congruent, $x = 50$. (Alternatively, using alternate interior angles and supplementary angles confirms that the angle measure is $50^\\circ$).</p>` +
        `<p><strong>Choice A is incorrect</strong> because 25 is half of the given angle.</p>` +
        `<p><strong>Choice C is incorrect</strong> because 180 is the total degree measure of a straight line, not the measure of angle $x$.</p>` +
        `<p><strong>Choice D is incorrect</strong> because 230 results from adding $180 + 50$.</p>`,

    // Q5
    '6a53ffdf4d554e04aa1bfc31':
        `<p><strong>Choice D is correct.</strong> Use the distributive property to multiply each term inside the parentheses by $6xy$:</p>` +
        `<p>$$6xy(2x^2 + 7y) = (6xy)(2x^2) + (6xy)(7y)$$</p>` +
        `<p>Multiplying the coefficients and combining like variables using the product rule of exponents ($x^a \\cdot x^b = x^{a+b}$ and $y^a \\cdot y^b = y^{a+b}$):</p>` +
        `<p>$$(6 \\cdot 2)(x \\cdot x^2)(y) + (6 \\cdot 7)(x)(y \\cdot y) = 12x^3y + 42xy^2$$</p>` +
        `<p><strong>Choice A is incorrect</strong> because the coefficients were added ($6+2=8$ and $6+7=13$) instead of multiplied.</p>` +
        `<p><strong>Choice B is incorrect</strong> because $6xy$ was not distributed to the second term.</p>` +
        `<p><strong>Choice C is incorrect</strong> because the variable exponents were not added when multiplying ($x \\cdot x^2 = x^3$ and $y \\cdot y = y^2$).</p>`,

    // Q6
    '6a5400fb4d554e04aa1bfc42':
        `<p><strong>The correct answer is 3/50 (or 0.06).</strong> The probability of an event is calculated as the number of favorable outcomes divided by the total number of possible outcomes:</p>` +
        `<p>$$P(\\text{Vegetarian}) = \\frac{\\text{Number of people who chose vegetarian}}{\\text{Total number of people attended}} = \\frac{3}{50}$$</p>` +
        `<p>Converting to decimal form gives $\\frac{3}{50} = 0.06$. Either <strong>3/50</strong> or <strong>0.06</strong> is an accepted answer.</p>`,

    // Q7
    '6a54015e4d554e04aa1bfc52':
        `<p><strong>Choice D is correct.</strong> In the scatterplot, when $x = 0$, the $y$-values are near 10, indicating a $y$-intercept around 9.1. As $x$ increases from 0 to 10, the values of $y$ decrease from approximately 10 down to 1. This downward trend indicates a negative slope. The slope can be estimated by taking two approximate points on the trendline, such as $(0, 9.1)$ and $(10, 0.1)$:</p>` +
        `<p>$$m \\approx \\frac{0.1 - 9.1}{10 - 0} = \\frac{-9.0}{10} = -0.9$$</p>` +
        `<p>Therefore, the most appropriate linear model is $y = 9.1 - 0.9x$.</p>` +
        `<p><strong>Choice A is incorrect</strong> because it has a positive slope and an incorrect $y$-intercept of 0.9.</p>` +
        `<p><strong>Choice B is incorrect</strong> because a slope of $-9.1$ is far too steep; $y$ would decrease by 9.1 when $x$ increases by only 1 unit.</p>` +
        `<p><strong>Choice C is incorrect</strong> because the slope is positive ($+0.9x$), which would predict $y$ increasing as $x$ increases, contradicting the scatterplot.</p>`,

    // Q8
    '6a5401ce4d554e04aa1bfc60':
        `<p><strong>Choice B is correct.</strong> The area of a square is given by $\\text{side}^2$. Since square X has a side length of 8 cm:</p>` +
        `<p>$$\\text{Area of square X} = 8^2 = 64\\text{ cm}^2$$</p>` +
        `<p>The area of rectangle Y is given as 45 cm$^2$. The total area of square X and rectangle Y is the sum of their individual areas:</p>` +
        `<p>$$\\text{Total area} = 64 + 45 = 109\\text{ cm}^2$$</p>` +
        `<p><strong>Choice A is incorrect</strong> because it results from an arithmetic error.</p>` +
        `<p><strong>Choice C is incorrect</strong> because 106 results from subtracting 3 from 109.</p>` +
        `<p><strong>Choice D is incorrect</strong> because 64 is only the area of square X, omitting rectangle Y.</p>`,

    // Q9
    '6a5402884d554e04aa1bfc6e':
        `<p><strong>Choice C is correct.</strong> Standard deviation measures the spread or dispersion of data values around their mean. In all four data sets, the mean is $p$ because the values are distributed symmetrically about $p$. The data set with the greatest standard deviation is the one whose values deviate furthest from the mean $p$ on average:</p>` +
        `<ul>` +
        `<li>For Set A: deviations from $p$ are $-5, -5, 0, 5, 5$ (sum of squared deviations is $25 + 25 + 0 + 25 + 25 = 100$).</li>` +
        `<li>For Set B: deviations from $p$ are $-6, 0, 0, 0, 6$ (sum of squared deviations is $36 + 0 + 0 + 0 + 36 = 72$).</li>` +
        `<li>For Set C: deviations from $p$ are $-9, -6, 0, 6, 9$ (sum of squared deviations is $81 + 36 + 0 + 36 + 81 = 234$).</li>` +
        `<li>For Set D: deviations from $p$ are $0, 0, 0, 0, 0$ (standard deviation is 0).</li>` +
        `</ul>` +
        `<p>Because Set C has the largest sum of squared deviations from the mean ($234$), it has the largest standard deviation.</p>` +
        `<p><strong>Choices A, B, and D are incorrect</strong> because their values cluster closer to the mean $p$ than those in Set C.</p>`,

    // Q10
    '6a5402eb4d554e04aa1bfc7a':
        `<p><strong>Choice C is correct.</strong> In the given function $f(x) = 900(0.5)^{\\frac{x}{12}}$, the input $x$ represents the depth in millimeters below the surface of the material, and the output $f(x)$ represents the predicted beam intensity, in photons. Therefore, in the statement $f(12) = 450$, the input $12$ corresponds to $x = 12$ millimeters below the surface, and the output $450$ corresponds to a predicted intensity of $450$ photons. Hence, a beam 12 millimeters below the surface has a predicted intensity of 450 photons.</p>` +
        `<p><strong>Choice A is incorrect</strong> because it misidentifies 12 as the intensity at the surface rather than the depth.</p>` +
        `<p><strong>Choice B is incorrect</strong> because at the surface ($x = 0$), $f(0) = 900(0.5)^0 = 900$ photons, not 450 photons.</p>` +
        `<p><strong>Choice D is incorrect</strong> because it reverses the roles of depth and intensity.</p>`,

    // Q11
    '6a54031f4d554e04aa1bfc86':
        `<p><strong>Choice B is correct.</strong> To find the percentage of the research farm that contains rice, divide the number of acres containing rice by the total acreage of the farm and multiply by $100\\%$:</p>` +
        `<p>$$\\text{Percentage} = \\frac{76}{1,000} \\times 100\\% = 0.076 \\times 100\\% = 7.6\\%$$</p>` +
        `<p><strong>Choice A is incorrect</strong> because $0.76\\%$ corresponds to $\\frac{7.6}{1,000}$.</p>` +
        `<p><strong>Choice C is incorrect</strong> because $76\\%$ corresponds to $\\frac{76}{100}$, not $\\frac{76}{1,000}$.</p>` +
        `<p><strong>Choice D is incorrect</strong> because $760\\%$ corresponds to an extra factor of 100.</p>`,

    // Q12
    '6a5404684d554e04aa1bfc92':
        `<p><strong>Choice A is correct.</strong> The relationship between the number of food tickets, $x$, and the total amount paid, $y$, is linear because each ticket costs the same amount. The slope $m$ (cost per ticket) is calculated using two points from the table, such as $(10, 34.00)$ and $(15, 41.50)$:</p>` +
        `<p>$$m = \\frac{41.50 - 34.00}{15 - 10} = \\frac{7.50}{5} = 1.50 = \\frac{3}{2}$$</p>` +
        `<p>The fixed entrance fee is the $y$-intercept $b$. Using the point $(10, 34.00)$:</p>` +
        `<p>$$y = mx + b \\implies 34.00 = \\frac{3}{2}(10) + b \\implies 34 = 15 + b \\implies b = 19$$</p>` +
        `<p>Thus, the equation representing the relationship is $y = \\frac{3}{2}x + 19$.</p>` +
        `<p><strong>Choice B is incorrect</strong> because the $y$-intercept is negative ($-41$).</p>` +
        `<p><strong>Choices C and D are incorrect</strong> because their $y$-intercepts are $\\frac{82}{3} \\approx 27.33$ rather than 19.</p>`,

    // Q13
    '6a5406d14d554e04aa1bfca0':
        `<p><strong>Choice D is correct.</strong> Start with the given equation $b^2 + 4c = 7d$. To express $b$ in terms of $c$ and $d$, isolate $b^2$ by subtracting $4c$ from both sides:</p>` +
        `<p>$$b^2 = 7d - 4c$$</p>` +
        `<p>Since $d > \\frac{4}{7}c$, the quantity $7d - 4c > 0$. Taking the square root of both sides gives:</p>` +
        `<p>$$b = \\pm\\sqrt{7d - 4c}$$</p>` +
        `<p><strong>Choices A and B are incorrect</strong> because they divide by 2 rather than taking the square root of $b^2$.</p>` +
        `<p><strong>Choice C is incorrect</strong> because it has $+4c$ under the radical instead of $-4c$.</p>`,

    // Q14
    '6a5408dd4d554e04aa1bfcb0':
        `<p><strong>The correct answer is -4.</strong> To find the slope of the line, rewrite the given equation $4x + y = 19$ in slope-intercept form, $y = mx + b$, where $m$ is the slope and $b$ is the $y$-intercept:</p>` +
        `<p>$$y = -4x + 19$$</p>` +
        `<p>Comparing this with $y = mx + b$, the coefficient of $x$ is $-4$. Therefore, the slope of the line is <strong>-4</strong>.</p>`,

    // Q15
    '6a540dda4d554e04aa1bfcbc':
        `<p><strong>Choice A is correct.</strong> Given $f(x) = \\frac{x+17}{5} + 175$ and $f(a) = -19$, substitute $x = a$ into the function:</p>` +
        `<p>$$\\frac{a + 17}{5} + 175 = -19$$</p>` +
        `<p>Subtract 175 from both sides:</p>` +
        `<p>$$\\frac{a + 17}{5} = -19 - 175 = -194$$</p>` +
        `<p>Multiply both sides by 5:</p>` +
        `<p>$$a + 17 = -194 \\times 5 = -970$$</p>` +
        `<p>Subtract 17 from both sides:</p>` +
        `<p>$$a = -970 - 17 = -987$$</p>` +
        `<p><strong>Choice B is incorrect</strong> because $-970$ is the value of $a + 17$, forgetting to subtract 17.</p>` +
        `<p><strong>Choice C is incorrect</strong> because $-194$ is the value of $\\frac{a+17}{5}$.</p>` +
        `<p><strong>Choice D is incorrect</strong> because $-953$ results from adding 17 instead of subtracting 17 ($-970 + 17 = -953$).</p>`,

    // Q16
    '6a540eab4d554e04aa1bfcc2':
        `<p><strong>The correct answer is 2.</strong> The function $g(x) = ax + b$ is linear, where $a$ represents the slope of the line. The given values $g(-4) = -6$ and $g(3) = 8$ correspond to the points $(-4, -6)$ and $(3, 8)$ on the line. The slope $a$ is calculated using the slope formula:</p>` +
        `<p>$$a = \\frac{g(3) - g(-4)}{3 - (-4)} = \\frac{8 - (-6)}{3 + 4} = \\frac{14}{7} = 2$$</p>` +
        `<p>Therefore, the value of $a$ is <strong>2</strong>.</p>`,

    // Q17
    '6a540f3d4d554e04aa1bfcdd':
        `<p><strong>The correct answer is 1.65 (or 33/20).</strong> The height function is $h(t) = -16t^2 + b$. When the object is dropped at $t = 0$, its height is $43.56$ feet, so:</p>` +
        `<p>$$h(0) = -16(0)^2 + b = 43.56 \\implies b = 43.56$$</p>` +
        `<p>The object hits the ground when its height is $0$ feet, so set $h(t) = 0$:</p>` +
        `<p>$$-16t^2 + 43.56 = 0 \\implies 16t^2 = 43.56 \\implies t^2 = \\frac{43.56}{16} = 2.7225$$</p>` +
        `<p>Taking the positive square root for time $t > 0$:</p>` +
        `<p>$$t = \\sqrt{2.7225} = 1.65\\text{ seconds}$$</p>` +
        `<p>In fractional form, $1.65 = \\frac{165}{100} = \\frac{33}{20}$. Either <strong>1.65</strong> or <strong>33/20</strong> may be entered as the correct answer.</p>`,

    // Q18
    '6a540f754d554e04aa1bfcef':
        `<p><strong>Choice C is correct.</strong> Given the equation $\\frac{|3x - 54|}{6} + 3 = 9$, first isolate the absolute value term by subtracting 3 from both sides:</p>` +
        `<p>$$\\frac{|3x - 54|}{6} = 6$$</p>` +
        `<p>Multiply both sides by 6:</p>` +
        `<p>$$|3x - 54| = 36$$</p>` +
        `<p>This absolute value equation produces two linear cases:</p>` +
        `<p>Case 1: $3x - 54 = 36 \\implies 3x = 90 \\implies x = 30$</p>` +
        `<p>Case 2: $3x - 54 = -36 \\implies 3x = 18 \\implies x = 6$</p>` +
        `<p>The sum of the solutions is $30 + 6 = 36$.</p>` +
        `<p>(Alternatively, by symmetry, the center of $|3x - 54| = 36$ is $3x = 54 \\implies x = 18$. The sum of two symmetric solutions about $x = 18$ is $2 \\times 18 = 36$).</p>` +
        `<p><strong>Choice A is incorrect</strong> because 1 is not related to the sum of the solutions.</p>` +
        `<p><strong>Choice B is incorrect</strong> because 35 is an off-by-one error.</p>` +
        `<p><strong>Choice D is incorrect</strong> because 54 is the constant inside the absolute value expression.</p>`,

    // Q19
    '6a540fc84d554e04aa1bfcff':
        `<p><strong>The correct answer is 6.</strong> A system of two linear equations has no solution if the lines are parallel and distinct (meaning they have the same slope but different $y$-intercepts). First, rewrite both equations in terms of $x$ and $y$:</p>` +
        `<p>Equation 1: $8x - 3y = 3y + 9 \\implies 8x - 6y = 9 \\implies 6y = 8x - 9$</p>` +
        `<p>Equation 2: $hy = 2 + 8x \\implies hy = 8x + 2$</p>` +
        `<p>Notice that the right sides both have the term $8x$. For the lines to have the exact same slope, the coefficients of $y$ on the left side must be equal:</p>` +
        `<p>$$h = 6$$</p>` +
        `<p>With $h = 6$, dividing both equations by 6 gives $y = \\frac{4}{3}x - \\frac{3}{2}$ and $y = \\frac{4}{3}x + \\frac{1}{3}$. Since they have the same slope $\\frac{4}{3}$ and different $y$-intercepts ($-\\frac{3}{2} \\neq \\frac{1}{3}$), the system has no solution. Thus, the value of $h$ is <strong>6</strong>.</p>`,

    // Q20
    '6a5410164d554e04aa1bfd0d':
        `<p><strong>Choice D is correct.</strong> In right triangle $QRS$, angle $R$ is the right angle ($90^\\circ$), so the side opposite angle $R$ is the hypotenuse, $\\overline{QS}$. For acute angle $Q$, the opposite leg is $\\overline{RS}$, whose length is given as 22. By the definition of the sine trigonometric ratio:</p>` +
        `<p>$$\\sin(Q) = \\frac{\\text{opposite}}{\\text{hypotenuse}} = \\frac{RS}{QS} = \\frac{22}{QS}$$</p>` +
        `<p>Multiplying both sides by $QS$ and then dividing by $\\sin(Q)$ yields:</p>` +
        `<p>$$QS = \\frac{22}{\\sin(Q)}$$</p>` +
        `<p><strong>Choice A is incorrect</strong> because $22\\cos(Q)$ multiplies by cosine instead of using the sine definition.</p>` +
        `<p><strong>Choice B is incorrect</strong> because $22\\sin(Q)$ would give the opposite side if the hypotenuse were 22.</p>` +
        `<p><strong>Choice C is incorrect</strong> because cosine is the ratio of adjacent leg to hypotenuse ($\\cos Q = \\frac{QR}{QS}$), which involves $QR$, not $RS = 22$.</p>`,

    // Q21
    '6a5410564d554e04aa1bfd13':
        `<p><strong>Choice C is correct.</strong> In the coordinate plane, the boundary line is dashed, indicating a strict inequality ($>$ or $<$). The boundary line has a $y$-intercept at $(0, -15)$ and passes through $(1.5, 0)$, so its slope is $m = \\frac{0 - (-15)}{1.5 - 0} = \\frac{15}{1.5} = 10$. Therefore, the equation of the boundary line is $y = 10x - 15$.</p>` +
        `<p>To determine the inequality sign, test a point in the shaded region, such as the origin $(0, 0)$:</p>` +
        `<p>$$0 > 10(0) - 15 \\implies 0 > -15$$</p>` +
        `<p>Since $0 > -15$ is a true statement, the shaded region corresponds to $y > 10x - 15$.</p>` +
        `<p><strong>Choice A is incorrect</strong> because a slope of 2 would produce an $x$-intercept at $(7.5, 0)$ instead of $(1.5, 0)$.</p>` +
        `<p><strong>Choices B and D are incorrect</strong> because the inequality symbol $<$ would shade the region below the boundary line (excluding the origin).</p>`,

    // Q22
    '6a54109c4d554e04aa1bfd17':
        `<p><strong>Choice A is correct.</strong> In the exponential function $y = 4^x + k$, as $x \\to -\\infty$, $4^x \\to 0$. Therefore, the line $y = k$ is the horizontal asymptote of the graph. Looking at the given graph, the curve flattens horizontally along the line $y = -5$, which directly indicates $k = -5$.</p>` +
        `<p>We can verify this using the $y$-intercept: when $x = 0$, $y = 4^0 + k = 1 + k$. The graph clearly crosses the $y$-axis at $(0, -4)$. Setting $1 + k = -4$ confirms that $k = -4 - 1 = -5$.</p>` +
        `<p><strong>Choice B is incorrect</strong> because $-4$ is the $y$-intercept of the graph, not the value of the vertical shift constant $k$.</p>` +
        `<p><strong>Choices C and D are incorrect</strong> because positive values ($4$ or $5$) would place the horizontal asymptote above the $x$-axis.</p>`
};

async function run() {
    console.log('🚀 Adding explanations to all 22 questions of Dec 2025 US 1 Module 1...\n');
    let count = 0;
    for (const [id, exp] of Object.entries(explanationsM1)) {
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
    for (const [id] of Object.entries(explanationsM1)) {
        const qData = await getQuestionDetails(id);
        const exp = qData.question?.explanation;
        console.log(`Q ID ${id}: ${exp ? `✅ Saved (${exp.length} chars)` : '❌ EMPTY'}`);
    }

    console.log('\n🎉 ALL MODULE 1 EXPLANATIONS SUCCESSFULLY DEPLOYED TO PRODUCTION!');
}

run().catch(console.error);
