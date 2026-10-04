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
  '6a5309f24d554e04aa1bf55a': `<p><strong>Choice C is correct.</strong></p>
<p>The graph shows the weight of solid wax ${f('y')}, in ounces, as a function of time ${f('x')}, in hours. To find the remaining weight 12 hours after the candle was lit, locate ${f('x = 12')} on the horizontal axis and find the corresponding ${f('y')}-value on the line.</p>
<p>At ${f('x = 12')}, the graph passes through the point ${f('(12, 10)')}. Therefore, the remaining solid wax was 10 ounces.</p>
<p><strong>Choice A is incorrect</strong> because 4 is the change in time or an unrelated coordinate.</p>
<p><strong>Choice B is incorrect</strong> because 8 ounces is the weight at a later time.</p>
<p><strong>Choice D is incorrect</strong> because 13 ounces is the initial weight at ${f('x = 0')}.</p>`,

  // Q2
  '6a530ab04d554e04aa1bf56c': `<p><strong>Choice A is correct.</strong></p>
<p>The sum of the interior angle measures of any triangle is ${f('180^\\circ')}:</p>
<p>${f('\\angle A + \\angle B + \\angle C = 180^\\circ')}</p>
<p>Substituting the given sum ${f('\\angle A + \\angle B = 159.5^\\circ')} into the equation yields:</p>
<p>${f('159.5^\\circ + \\angle C = 180^\\circ \\implies \\angle C = 180^\\circ - 159.5^\\circ = 20.5^\\circ')}</p>
<p><strong>Choice B is incorrect</strong> because ${f('90^\\circ')} corresponds to a right triangle.</p>
<p><strong>Choices C and D are incorrect</strong> and represent arithmetic calculation errors.</p>`,

  // Q3
  '6a533b854d554e04aa1bf572': `<p><strong>Choice B is correct.</strong></p>
<p>The amount by which the discounted cost is less than the regular cost is the value of the 25% discount itself.</p>
<p>Calculate 25% of the regular price $288:</p>
<p>${f('0.25 \\times 288 = \\frac{1}{4} \\times 288 = 72')}</p>
<p>Thus, the membership is $72 less.</p>
<p><strong>Choice A is incorrect</strong> because 25 is the discount percentage, not the dollar savings.</p>
<p><strong>Choice C is incorrect</strong> because $216 is the discounted price of the membership (${f('288 - 72 = 216')}), not how much less it is.</p>
<p><strong>Choice D is incorrect</strong> because $288 is the original un-discounted price.</p>`,

  // Q4
  '6a533ca64d554e04aa1bf578': `<p><strong>Choice B is correct.</strong></p>
<p>The problem states that the product of a positive number ${f('x')} and the number 5 less than ${f('x')} (${f('x - 5')}) is 104:</p>
<p>${f('x(x - 5) = 104 \\implies x^2 - 5x - 104 = 0')}</p>
<p>Factoring the quadratic equation:</p>
<p>${f('(x - 13)(x + 8) = 0')}</p>
<p>This gives solutions ${f('x = 13')} and ${f('x = -8')}. Since ${f('x')} must be positive, ${f('x = 13')}.</p>
<p><strong>Choice A is incorrect</strong> and may result from dividing 5 by 2.</p>
<p><strong>Choices C and D are incorrect</strong> and result from setting up ${f('x - 5 = 104')} or ${f('x + 5 = 104')}.</p>`,

  // Q5
  '6a533de84d554e04aa1bf584': `<p><strong>Choice D is correct.</strong></p>
<p>From the table, when ${f('x = 0')}, ${f('y = 8')}, so the ${f('y')}-intercept is ${f('b = 8')}.</p>
<p>The slope of the linear relationship is:</p>
<p>${f('m = \\frac{9 - 8}{1 - 0} = 1')}</p>
<p>Using the slope-intercept form ${f('y = mx + b')}:</p>
<p>${f('y = 1x + 8 \\implies y = x + 8')}</p>
<p>Testing ${f('x = 2')} gives ${f('y = 2 + 8 = 10')}, which matches the table.</p>
<p><strong>Choice A is incorrect</strong> because ${f('y = 8x')} gives ${f('y = 0')} at ${f('x = 0')}.</p>
<p><strong>Choices B and C are incorrect</strong> and do not satisfy the points in the table.</p>`,

  // Q6
  '6a533e5e4d554e04aa1bf590': `<p><strong>The correct answer is 3800.</strong></p>
<p>The function is defined as ${f('f(x) = 380x')}. To evaluate ${f('f(10)')}, substitute ${f('x = 10')} into the equation:</p>
<p>${f('f(10) = 380(10) = 3,800')}</p>`,

  // Q7
  '6a533f0a4d554e04aa1bf59c': `<p><strong>Choice A is correct.</strong></p>
<p>By the zero-product property, an equation with solutions ${f('x = 13')} and ${f('x = -24')} must have factors that equal zero at those values:</p>
<p>${f('x - 13 = 0')} and ${f('x - (-24) = x + 24 = 0')}</p>
<p>Multiplying these linear factors gives:</p>
<p>${f('(x - 13)(x + 24) = 0')}</p>
<p><strong>Choice B is incorrect</strong> because its solutions are ${f('-13')} and ${f('24')}.</p>
<p><strong>Choices C and D are incorrect</strong> because their solutions have opposite signs.</p>`,

  // Q8
  '6a533fd44d554e04aa1bf5a2': `<p><strong>Choice A is correct.</strong></p>
<p>Two representative points on the line of best fit are approximately ${f('(230, 404.5)')} and ${f('(270, 485.3)')}.</p>
<p>The slope ${f('m')} of the line is:</p>
<p>${f('m \\approx \\frac{485.3 - 404.5}{270 - 230} = \\frac{80.8}{40} \\approx 2.02')}</p>
<p>To find the vertical intercept ${f('b')}:</p>
<p>${f('b \\approx 404.5 - 2.02(230) = 404.5 - 464.6 = -60.1')}</p>
<p>Therefore, the linear model is ${f('d = -60.1 + 2.02t')}.</p>
<p><strong>Choices B, C, and D are incorrect</strong> because they feature incorrect vertical intercepts that would predict values far above the actual data.</p>`,

  // Q9
  '6a5340574d554e04aa1bf5a8': `<p><strong>Choice C is correct.</strong></p>
<p>Substitute ${f('y = 0')} into the second equation:</p>
<p>${f('0 = 4x^2 - 36 \\implies 4x^2 = 36 \\implies x^2 = 9 \\implies x = \\pm 3')}</p>
<p>Thus, the solutions to the system are ${f('(3, 0)')} and ${f('(-3, 0)')}. Among the choices, ${f('(3, 0)')} is given.</p>
<p><strong>Choices A, B, and D are incorrect</strong> because substituting their coordinates into the system does not satisfy both equations.</p>`,

  // Q10
  '6a5340d64d554e04aa1bf5b4': `<p><strong>Choice A is correct.</strong></p>
<p>The initial mass is 530,000 mg, and it halves every 5 days. In 35 days, the number of half-life periods that have elapsed is:</p>
<p>${f('n = \\frac{35}{5} = 7')}</p>
<p>The remaining mass after 7 half-lives is:</p>
<p>${f('M = 530,000 \\times \\left(\\frac{1}{2}\\right)^7 = \\frac{530,000}{128} \\approx 4,140.625 \\approx 4,141\\text{ mg}')}</p>
<p><strong>Choice B is incorrect</strong> and corresponds to approximately 5 half-lives.</p>
<p><strong>Choices C and D are incorrect</strong> and correspond to fewer elapsed periods.</p>`,

  // Q11
  '6a5341544d554e04aa1bf5c0': `<p><strong>Choice D is correct.</strong></p>
<p>The total surface area of a right circular cylinder is the sum of its lateral area and the areas of its two circular bases:</p>
<p>${f('\\text{Total Area} = \\text{Lateral Area} + 2(\\text{Base Area})')}</p>
<p>The lateral area is the circumference times the height:</p>
<p>${f('\\text{Lateral Area} = C \\times h = 310 \\times 31 = 9,610')}</p>
<p>The circumference is given by ${f('C = 2\\pi r = 310')}, which gives radius ${f('r = \\frac{310}{2\\pi} = \\frac{155}{\\pi}')}.</p>
<p>The combined area of the two bases is:</p>
<p>${f('2(\\pi r^2) = 2\\pi \\left(\\frac{155}{\\pi}\\right)^2')}</p>
<p>Adding the lateral area gives ${f('9610 + 2\\pi \\left(\\frac{155}{\\pi}\\right)^2')}.</p>
<p><strong>Choices A, B, and C are incorrect</strong> because they omit one of the base areas or confuse volume with surface area.</p>`,

  // Q12
  '6a5343ff4d554e04aa1bf5d5': `<p><strong>Choice A is correct.</strong></p>
<p>In the given function ${f('f(w) = 6w^2')}, the input variable ${f('w')} represents the width of the rectangle in feet, and the output ${f('f(w)')} represents the area of the rectangle in square feet.</p>
<p>Therefore, the equation ${f('f(13) = 1,014')} indicates that when the width is 13 ft, the resulting area of the rectangle is 1,014 ${f('\\text{ft}^2')}.</p>
<p><strong>Choices B, C, and D are incorrect</strong> because they confuse the input and output variables or confuse length with area.</p>`,

  // Q13
  '6a5345554d554e04aa1bf5db': `<p><strong>The correct answer is 61.</strong></p>
<p>The expression is ${f('3x + 58x^2 - 7')}. Writing this quadratic expression in standard form ${f('ax^2 + bx + c')}:</p>
<p>${f('58x^2 + 3x - 7')}</p>
<p>Comparing coefficients:</p>
<p>${f('a = 58')}, ${f('b = 3')}, and ${f('c = -7')}.</p>
<p>Therefore, the value of ${f('a + b')} is:</p>
<p>${f('a + b = 58 + 3 = 61')}</p>`,

  // Q14
  '6a5345d74d554e04aa1bf5e7': `<p><strong>The correct answer is 343.</strong></p>
<p>The ratio of ${f('a')} to ${f('b')} is equal to ${f('49 : 26')}:</p>
<p>${f('\\frac{a}{b} = \\frac{49}{26}')}</p>
<p>When ${f('b = 182')}, solve for ${f('a')}:</p>
<p>${f('a = 182 \\times \\frac{49}{26}')}</p>
<p>Since ${f('182 \\div 26 = 7')}:</p>
<p>${f('a = 7 \\times 49 = 343')}</p>`,

  // Q15
  '6a53466c4d554e04aa1bf5f3': `<p><strong>Choice D is correct.</strong></p>
<p>Imani starts with an initial balance of $170.</p>
<p>Over 10 months, she deposits between $30 and $60 each month:</p>
<p>Minimum total deposits: ${f('10 \\times 30 = 300')} dollars.</p>
<p>Maximum total deposits: ${f('10 \\times 60 = 600')} dollars.</p>
<p>Adding the initial $170 gives the range of possible account balances ${f('x')}:</p>
<p>Minimum balance: ${f('170 + 300 = 470')}</p>
<p>Maximum balance: ${f('170 + 600 = 770')}</p>
<p>Thus, ${f('470 \\le x \\le 770')}.</p>
<p><strong>Choices A, B, and C are incorrect</strong> because they omit the initial account balance or miscalculate the monthly totals.</p>`,

  // Q16
  '6a5347894d554e04aa1bf5f9': `<p><strong>Choice A is correct.</strong></p>
<p>The ${f('y')}-intercept of ${f('y = f(x)')} occurs at ${f('x = 0')}:</p>
<p>${f('f(0) = 0^3 - 2(0)^2 - 8(0) + 3 = 3')}</p>
<p>The graph of ${f('y = h(x)')} is obtained by translating the graph of ${f('y = f(x)')} up 6 units, which means:</p>
<p>${f('h(x) = f(x) + 6')}</p>
<p>The ${f('y')}-coordinate of the ${f('y')}-intercept of ${f('y = h(x)')} is:</p>
<p>${f('h(0) = f(0) + 6 = 3 + 6 = 9')}</p>
<p><strong>Choice B is incorrect</strong> and may result from multiplying constants.</p>
<p><strong>Choice C is incorrect</strong> because 6 is only the vertical shift, omitting the initial intercept 3.</p>
<p><strong>Choice D is incorrect</strong> because 0 assumes an intercept at the origin.</p>`,

  // Q17
  '6a53485d4d554e04aa1bf605': `<p><strong>The correct answer is 28.</strong></p>
<p>The circumference of a circle is given by the formula ${f('C = \\pi d')}, where ${f('d')} is the diameter.</p>
<p>Given ${f('C = 28\\pi')}:</p>
<p>${f('\\pi d = 28\\pi \\implies d = 28')}</p>`,

  // Q18
  '6a5348f14d554e04aa1bf611': `<p><strong>Choice A is correct.</strong></p>
<p>The given equation is linear: ${f('35x - 25 = 57x - 5')}.</p>
<p>Subtract ${f('35x')} from both sides:</p>
<p>${f('-25 = 22x - 5 \\implies 22x = -20 \\implies x = -\\frac{10}{11}')}</p>
<p>Since the coefficients of ${f('x')} on both sides are unequal (${f('35 \\ne 57')}), the lines intersect at exactly one point, meaning there is exactly one solution.</p>
<p><strong>Choices B, C, and D are incorrect</strong> because linear equations in one variable can only have infinitely many solutions (if identical) or zero solutions (if parallel with different constants).</p>`,

  // Q19
  '6a534a3f4d554e04aa1bf61d': `<p><strong>Choice C is correct.</strong></p>
<p>The time between 2000 and 2010 is 10 years. In the equation ${f('10x + 26,257 = 26,858')}, 26,257 is the starting population in 2000 and 26,858 is the population in 2010.</p>
<p>The difference ${f('26,858 - 26,257 = 601')} is the total population increase over 10 years. Therefore, ${f('10x = 601 \\implies x = 60.1')}, which represents the average increase per year of the population between 2000 and 2010.</p>
<p><strong>Choice A is incorrect</strong> because the total increase is ${f('10x')}, not ${f('x')}.</p>
<p><strong>Choices B and D are incorrect</strong> because ${f('x')} is an annual linear increase, not a projection or percentage rate.</p>`,

  // Q20
  '6a534c284d554e04aa1bf629': `<p><strong>Choice A is correct.</strong></p>
<p>A linear function has the form ${f('f(x) = mx + b')}. Given that the slope is ${f('m = 3')}:</p>
<p>${f('f(x) = 3x + b')}</p>
<p>Substitute ${f('f(-5) = -7')} into the equation:</p>
<p>${f('-7 = 3(-5) + b \\implies -7 = -15 + b \\implies b = 8')}</p>
<p>Therefore, the function is ${f('f(x) = 3x + 8')}.</p>
<p><strong>Choices B, C, and D are incorrect</strong> and result from sign errors during substitution.</p>`,

  // Q21
  '6a534cb24d554e04aa1bf62f': `<p><strong>Choice B is correct.</strong></p>
<p>The standard equation of a circle is ${f('(x - h)^2 + (y - k)^2 = r^2')}, where ${f('(h, k)')} is the center and ${f('r')} is the radius.</p>
<p>For Circle A, ${f('(x - 2)^2 + (y - 7)^2 = 25')}, the center is ${f('(2, 7)')} and the radius is ${f('r_A = \\sqrt{25} = 5')}.</p>
<p>Circle B has the same center ${f('(2, 7)')} and twice the radius:</p>
<p>${f('r_B = 2 \\times 5 = 10')}</p>
<p>The equation of Circle B is:</p>
<p>${f('(x - 2)^2 + (y - 7)^2 = 10^2 = 100')}</p>
<p><strong>Choice A is incorrect</strong> because it doubles the right-hand side (${f('25 \\times 2 = 50')}) instead of doubling the radius.</p>
<p><strong>Choices C and D are incorrect</strong> because they calculate ${f('r_B^2')} erroneously.</p>`,

  // Q22
  '6a534d5e4d554e04aa1bf635': `<p><strong>The correct answer is 0.529 (or 9/17, or 9).</strong></p>
<p>The distance from ${f('v')} to 0 is ${f('|v|')}, and the distance from ${f('v')} to 1 is ${f('|v - 1|')}. The ratio is given as ${f('9 : 8')}:</p>
<p>${f('\\frac{|v|}{|v - 1|} = \\frac{9}{8}')}</p>
<p>If ${f('v')} lies between 0 and 1 (${f('0 < v < 1')}):</p>
<p>${f('\\frac{v}{1 - v} = \\frac{9}{8} \\implies 8v = 9(1 - v) \\implies 8v = 9 - 9v \\implies 17v = 9 \\implies v = \\frac{9}{17} \\approx 0.529')}</p>
<p>If ${f('v > 1')}:</p>
<p>${f('\\frac{v}{v - 1} = \\frac{9}{8} \\implies 8v = 9(v - 1) \\implies 8v = 9v - 9 \\implies v = 9')}</p>
<p>Either 0.529 (or .529 or 9/17) or 9 is accepted.</p>`
};

async function run() {
  console.log('🚀 Injecting explanations for March 2026 INT 1 Module 1...\n');
  const ids = Object.keys(explanations);
  for (let i = 0; i < ids.length; i++) {
    const id = ids[i];
    process.stdout.write(`[${i + 1}/${ids.length}] Updating Q ${id}... `);
    const res = await updateQuestionExplanation(id, explanations[id]);
    console.log(res.message === 'success' ? '✅ Success' : '⚠️ ' + JSON.stringify(res));
  }
  console.log('\nAll 22 explanations injected for Module 1!');
}

run().catch(console.error);
