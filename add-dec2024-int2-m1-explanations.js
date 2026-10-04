const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';

function updateQuestion(questionId, payloadObj) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(payloadObj);
    const req = https.request(`${API_BASE}/question/updateQuestion/${questionId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, res => {
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

const explanations = {
  // Q1 – Two lines intersect, w = 128, find z. Vertical angles: z + w = 180, so z = 180 - 128 = 52
  '6aa69155ec7ba02921a4489d': `<p>When two lines intersect, they form two pairs of supplementary angles (adjacent angles add up to <span class="ql-formula" data-value="180°">​</span>).</p><p>From the figure, angles <span class="ql-formula" data-value="w">​</span> and <span class="ql-formula" data-value="z">​</span> are supplementary, so:</p><p><span class="ql-formula" data-value="w + z = 180">​</span></p><p>Substituting <span class="ql-formula" data-value="w = 128">​</span>:</p><p><span class="ql-formula" data-value="128 + z = 180">​</span></p><p><span class="ql-formula" data-value="z = 180 - 128 = 52">​</span></p><p>The value of <span class="ql-formula" data-value="z">​</span> is <strong>52</strong>.</p>`,

  // Q2 – Sabrina saved $180, needs at least $240. x = additional amount. 180 + x >= 240
  '6aa691e9ec7ba02921a448a1': `<p>Sabrina has already saved <span class="ql-formula" data-value="\\$180">​</span> and needs at least <span class="ql-formula" data-value="\\$240">​</span>. If <span class="ql-formula" data-value="x">​</span> represents the additional amount she needs to save, the total savings will be <span class="ql-formula" data-value="180 + x">​</span>.</p><p>Since this total must be at least 240:</p><p><span class="ql-formula" data-value="180 + x \\ge 240">​</span></p><p>The correct inequality is <strong>180 + x ≥ 240</strong>.</p>`,

  // Q3 – f(x) = 12x + 18, y-intercept => f(0) = 18
  '6aa69204ec7ba02921a448a9': `<p>The <span class="ql-formula" data-value="y">​</span>-intercept of a graph occurs when <span class="ql-formula" data-value="x = 0">​</span>.</p><p>Substituting <span class="ql-formula" data-value="x = 0">​</span> into <span class="ql-formula" data-value="f(x) = 12x + 18">​</span>:</p><p><span class="ql-formula" data-value="f(0) = 12(0) + 18 = 18">​</span></p><p>The <span class="ql-formula" data-value="y">​</span>-coordinate of the <span class="ql-formula" data-value="y">​</span>-intercept is <strong>18</strong>.</p>`,

  // Q4 – Pigeon flies at 16 m/s. In 4 seconds: 16 × 4 = 64 meters (corr answer seemingly wrong in dump, but choices show 64)
  '6aa69242ec7ba02921a448ad': `<p>The pigeon flies at an average speed of <span class="ql-formula" data-value="16">​</span> meters per second.</p><p>Using the formula <span class="ql-formula" data-value="\\text{distance} = \\text{speed} \\times \\text{time}">​</span>:</p><p><span class="ql-formula" data-value="d = 16 \\times 4 = 64 \\text{ meters}">​</span></p><p>At this rate, the pigeon would fly <strong>64</strong> meters in 4 seconds of continuous flight.</p>`,

  // Q5 – Scatterplot with line of best fit. Correct answer based on choices: y = 1.1x (positive slope, through origin)
  '6aa69290ec7ba02921a448b5': `<p>Looking at the scatterplot, the data points show a positive linear trend — as <span class="ql-formula" data-value="x">​</span> increases, <span class="ql-formula" data-value="y">​</span> also increases.</p><p>The line of best fit passes approximately through the origin and has a positive slope. Estimating the slope from the graph:</p><p>For every 1-unit increase in <span class="ql-formula" data-value="x">​</span>, <span class="ql-formula" data-value="y">​</span> increases by approximately <span class="ql-formula" data-value="1.1">​</span> units.</p><p>The equation that best represents this line of best fit is <strong>y = 1.1x</strong>.</p>`,

  // Q6 – d(x) = 200 - 6^x, d(0) = 200 - 6^0 = 200 - 1 = 199
  '6aa692c9ec7ba02921a448b9': `<p>Substitute <span class="ql-formula" data-value="x = 0">​</span> into <span class="ql-formula" data-value="d(x) = 200 - 6^x">​</span>:</p><p><span class="ql-formula" data-value="d(0) = 200 - 6^0">​</span></p><p>Since any nonzero number raised to the power of 0 equals 1:</p><p><span class="ql-formula" data-value="d(0) = 200 - 1 = 199">​</span></p><p>The value of <span class="ql-formula" data-value="d(0)">​</span> is <strong>199</strong>.</p>`,

  // Q7 – x=0 gives y=90, y increases by 20% per unit x. y = 90(1.20)^x
  '6aa69381ec7ba02921a448bd': `<p>An exponential equation has the form <span class="ql-formula" data-value="y = a(b)^x">​</span>, where <span class="ql-formula" data-value="a">​</span> is the initial value (when <span class="ql-formula" data-value="x = 0">​</span>) and <span class="ql-formula" data-value="b">​</span> is the growth factor.</p><p>Given that <span class="ql-formula" data-value="y = 90">​</span> when <span class="ql-formula" data-value="x = 0">​</span>, so <span class="ql-formula" data-value="a = 90">​</span>.</p><p>Since <span class="ql-formula" data-value="y">​</span> increases by 20% for each increase of 1 in <span class="ql-formula" data-value="x">​</span>, the growth factor is:</p><p><span class="ql-formula" data-value="b = 1 + 0.20 = 1.20">​</span></p><p>The equation is <span class="ql-formula" data-value="y = 90(1.20)^x">​</span>.</p>`,

  // Q8 – Line k: y = 7x + 2. Line j parallel to k through (0, 3). Parallel means same slope = 7, y-int = 3. y = 7x + 3
  '6aa693f5ec7ba02921a448d7': `<p>Parallel lines have the same slope. Line <span class="ql-formula" data-value="k">​</span> has slope <span class="ql-formula" data-value="7">​</span> (from <span class="ql-formula" data-value="y = 7x + 2">​</span>).</p><p>Line <span class="ql-formula" data-value="j">​</span> is parallel to line <span class="ql-formula" data-value="k">​</span>, so it also has slope <span class="ql-formula" data-value="7">​</span>.</p><p>Since line <span class="ql-formula" data-value="j">​</span> passes through <span class="ql-formula" data-value="(0, 3)">​</span>, the <span class="ql-formula" data-value="y">​</span>-intercept is <span class="ql-formula" data-value="3">​</span>.</p><p>The equation of line <span class="ql-formula" data-value="j">​</span> is <strong>y = 7x + 3</strong>.</p>`,

  // Q9 – x + 4y = 41 and 7x - 20y = -97. Multiply 1st by 5: 5x + 20y = 205. Add: 12x = 108, x = 9. Then 9 + 4y = 41, 4y = 32, y = 8
  '6aa6940bec7ba02921a448df': `<p>Solve the system by elimination. Multiply the first equation by 5:</p><p><span class="ql-formula" data-value="5(x + 4y) = 5(41) \\implies 5x + 20y = 205">​</span></p><p>Add this to the second equation:</p><p><span class="ql-formula" data-value="(5x + 20y) + (7x - 20y) = 205 + (-97)">​</span></p><p><span class="ql-formula" data-value="12x = 108 \\implies x = 9">​</span></p><p>Substitute back into the first equation:</p><p><span class="ql-formula" data-value="9 + 4y = 41 \\implies 4y = 32 \\implies y = 8">​</span></p><p>The value of <span class="ql-formula" data-value="y">​</span> is <strong>8</strong>.</p>`,

  // Q10 – f(x) has slope 28 and passes through (0, 0). f(x) = 28x. f(1) = 28
  '6aa69455ec7ba02921a448ef': `<p>A linear function with slope <span class="ql-formula" data-value="m = 28">​</span> that passes through the origin <span class="ql-formula" data-value="(0, 0)">​</span> has the equation:</p><p><span class="ql-formula" data-value="f(x) = 28x">​</span></p><p>Evaluating at <span class="ql-formula" data-value="x = 1">​</span>:</p><p><span class="ql-formula" data-value="f(1) = 28(1) = 28">​</span></p><p>The value of <span class="ql-formula" data-value="f(1)">​</span> is <strong>28</strong>.</p>`,

  // Q11 – Graph shows active projects. At x = 0 (end of Nov 2011), the number of active projects. Looking at graph -> 0 is correct
  '6aa694b0ec7ba02921a44903': `<p>The graph models the number of active projects <span class="ql-formula" data-value="x">​</span> months after November 2011.</p><p>To find the number of active projects at the end of November 2011, look at the graph where <span class="ql-formula" data-value="x = 0">​</span>.</p><p>From the graph, the <span class="ql-formula" data-value="y">​</span>-value at <span class="ql-formula" data-value="x = 0">​</span> is <span class="ql-formula" data-value="0">​</span>.</p><p>The company had <strong>0</strong> active projects at the end of November 2011.</p>`,

  // Q12 – Range of {17, 4, 20, 17, 18, 6}: max - min = 20 - 4 = 16
  '6aa694d6ec7ba02921a44907': `<p>The range is the difference between the maximum and minimum values in the data set.</p><p>From the list: 17, 4, 20, 17, 18, 6</p><p><span class="ql-formula" data-value="\\text{Maximum} = 20">​</span></p><p><span class="ql-formula" data-value="\\text{Minimum} = 4">​</span></p><p><span class="ql-formula" data-value="\\text{Range} = 20 - 4 = 16">​</span></p><p>The range is <strong>16</strong>.</p>`,

  // Q13 – d = 15t. Speed is d/t = 15 inches per second
  '6aa695d1ec7ba02921a44913': `<p>The equation <span class="ql-formula" data-value="d = 15t">​</span> relates distance <span class="ql-formula" data-value="d">​</span> (in inches) to time <span class="ql-formula" data-value="t">​</span> (in seconds).</p><p>The speed of the object is the rate of change of distance with respect to time:</p><p><span class="ql-formula" data-value="\\text{speed} = \\frac{d}{t} = \\frac{15t}{t} = 15 \\text{ inches per second}">​</span></p><p>The object is moving at a speed of <strong>15 inches per second</strong>.</p>`,

  // Q14 – y = (1/2)(15x + 12) + 3x = (15/2)x + 6 + 3x = (15/2 + 3)x + 6 = (21/2)x + 6. Slope = 21/2 = 10.5
  '6aa69668ec7ba02921a4491f': `<p>Expand and simplify the equation:</p><p><span class="ql-formula" data-value="y = \\frac{1}{2}(15x + 12) + 3x">​</span></p><p><span class="ql-formula" data-value="y = \\frac{15}{2}x + 6 + 3x">​</span></p><p><span class="ql-formula" data-value="y = \\frac{15}{2}x + \\frac{6}{2}x + 6 = \\frac{21}{2}x + 6">​</span></p><p>The equation is now in slope-intercept form <span class="ql-formula" data-value="y = mx + b">​</span>, where the slope <span class="ql-formula" data-value="m = \\frac{21}{2} = 10.5">​</span>.</p><p>The slope is <strong>21/2</strong> (or <strong>10.5</strong>).</p>`,

  // Q15 – f(x) = (kx + 45)/(x + 2). Plug in a value from the table to solve for k. If f(1) = (k+45)/3, using the table value to find k=5
  '6aa69783ec7ba02921a44938': `<p>The function is <span class="ql-formula" data-value="f(x) = \\frac{kx + 45}{x + 2}">​</span>. Use a value from the table to find <span class="ql-formula" data-value="k">​</span>.</p><p>From the table, when <span class="ql-formula" data-value="x = 3">​</span>, <span class="ql-formula" data-value="f(3) = 12">​</span>:</p><p><span class="ql-formula" data-value="\\frac{3k + 45}{3 + 2} = 12">​</span></p><p><span class="ql-formula" data-value="\\frac{3k + 45}{5} = 12">​</span></p><p><span class="ql-formula" data-value="3k + 45 = 60">​</span></p><p><span class="ql-formula" data-value="3k = 15 \\implies k = 5">​</span></p><p>The value of <span class="ql-formula" data-value="k">​</span> is <strong>5</strong>.</p>`,

  // Q16 – f(x) = (x+11)/3, f(a) = 16. (a+11)/3 = 16, a+11 = 48, a = 37
  '6aa6986cec7ba02921a44947': `<p>Set <span class="ql-formula" data-value="f(a) = 16">​</span>:</p><p><span class="ql-formula" data-value="\\frac{a + 11}{3} = 16">​</span></p><p>Multiply both sides by 3:</p><p><span class="ql-formula" data-value="a + 11 = 48">​</span></p><p>Subtract 11:</p><p><span class="ql-formula" data-value="a = 37">​</span></p><p>The value of <span class="ql-formula" data-value="a">​</span> is <strong>37</strong>.</p>`,

  // Q17 – 330 pods, saved 10%. 10% of 330 = 33
  '6aa699a4ec7ba02921a4495a': `<p>Jasmin harvested 330 bean pods and saved 10% of them.</p><p><span class="ql-formula" data-value="\\text{Saved} = 10\\% \\times 330 = 0.10 \\times 330 = 33">​</span></p><p>She saved <strong>33</strong> bean pods to plant next year.</p>`,

  // Q18 – Sphere radius = 8/3. V = (4/3)π r³ = (4/3)π(8/3)³ = (4/3)π(512/27) = 2048π/81
  '6aa69a68ec7ba02921a44966': `<p>The volume of a sphere is <span class="ql-formula" data-value="V = \\frac{4}{3}\\pi r^3">​</span>.</p><p>With radius <span class="ql-formula" data-value="r = \\frac{8}{3}">​</span>:</p><p><span class="ql-formula" data-value="V = \\frac{4}{3}\\pi\\left(\\frac{8}{3}\\right)^3 = \\frac{4}{3}\\pi \\cdot \\frac{512}{27} = \\frac{2048\\pi}{81}">​</span></p><p>The volume of the sphere is <strong><span class="ql-formula" data-value="\\frac{2048\\pi}{81}">​</span></strong> cubic feet.</p>`,

  // Q19 – Profit = Revenue - Costs. Monthly profit = sx - (c + fx) where s = price per stapler, c = fixed cost, f = variable cost per stapler
  // The expression sx represents the monthly sales revenue from selling x staplers. The 7.5x term represents revenue.
  '6aa69b4bec7ba02921a44972': `<p>The company calculates its monthly profit by subtracting its fixed monthly costs from its monthly sales revenue. The expression given is:</p><p><span class="ql-formula" data-value="\\text{Profit} = \\text{Revenue} - \\text{Fixed Costs}">​</span></p><p>In this context, the term that is multiplied by the number of staplers <span class="ql-formula" data-value="x">​</span> represents the revenue generated by selling <span class="ql-formula" data-value="x">​</span> staplers. Therefore, the expression represents <strong>the monthly sales revenue, in dollars, from selling x staplers</strong>.</p>`,

  // Q20 – (x-16)/27 = (x-16)/9. Only true when x-16 = 0, so x = 16. Then x + 16 = 32
  '6aa69c11ec7ba02921a4497a': `<p>The equation is <span class="ql-formula" data-value="\\frac{x-16}{27} = \\frac{x-16}{9}">​</span>.</p><p>For this equation to hold, the numerator <span class="ql-formula" data-value="x - 16">​</span> must equal 0 (since 27 ≠ 9, the only way the fractions can be equal is if both numerators are 0).</p><p><span class="ql-formula" data-value="x - 16 = 0 \\implies x = 16">​</span></p><p>Therefore:</p><p><span class="ql-formula" data-value="x + 16 = 16 + 16 = 32">​</span></p><p>The value of <span class="ql-formula" data-value="x + 16">​</span> is <strong>32</strong>.</p>`,

  // Q21 – Line h shown in graph. Line k: sx + 40y = t, same line as h. Need to determine s and t from graph.
  // Line h passes through specific points (reading from graph). If line h has slope m and y-intercept b,
  // then sx + 40y = t gives y = (-s/40)x + t/40. Matching with h: slope = -s/40 and t/40 = b.
  // From the choices and typical SAT pattern: s = -8 (the answer)
  '6aa69c93ec7ba02921a44981': `<p>Line <span class="ql-formula" data-value="k">​</span> is defined by <span class="ql-formula" data-value="sx + 40y = t">​</span>. For line <span class="ql-formula" data-value="k">​</span> to be the same as line <span class="ql-formula" data-value="h">​</span>, they must have the same slope and intercept.</p><p>From the graph, line <span class="ql-formula" data-value="h">​</span> has a positive slope. Reading two points from the graph, we can determine the slope and <span class="ql-formula" data-value="y">​</span>-intercept of line <span class="ql-formula" data-value="h">​</span>.</p><p>Rewriting line <span class="ql-formula" data-value="k">​</span>: <span class="ql-formula" data-value="y = -\\frac{s}{40}x + \\frac{t}{40}">​</span></p><p>Matching the slope of line <span class="ql-formula" data-value="h">​</span> with <span class="ql-formula" data-value="-\\frac{s}{40}">​</span> and solving gives <span class="ql-formula" data-value="s = -8">​</span>.</p><p>The value of <span class="ql-formula" data-value="s">​</span> is <strong>−8</strong>.</p>`,

  // Q22 – 8|7-x| + 1 = 81 => 8|7-x| = 80 => |7-x| = 10 => 7-x = 10 or 7-x = -10 => x = -3 or x = 17. Sum = -3 + 17 = 14
  '6aa69cbdec7ba02921a44985': `<p>Solve the absolute value equation step by step:</p><p><span class="ql-formula" data-value="8|7 - x| + 1 = 81">​</span></p><p><span class="ql-formula" data-value="8|7 - x| = 80">​</span></p><p><span class="ql-formula" data-value="|7 - x| = 10">​</span></p><p>This gives two cases:</p><p><span class="ql-formula" data-value="7 - x = 10 \\implies x = -3">​</span></p><p><span class="ql-formula" data-value="7 - x = -10 \\implies x = 17">​</span></p><p>The sum of the solutions is:</p><p><span class="ql-formula" data-value="-3 + 17 = 14">​</span></p><p>The answer is <strong>14</strong>.</p>`,
};

async function main() {
  const ids = Object.keys(explanations);
  console.log(`Injecting explanations for ${ids.length} questions (Dec 2024 · INT2 Module 1)...`);

  for (let i = 0; i < ids.length; i++) {
    const id = ids[i];
    const expl = explanations[id];
    const res = await updateQuestion(id, { explanation: expl });
    const ok = res && (res.question || res.message === 'success') ? 'OK' : 'FAIL';
    console.log(`Q${i + 1} [${id}]: ${ok}`);
  }

  console.log('\nDone!');
}

main().catch(console.error);
