const axios = require('axios');

const API_BASE = 'https://sat-backend-production.up.railway.app';

// 22 explanations for March 2025 · INT 1 Module 1
const explanationsM1 = {
  // Q1
  '6aa0f3fbdf63ca493d4799fd': `<p>To find the cost for the manufacturer to make 50 rings, locate 50 on the horizontal axis (Number of rings made) and determine the corresponding value on the vertical axis (Cost in dollars).</p>
<p>From the graph, the line passes through the points (0, 100) and (50, 175). When the number of rings made is 50, the cost is <strong>175</strong> dollars.</p>
<p>Therefore, the correct choice is <strong>175</strong>.</p>`,

  // Q2
  '6aa0f439df63ca493d479a03': `<p>To find the equivalent expression, distribute 9 to both terms inside the parentheses:</p>
<p><span class="ql-formula" data-value="9(x^2 + 6) = 9 \\cdot x^2 + 9 \\cdot 6 = 9x^2 + 54"></span></p>
<p>Therefore, the equivalent expression is <strong><span class="ql-formula" data-value="9x^2 + 54"></span></strong>.</p>`,

  // Q3
  '6aa0f5cfdf63ca493d479a0b': `<p>The solution to a system of two linear equations in the <span class="ql-formula" data-value="xy"></span>-plane is the point of intersection of their graphs.</p>
<p>Since the solution is given as <span class="ql-formula" data-value="(5, 5)"></span>, the graphs of the two lines must intersect precisely at the point <span class="ql-formula" data-value="(5, 5)"></span>.</p>
<p>Therefore, the correct description is <strong>A graph showing two lines that intersect at (5, 5)</strong>.</p>`,

  // Q4
  '6aa0f5e4df63ca493d479a11': `<p>A linear equation in one variable has infinitely many solutions if both sides are identical for all values of <span class="ql-formula" data-value="x"></span> (an identity).</p>
<p>The given equation is:</p>
<p><span class="ql-formula" data-value="7x + 21 = 7x + k"></span></p>
<p>Subtracting <span class="ql-formula" data-value="7x"></span> from both sides gives:</p>
<p><span class="ql-formula" data-value="21 = k"></span></p>
<p>For the equation to be true for all values of <span class="ql-formula" data-value="x"></span>, the constant term <span class="ql-formula" data-value="k"></span> must equal <strong>21</strong>.</p>`,

  // Q5
  '6aa0f630df63ca493d479a17': `<p>The <span class="ql-formula" data-value="y"></span>-intercept of the graph of <span class="ql-formula" data-value="y = f(x)"></span> occurs where <span class="ql-formula" data-value="x = 0"></span>.</p>
<p>Substitute <span class="ql-formula" data-value="x = 0"></span> into the given function:</p>
<p><span class="ql-formula" data-value="f(0) = 2(0) - \\frac{1}{4} = -\\frac{1}{4}"></span></p>
<p>Thus, the coordinates of the <span class="ql-formula" data-value="y"></span>-intercept are <strong><span class="ql-formula" data-value=\"(0, -\\frac{1}{4})\"></span></strong>.</p>`,

  // Q6
  '6aa0f647df63ca493d479a1d': `<p>The mean of a data set is the sum of all values divided by the number of values.</p>
<p>Summing the masses of the 5 ruffed lemurs:</p>
<p><span class="ql-formula" data-value="3810 + 3810 + 3530 + 3850 + 3550 = 18550"></span></p>
<p>Divide the sum by 5:</p>
<p><span class="ql-formula" data-value=\"\\frac{18550}{5} = 3710\"></span></p>
<p>Therefore, the mean mass is <strong>3710</strong> grams.</p>`,

  // Q7
  '6aa0f687df63ca493d479a23': `<p>The percent increase is calculated using the formula:</p>
<p><span class="ql-formula" data-value=\"\\text{Percent Increase} = \\frac{\\text{New Value} - \\text{Original Value}}{\\text{Original Value}} \\times 100\\%\"></span></p>
<p>Substituting the given values:</p>
<p><span class="ql-formula" data-value=\"\\text{Percent Increase} = \\frac{80 - 16}{16} \\times 100\\% = \\frac{64}{16} \\times 100\\% = 4 \\times 100\\% = 400\\%\"></span></p>
<p>Therefore, the percent increase in the price is <strong>400%</strong>.</p>`,

  // Q8
  '6aa0f6dedf63ca493d479a29': `<p>In similar triangles, corresponding angles are congruent (have equal measures).</p>
<p>We are given that <span class="ql-formula" data-value=\"\\Delta CAE \\sim \\Delta CBD\"></span>. In this similarity correspondence, vertex <span class="ql-formula" data-value=\"C\"></span> corresponds to <span class="ql-formula" data-value=\"C\"></span>, vertex <span class="ql-formula" data-value=\"A\"></span> corresponds to <span class="ql-formula" data-value=\"B\"></span>, and vertex <span class="ql-formula" data-value=\"E\"></span> corresponds to <span class="ql-formula" data-value=\"D\"></span>.</p>
<p>Therefore, <span class="ql-formula" data-value=\"\\angle CAE\"></span> corresponds to <span class="ql-formula" data-value=\"\\angle CBD\"></span>, which means:</p>
<p><span class="ql-formula" data-value=\"m\\angle CAE = m\\angle CBD = 59^\\circ\"></span></p>
<p>The scale factor of side lengths does not affect angle measures. Thus, the measure of angle <span class="ql-formula" data-value=\"CAE\"></span> is <strong><span class="ql-formula" data-value=\"59^\\circ\"></span></strong>.</p>`,

  // Q9
  '6aa0f716df63ca493d479a2f': `<p>The student already collected 30 signatures on Monday and collects an additional <span class="ql-formula" data-value="s"></span> signatures on Tuesday.</p>
<p>The total number of signatures collected is <span class="ql-formula" data-value="s + 30"></span>.</p>
<p>The phrase "at least 190" means the total must be greater than or equal to 190:</p>
<p><span class="ql-formula" data-value="s + 30 \\ge 190"></span></p>
<p>Therefore, the inequality is <strong><span class="ql-formula" data-value="s + 30 \\ge 190"></span></strong>.</p>`,

  // Q10
  '6aa0f75bdf63ca493d479a35': `<p>To factor the expression <span class="ql-formula" data-value="7x^6 - 14x^2"></span>, find the greatest common factor (GCF) of the two terms:</p>
<p>The greatest common numerical factor of 7 and 14 is 7. The highest common power of <span class="ql-formula" data-value="x"></span> is <span class="ql-formula" data-value="x^2"></span>. So the GCF is <span class="ql-formula" data-value="7x^2"></span>.</p>
<p>Factoring out <span class="ql-formula" data-value="7x^2"></span>:</p>
<p><span class="ql-formula" data-value="7x^6 - 14x^2 = 7x^2(x^4 - 2)"></span></p>
<p>Therefore, the equivalent expression is <strong><span class="ql-formula" data-value="7x^2(x^4 - 2)"></span></strong>.</p>`,

  // Q11
  '6aa0fd2ddf63ca493d479a52': `<p>The equation is <span class="ql-formula" data-value="y = 53x^2"></span> for <span class="ql-formula" data-value="x \\ge 0"></span>, where <span class="ql-formula" data-value="x"></span> represents the radius and <span class="ql-formula" data-value="y"></span> represents the volume.</p>
<p>This is a quadratic equation with a positive leading coefficient (53) and vertex at <span class="ql-formula" data-value="(0, 0)"></span>. For <span class="ql-formula" data-value="x \\ge 0"></span>, the graph starts at the origin <span class="ql-formula" data-value="(0, 0)"></span> and curves upward with increasing steepness (concave up).</p>
<p>Graph A correctly depicts this upward-curving parabola passing through <span class="ql-formula" data-value="(0, 0)"></span>.</p>
<p>Therefore, the correct choice is <strong>graph A</strong>.</p>`,

  // Q12
  '6aa0fd58df63ca493d479a58': `<p>Rearrange the quadratic equation into standard form <span class="ql-formula" data-value="ax^2 + bx + c = 0"></span>:</p>
<p><span class="ql-formula" data-value="8x^2 + 13x - 6 = 0"></span></p>
<p>Factor the quadratic expression by grouping. We need two numbers that multiply to <span class="ql-formula" data-value="8 \\times (-6) = -48"></span> and add to 13. These numbers are 16 and -3:</p>
<p><span class="ql-formula" data-value="8x^2 + 16x - 3x - 6 = 0"></span></p>
<p><span class="ql-formula" data-value="8x(x + 2) - 3(x + 2) = 0"></span></p>
<p><span class="ql-formula" data-value="(8x - 3)(x + 2) = 0"></span></p>
<p>This gives solutions:</p>
<p><span class="ql-formula" data-value="8x - 3 = 0 \\implies x = \\frac{3}{8}"></span>, or <span class="ql-formula" data-value="x + 2 = 0 \\implies x = -2"></span>.</p>
<p>Since we are asked for the positive solution, the answer is <strong><span class="ql-formula" data-value=\"\\frac{3}{8}\"></span></strong> (or 0.375).</p>`,

  // Q13
  '6aa0fd88df63ca493d479a5e': `<p>When a quantity changes by a constant percentage per unit of time, it is modeled by an <strong>exponential function</strong>.</p>
<p>Because the money increases by 2.7% each year, the growth factor is <span class="ql-formula" data-value="1 + 0.027 = 1.027 > 1"></span>, meaning the account balance increases over time.</p>
<p>Therefore, the model that best describes this situation is an <strong>Increasing exponential</strong> model.</p>`,

  // Q14
  '6aa0fe0ddf63ca493d479a64': `<p>In any right triangle where the acute angles are <span class="ql-formula" data-value="R"></span> and <span class="ql-formula" data-value="S"></span>, the two angles are complementary (<span class="ql-formula" data-value="R + S = 90^\\circ"></span>).</p>
<p>By the complementary angle identity for sine and cosine:</p>
<p><span class="ql-formula" data-value=\"\\cos(S) = \\sin(90^\\circ - S) = \\sin(R)\"></span></p>
<p>We are given that <span class="ql-formula" data-value=\"\\sin(R) = \\frac{2\\sqrt{10}}{7}\"></span>. Therefore:</p>
<p><span class="ql-formula" data-value=\"\\cos(S) = \\frac{2\\sqrt{10}}{7}\"></span></p>
<p>Thus, the correct answer is <strong><span class="ql-formula" data-value=\"\\frac{2\\sqrt{10}}{7}\"></span></strong>.</p>`,

  // Q15
  '6aa0fe45df63ca493d479a6a': `<p>The given equation for line <span class="ql-formula" data-value="t"></span> is <span class="ql-formula" data-value=\"y = -\\frac{1}{2}x + 14\"></span>, which is in slope-intercept form <span class="ql-formula" data-value="y = mx + b"></span> with slope <span class="ql-formula" data-value=\"m_t = -\\frac{1}{2}\"></span>.</p>
<p>Two lines are perpendicular if and only if their slopes are negative reciprocals of each other:</p>
<p><span class="ql-formula" data-value=\"m_s = -\\frac{1}{m_t} = -\\frac{1}{-\\frac{1}{2}} = 2\"></span></p>
<p>Therefore, the slope of line <span class="ql-formula" data-value="s"></span> is <strong>2</strong>.</p>`,

  // Q16
  '6aa0fe92df63ca493d479a70': `<p>Evaluate the given exponential function <span class="ql-formula" data-value=\"f(x) = 8(2)^{\\frac{x}{4}}\"></span> for the values in the table:</p>
<ul>
  <li>For <span class="ql-formula" data-value="x = -4"></span>: <span class="ql-formula" data-value=\"f(-4) = 8(2)^{-4/4} = 8(2)^{-1} = 8 \\cdot \\frac{1}{2} = 4\"></span></li>
  <li>For <span class="ql-formula" data-value="x = 0"></span>: <span class="ql-formula" data-value=\"f(0) = 8(2)^{0} = 8 \\cdot 1 = 8\"></span></li>
  <li>For <span class="ql-formula" data-value="x = 4"></span>: <span class="ql-formula" data-value=\"f(4) = 8(2)^{4/4} = 8(2)^1 = 16\"></span></li>
  <li>For <span class="ql-formula" data-value="x = 8"></span>: <span class="ql-formula" data-value=\"f(8) = 8(2)^{8/4} = 8(2)^2 = 8 \\cdot 4 = 32\"></span></li>
</ul>
<p>The table with values <span class="ql-formula" data-value=\"(-4, 4), (0, 8), (4, 16), (8, 32)\"></span> is the correct table.</p>`,

  // Q17
  '6aa0fed4febc2d2509387a64': `<p>To find <span class="ql-formula" data-value=\"\\cos\\left(\\frac{3\\pi}{4}\\right)\"></span>, note that the angle <span class="ql-formula" data-value=\"\\frac{3\\pi}{4}\"></span> lies in Quadrant II.</p>
<p>The reference angle is <span class="ql-formula" data-value=\"\\pi - \\frac{3\\pi}{4} = \\frac{\\pi}{4}\"></span>.</p>
<p>In Quadrant II, cosine is negative:</p>
<p><span class="ql-formula" data-value=\"\\cos\\left(\\frac{3\\pi}{4}\\right) = -\\cos\\left(\\frac{\\pi}{4}\\right) = -\\frac{\\sqrt{2}}{2}\"></span></p>
<p>Therefore, the value is <strong><span class="ql-formula" data-value=\"-\\frac{\\sqrt{2}}{2}\"></span></strong>.</p>`,

  // Q18
  '6aa0feedfebc2d2509387a6a': `<p>We are given the system of linear equations:</p>
<p>1) <span class="ql-formula" data-value="6x + 7y = 2170"></span></p>
<p>2) <span class="ql-formula" data-value="24x - 28y = 1400"></span></p>
<p>Multiply equation (1) by 4 to eliminate <span class="ql-formula" data-value="y"></span>:</p>
<p><span class="ql-formula" data-value="4(6x + 7y) = 4(2170) \\implies 24x + 28y = 8680"></span></p>
<p>Now add this to equation (2):</p>
<p><span class="ql-formula" data-value="(24x + 28y) + (24x - 28y) = 8680 + 1400"></span></p>
<p><span class="ql-formula" data-value="48x = 10080 \\implies x = \\frac{10080}{48} = 210"></span></p>
<p>Substitute <span class="ql-formula" data-value="x = 210"></span> back into equation (1):</p>
<p><span class="ql-formula" data-value="6(210) + 7y = 2170"></span></p>
<p><span class="ql-formula" data-value="1260 + 7y = 2170 \\implies 7y = 910 \\implies y = 130"></span></p>
<p>Now find the value of <span class="ql-formula" data-value="x + y"></span>:</p>
<p><span class="ql-formula" data-value="x + y = 210 + 130 = 340"></span></p>
<p>Therefore, the value of <span class="ql-formula" data-value="x + y"></span> is <strong>340</strong>.</p>`,

  // Q19
  '6aa0ff2bfebc2d2509387a70': `<p>When a quantity decreases by 23%, the remaining percentage is:</p>
<p><span class="ql-formula" data-value="100\\% - 23\\% = 77\\% = 0.77"></span></p>
<p>The decay occurs every 11.69 minutes, so after <span class="ql-formula" data-value="t"></span> minutes, the number of 11.69-minute periods that have passed is <span class="ql-formula" data-value=\"\\frac{t}{11.69}\"></span>.</p>
<p>Thus, the general exponential decay model with initial mass 100 is:</p>
<p><span class="ql-formula" data-value=\"M = 100(0.77)^{\\frac{t}{11.69}}\"></span></p>
<p>Therefore, the correct equation is <strong><span class="ql-formula" data-value=\"M = 100(0.77)^{\\frac{t}{11.69}}\"></span></strong>.</p>`,

  // Q20
  '6aa0ff77febc2d2509387a76': `<p>Isolate the absolute value term in the equation <span class="ql-formula" data-value="-4|5x + 4| + 2 = -14"></span>:</p>
<p>Subtract 2 from both sides:</p>
<p><span class="ql-formula" data-value="-4|5x + 4| = -16"></span></p>
<p>Divide by -4:</p>
<p><span class="ql-formula" data-value="|5x + 4| = 4"></span></p>
<p>This gives two linear cases:</p>
<p><strong>Case 1:</strong></p>
<p><span class="ql-formula" data-value="5x + 4 = 4 \\implies 5x = 0 \\implies x = 0"></span></p>
<p><strong>Case 2:</strong></p>
<p><span class="ql-formula" data-value=\"5x + 4 = -4 \\implies 5x = -8 \\implies x = -\\frac{8}{5}\"></span></p>
<p>Therefore, all solutions to the equation are <strong><span class="ql-formula" data-value=\"0, -\\frac{8}{5}\"></span></strong>.</p>`,

  // Q21
  '6aa10008febc2d2509387a81': `<p>In a right circular cone, the height <span class="ql-formula" data-value="h"></span>, the radius of the base <span class="ql-formula" data-value="r"></span>, and the slant height from the apex <span class="ql-formula" data-value="A"></span> to a point <span class="ql-formula" data-value="B"></span> on the circumference form a right triangle:</p>
<p><span class="ql-formula" data-value="r^2 + h^2 = AB^2"></span></p>
<p>Given <span class="ql-formula" data-value="h = 42"></span> cm and <span class="ql-formula" data-value="AB = 84"></span> cm:</p>
<p><span class="ql-formula" data-value="r^2 + 42^2 = 84^2"></span></p>
<p><span class="ql-formula" data-value="r^2 = 84^2 - 42^2 = 7056 - 1764 = 5292"></span></p>
<p>The volume <span class="ql-formula" data-value="V"></span> of a right circular cone is given by:</p>
<p><span class="ql-formula" data-value=\"V = \\frac{1}{3}\\pi r^2 h\"></span></p>
<p>Substitute <span class="ql-formula" data-value="r^2 = 5292"></span> and <span class="ql-formula" data-value="h = 42"></span>:</p>
<p><span class="ql-formula" data-value=\"V = \\frac{1}{3}\\pi (5292)(42) = \\pi (5292)(14) = 74088\\pi\"></span></p>
<p>Since the volume is given as <span class="ql-formula" data-value="k\\pi"></span>, the value of <span class="ql-formula" data-value="k"></span> is <strong>74088</strong>.</p>`,

  // Q22
  '6aa10070febc2d2509387a87': `<p>To convert cubic yards to cubic meters, use the linear conversion factor <span class="ql-formula" data-value="1\\text{ yard} = 0.914\\text{ meter}"></span>.</p>
<p>The volume conversion factor is the cube of the linear conversion factor:</p>
<p><span class="ql-formula" data-value=\"1\\text{ yd}^3 = (0.914\\text{ m})^3 = 0.763511144\\text{ m}^3\"></span></p>
<p>Multiply the given volume of 247 cubic yards by this factor:</p>
<p><span class="ql-formula" data-value=\"V = 247 \\times (0.914)^3 = 247 \\times 0.763511144 \\approx 188.58725\\text{ m}^3\"></span></p>
<p>Rounding to the nearest tenth gives <strong>188.6</strong>.</p>`
};

async function main() {
  console.log('Injecting 22 pedagogical explanations for March 2025 · INT 1 Module 1...');
  let successCount = 0;

  for (const [id, explanation] of Object.entries(explanationsM1)) {
    try {
      await axios.put(`${API_BASE}/question/updateQuestion/${id}`, {
        explanation: explanation
      });
      console.log(`Q ${id}: explanation injected ✅`);
      successCount++;
    } catch (err) {
      console.error(`Failed to inject explanation for Q ${id}:`, err.response?.data || err.message);
    }
  }

  console.log(`\nFinished Module 1: ${successCount}/22 explanations successfully injected.`);
}

main();
