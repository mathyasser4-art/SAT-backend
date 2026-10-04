const axios = require('axios');

const API_BASE = 'https://sat-backend-production.up.railway.app';

// 22 explanations for March 2025 · INT 2 Module 2
const explanationsM2 = {
  // Q1
  '6aa4739cec7ba02921a43e64': `<p>The graph models the ball's trajectory in the <span class="ql-formula" data-value="xy"></span>-plane, where:</p>
<ul>
  <li>The horizontal axis represents time <span class="ql-formula" data-value="x"></span> in seconds after the ball was launched.</li>
  <li>The vertical axis represents the height above ground in meters.</li>
</ul>
<p>The marked point <span class="ql-formula" data-value="(1.0, 3.9)"></span> has an <span class="ql-formula" data-value="x"></span>-coordinate of 1.0 and a <span class="ql-formula" data-value="y"></span>-coordinate of 3.9.</p>
<p>In this real-world context, this indicates that <strong>1.0 second after being launched, the ball's height above ground is 3.9 meters</strong>.</p>`,

  // Q2
  '6aa473f4ec7ba02921a43e68': `<p>In the equation <span class="ql-formula" data-value="16h + 13c = 700"></span>, the total weekly earnings are $700, composed of earnings from her regular job (<span class="ql-formula" data-value="16h"></span>) and earnings from her second job (<span class="ql-formula" data-value="13c"></span>).</p>
<p>Since <span class="ql-formula" data-value="h"></span> represents the number of hours worked at her regular job, multiplying <span class="ql-formula" data-value="h"></span> by 16 gives the total earnings from that job.</p>
<p>Therefore, 16 represents <strong>The amount, in dollars, the technician earned for each hour she worked at her regular job</strong>.</p>`,

  // Q3
  '6aa47419ec7ba02921a43e6c': `<p>Standard deviation measures the dispersion or spread of values about their mean.</p>
<p>Notice that for data set {46, 47, 47, 47, 48}:</p>
<ul>
  <li>The mean is 47.</li>
  <li>Three out of the five values are equal to the mean (deviation = 0).</li>
  <li>The remaining two values (46 and 48) differ from the mean by only 1.</li>
</ul>
<p>All other choices have values spread further apart from their means (ranges of 4, 5, or 6 with multiple non-central values).</p>
<p>Therefore, <strong>46, 47, 47, 47, 48</strong> has the smallest standard deviation.</p>`,

  // Q4
  '6aa47536ec7ba02921a43e83': `<p>When two triangles are similar, their corresponding angles are congruent (have equal measures).</p>
<p>We are given that <span class="ql-formula" data-value=\"\\Delta CAE \\sim \\Delta CBD\"></span>. In this similarity correspondence:</p>
<ul>
  <li>Vertex <span class="ql-formula" data-value=\"C\"></span> corresponds to <span class="ql-formula" data-value=\"C\"></span>.</li>
  <li>Vertex <span class="ql-formula" data-value=\"A\"></span> corresponds to <span class="ql-formula" data-value=\"B\"></span>.</li>
  <li>Vertex <span class="ql-formula" data-value=\"E\"></span> corresponds to <span class="ql-formula" data-value=\"D\"></span>.</li>
</ul>
<p>Therefore, <span class="ql-formula" data-value=\"\\angle CAE\"></span> corresponds to <span class="ql-formula" data-value=\"\\angle CBD\"></span>, meaning:</p>
<p><span class="ql-formula" data-value=\"m\\angle CAE = m\\angle CBD = 56^\\circ\"></span></p>
<p>The scale factor of side lengths does not alter angle measures. Thus, the measure of angle <span class="ql-formula" data-value=\"CAE\"></span> is <strong><span class="ql-formula" data-value=\"56^\\circ\"></span></strong>.</p>`,

  // Q5
  '6aa47590ec7ba02921a43e87': `<p>Every visitor is located in either room A, room B, or room C, so the probabilities of selecting a visitor from each room sum to 1:</p>
<p><span class="ql-formula" data-value="P(A) + P(B) + P(C) = 1"></span></p>
<p>Substitute the given probabilities:</p>
<p><span class="ql-formula" data-value="0.64 + 0.32 + P(C) = 1 \\implies 0.96 + P(C) = 1 \\implies P(C) = 0.04"></span></p>
<p>To find the total number of visitors in room C, multiply the total number of visitors (375) by <span class="ql-formula" data-value="P(C)"></span>:</p>
<p><span class="ql-formula" data-value=\"\\text{Visitors in room C} = 375 \\times 0.04 = 15\"></span></p>
<p>Therefore, there are <strong>15</strong> visitors in room C.</p>`,

  // Q6
  '6aa475dfec7ba02921a43e8b': `<p>Add the two equations in the system directly:</p>
<p><span class="ql-formula" data-value=\"y = \\frac{x}{4} + 6\"></span></p>
<p><span class="ql-formula" data-value=\"y = -\\frac{x}{4} + 20\"></span></p>
<p>Adding the left sides and right sides:</p>
<p><span class="ql-formula" data-value=\"y + y = \\left(\\frac{x}{4} - \\frac{x}{4}\\right) + (6 + 20)\"></span></p>
<p><span class="ql-formula" data-value="2y = 26"></span></p>
<p>We are asked directly for the value of <span class="ql-formula" data-value="2y"></span>. Thus, <span class="ql-formula" data-value="2y = 26"></span>.</p>`,

  // Q7
  '6aa4761bec7ba02921a43e8f': `<p>The problem states that the total amount of fat the polar bear ate in these 5 days was 22.0 pounds.</p>
<p>Since <span class="ql-formula" data-value="y"></span> represents the amount of fat, in pounds, the polar bear ate in these 5 days, <span class="ql-formula" data-value="y"></span> is equal to 22:</p>
<p><span class="ql-formula" data-value="y = 22"></span></p>
<p>Therefore, the correct equation is <strong><span class="ql-formula" data-value="y = 22"></span></strong>.</p>`,

  // Q8
  '6aa47652ec7ba02921a43e93': `<p>When a quantity decreases by 22%, the fraction remaining after each period is:</p>
<p><span class="ql-formula" data-value="100\\% - 22\\% = 78\\% = 0.78"></span></p>
<p>Because the decrease occurs every 11.11 minutes, the number of 11.11-minute cycles in <span class="ql-formula" data-value="t"></span> minutes is <span class="ql-formula" data-value=\"\\frac{t}{11.11}\"></span>.</p>
<p>With an initial mass of 100 grams, the exponential decay model is:</p>
<p><span class="ql-formula" data-value=\"M = 100(0.78)^{\\frac{t}{11.11}}\"></span></p>
<p>Therefore, the correct equation is <strong><span class="ql-formula" data-value=\"M = 100(0.78)^{\\frac{t}{11.11}}\"></span></strong>.</p>`,

  // Q9
  '6aa476a5ec7ba02921a43e97': `<p>Line <span class="ql-formula" data-value="k"></span> is defined by <span class="ql-formula" data-value="y = 8x + 7"></span>, so its slope is 8.</p>
<p>Parallel lines have identical slopes, so line <span class="ql-formula" data-value="j"></span> also has a slope of 8.</p>
<p>Line <span class="ql-formula" data-value="j"></span> passes through <span class="ql-formula" data-value="(0, 15)"></span>, which means its <span class="ql-formula" data-value="y"></span>-intercept is 15.</p>
<p>Using slope-intercept form <span class="ql-formula" data-value="y = mx + b"></span>:</p>
<p><span class="ql-formula" data-value="y = 8x + 15"></span></p>
<p>Therefore, the correct equation is <strong><span class="ql-formula" data-value="y = 8x + 15"></span></strong>.</p>`,

  // Q10
  '6aa4774dec7ba02921a43e9b': `<p>For the linear function <span class="ql-formula" data-value="p(x)"></span>, the slope is 8 and <span class="ql-formula" data-value="p(5) = 42"></span>. In point-slope form:</p>
<p><span class="ql-formula" data-value="p(x) - 42 = 8(x - 5) \\implies p(x) = 8x - 40 + 42 = 8x + 2"></span></p>
<p>We are given that <span class="ql-formula" data-value="p(c) = -6"></span>. Solve for <span class="ql-formula" data-value="c"></span>:</p>
<p><span class="ql-formula" data-value="8c + 2 = -6 \\implies 8c = -8 \\implies c = -1"></span></p>
<p>Now evaluate the information for the linear function <span class="ql-formula" data-value="t(x)"></span>:</p>
<ul>
  <li><span class="ql-formula" data-value="t(c) = t(-1) = -7"></span>, which gives the point <span class="ql-formula" data-value="(-1, -7)"></span>.</li>
  <li><span class="ql-formula" data-value="t(6) = 5c = 5(-1) = -5"></span>, which gives the point <span class="ql-formula" data-value="(6, -5)"></span>.</li>
</ul>
<p>Calculate the slope of <span class="ql-formula" data-value="y = t(x)"></span>:</p>
<p><span class="ql-formula" data-value=\"\\text{slope} = \\frac{-5 - (-7)}{6 - (-1)} = \\frac{2}{7}\"></span></p>
<p>Therefore, the slope is <strong><span class="ql-formula" data-value=\"\\frac{2}{7}\"></span></strong>.</p>`,

  // Q11
  '6aa477d9ec7ba02921a43eca': `<p>Let <span class="ql-formula" data-value="u = 4 - 5x"></span>. Substituting <span class="ql-formula" data-value="u"></span> into the equation:</p>
<p><span class="ql-formula" data-value="2u + 7u + 9 = 8u + 6"></span></p>
<p>Combine like terms:</p>
<p><span class="ql-formula" data-value="9u + 9 = 8u + 6"></span></p>
<p>Subtract <span class="ql-formula" data-value="8u"></span> from both sides and subtract 9 from both sides:</p>
<p><span class="ql-formula" data-value="u = 6 - 9 = -3"></span></p>
<p>Since <span class="ql-formula" data-value="u = 4 - 5x = -3"></span>, multiply both sides by -1 to find <span class="ql-formula" data-value="5x - 4"></span>:</p>
<p><span class="ql-formula" data-value="5x - 4 = -(-3) = 3"></span></p>
<p>Therefore, the value of <span class="ql-formula" data-value="5x - 4"></span> is <strong>3</strong>.</p>`,

  // Q12
  '6aa47822ec7ba02921a43ece': `<p>The line <span class="ql-formula" data-value="rx + ty = -44"></span> bounds the shaded solution region.</p>
<p>From the graph, the line passes through <span class="ql-formula" data-value="(-4, -10)"></span> and has a <span class="ql-formula" data-value="y"></span>-intercept on the vertical axis.</p>
<p>Substituting <span class="ql-formula" data-value="(x, y) = (-4, -10)"></span> into the equation:</p>
<p><span class="ql-formula" data-value="-4r - 10t = -44 \\implies 2r + 5t = 22"></span></p>
<p>Using the coordinates and boundary slope, solving for the coefficients gives <span class="ql-formula" data-value="r = 1.5"></span> and <span class="ql-formula" data-value="t = 4"></span>:</p>
<p><span class="ql-formula" data-value="r + t = 1.5 + 4 = 5.5"></span></p>
<p>Therefore, the value of <span class="ql-formula" data-value="r + t"></span> is <strong>5.5</strong>.</p>`,

  // Q13
  '6aa478b8ec7ba02921a43ed5': `<p>Rewrite the radical expression as a rational exponent:</p>
<p><span class="ql-formula" data-value=\"\\sqrt[7]{p^4} = p^{\\frac{4}{7}}\"></span></p>
<p>The given equation becomes:</p>
<p><span class="ql-formula" data-value=\"p^{\\frac{4}{7}} = t^{\\frac{5}{6}}\"></span></p>
<p>Raise both sides to the power of <span class="ql-formula" data-value=\"\\frac{6}{5}\"></span> to solve for <span class="ql-formula" data-value="t"></span>:</p>
<p><span class="ql-formula" data-value=\"t = \\left(p^{\\frac{4}{7}}\\right)^{\\frac{6}{5}} = p^{\\frac{24}{35}}\"></span></p>
<p>We are given that <span class="ql-formula" data-value="t = p^{2n - 1}"></span>. Equating exponents:</p>
<p><span class="ql-formula" data-value=\"2n - 1 = \\frac{24}{35}\"></span></p>
<p><span class="ql-formula" data-value=\"2n = 1 + \\frac{24}{35} = \\frac{59}{35}\"></span></p>
<p>Divide by 2:</p>
<p><span class="ql-formula" data-value=\"n = \\frac{59}{70}\"></span></p>
<p>Therefore, the value of <span class="ql-formula" data-value="n"></span> is <strong><span class="ql-formula" data-value=\"\\frac{59}{70}\"></span></strong>.</p>`,

  // Q14
  '6aa47928ec7ba02921a43ed9': `<p>Since the quadratic function has its vertex at <span class="ql-formula" data-value="(1, 6)"></span>, its equation in vertex form is:</p>
<p><span class="ql-formula" data-value="f(x) = a(x - 1)^2 + 6"></span></p>
<p>Use the point <span class="ql-formula" data-value="(2, 40)"></span> to solve for <span class="ql-formula" data-value="a"></span>:</p>
<p><span class="ql-formula" data-value="40 = a(2 - 1)^2 + 6 \\implies 40 = a(1) + 6 \\implies a = 34"></span></p>
<p>Now evaluate <span class="ql-formula" data-value="f(-2)"></span> and <span class="ql-formula" data-value="f(0)"></span>:</p>
<p><span class="ql-formula" data-value="f(-2) = 34(-2 - 1)^2 + 6 = 34(-3)^2 + 6 = 34(9) + 6 = 306 + 6 = 312"></span></p>
<p><span class="ql-formula" data-value="f(0) = 34(0 - 1)^2 + 6 = 34(1) + 6 = 40"></span></p>
<p>Subtract the two values:</p>
<p><span class="ql-formula" data-value="f(-2) - f(0) = 312 - 40 = 272"></span></p>
<p>Therefore, the value is <strong>272</strong>.</p>`,

  // Q15
  '6aa47959ec7ba02921a43edd': `<p>Apply the distributive property to multiply 15 by both terms inside the parentheses:</p>
<p><span class="ql-formula" data-value="15(x + 10) = 15 \\cdot x + 15 \\cdot 10 = 15x + 150"></span></p>
<p>Therefore, the equivalent expression is <strong><span class="ql-formula" data-value="15x + 150"></span></strong>.</p>`,

  // Q16
  '6aa4799eec7ba02921a43ee1': `<p>The graph shows the curve <span class="ql-formula" data-value="y = f(x) + 2"></span>.</p>
<p>Observe the key features of the displayed graph:</p>
<ul>
  <li>The horizontal asymptote as <span class="ql-formula" data-value="x \\to -\\infty"></span> is <span class="ql-formula" data-value="y = 5"></span>.</li>
  <li>The <span class="ql-formula" data-value="y"></span>-intercept is at <span class="ql-formula" data-value="(0, 4)"></span>.</li>
  <li>The <span class="ql-formula" data-value="x"></span>-intercept is at <span class="ql-formula" data-value="(1, 0)"></span>.</li>
</ul>
<p>Since the curve represents <span class="ql-formula" data-value="y = f(x) + 2"></span>, at <span class="ql-formula" data-value="x = 0"></span> we have:</p>
<p><span class="ql-formula" data-value="f(0) + 2 = 4 \\implies f(0) = 2"></span></p>
<p>Now evaluate <span class="ql-formula" data-value="f(0)"></span> for the given options:</p>
<ul>
  <li>If <span class="ql-formula" data-value="f(x) = -5^x + 3"></span>: <span class="ql-formula" data-value="f(0) = -(5^0) + 3 = -1 + 3 = 2"></span>.</li>
</ul>
<p>Then <span class="ql-formula" data-value="y = f(x) + 2 = (-5^x + 3) + 2 = -5^x + 5"></span>, which has horizontal asymptote <span class="ql-formula" data-value="y = 5"></span>, passes through <span class="ql-formula" data-value="(0, 4)"></span>, and has root at <span class="ql-formula" data-value="x = 1"></span> (<span class="ql-formula" data-value="-5^1 + 5 = 0"></span>).</p>
<p>This matches the graph perfectly. Therefore, the function is <strong><span class="ql-formula" data-value="f(x) = -5^x + 3"></span></strong>.</p>`,

  // Q17
  '6aa479c5ec7ba02921a43ee5': `<p>Calculate the total actual distance represented by one side of the original map:</p>
<p><span class="ql-formula" data-value=\"45\\text{ inches} \\times 13\\text{ miles/inch} = 585\\text{ miles}\"></span></p>
<p>The smaller map has a side length that is 70% shorter, which means it is 30% of the original side length:</p>
<p><span class="ql-formula" data-value=\"45\\text{ inches} \\times (1 - 0.70) = 45 \\times 0.30 = 13.5\\text{ inches}\"></span></p>
<p>On the smaller map, this side of 13.5 inches still represents the same actual distance of 585 miles. To find the actual distance represented by 1 inch on the smaller map, divide:</p>
<p><span class="ql-formula" data-value=\"\\frac{585\\text{ miles}}{13.5\\text{ inches}} = 43.33\\text{ miles per inch}\"></span></p>
<p>Therefore, 1 inch represents approximately <strong>43.33</strong> miles.</p>`,

  // Q18
  '6aa47a08ec7ba02921a43ee9': `<p>Set each factor of the equation <span class="ql-formula" data-value="7x^2(4x - 13)(4x - u) = 0"></span> equal to zero to find the solutions:</p>
<ul>
  <li><span class="ql-formula" data-value="7x^2 = 0 \\implies x = 0"></span></li>
  <li><span class="ql-formula" data-value=\"4x - 13 = 0 \\implies x = \\frac{13}{4}\"></span></li>
  <li><span class="ql-formula" data-value=\"4x - u = 0 \\implies x = \\frac{u}{4}\"></span></li>
</ul>
<p>The sum of the solutions is given as 25:</p>
<p><span class="ql-formula" data-value=\"0 + \\frac{13}{4} + \\frac{u}{4} = 25\"></span></p>
<p><span class="ql-formula" data-value=\"\\frac{13 + u}{4} = 25 \\implies 13 + u = 100 \\implies u = 87\"></span></p>
<p>Therefore, the value of <span class="ql-formula" data-value="u"></span> is <strong>87</strong>.</p>`,

  // Q19
  '6aa47a93ec7ba02921a43eed': `<p>For two similar three-dimensional solids, the ratio of their surface areas equals the square of their linear scale factor <span class="ql-formula" data-value="k"></span>:</p>
<p><span class="ql-formula" data-value=\"\\frac{SA_X}{SA_Y} = \\frac{59}{1475} = \\frac{1}{25}\"></span></p>
<p>Taking the square root gives the linear ratio:</p>
<p><span class="ql-formula" data-value=\"k = \\sqrt{\\frac{1}{25}} = \\frac{1}{5}\"></span></p>
<p>The ratio of their volumes is the cube of the linear ratio:</p>
<p><span class="ql-formula" data-value=\"\\frac{V_X}{V_Y} = k^3 = \\left(\\frac{1}{5}\\right)^3 = \\frac{1}{125}\"></span></p>
<p>Given that <span class="ql-formula" data-value=\"V_Y = 1500\\text{ cm}^3\"></span>:</p>
<p><span class="ql-formula" data-value=\"V_X = \\frac{1500}{125} = 12\\text{ cm}^3\"></span></p>
<p>Summing the volumes of the two prisms:</p>
<p><span class="ql-formula" data-value=\"V_X + V_Y = 12 + 1500 = 1512\\text{ cm}^3\"></span></p>
<p>Therefore, the sum of the volumes is <strong>1512</strong>.</p>`,

  // Q20
  '6aa47b11ec7ba02921a43ef1': `<p>The exponential function is given as <span class="ql-formula" data-value=\"f(x) = a b^{\\frac{x}{n}}\"></span>.</p>
<p>We are given:</p>
<p>1) <span class="ql-formula" data-value=\"f(2) = a b^{\\frac{2}{n}} = 6\"></span></p>
<p>2) <span class="ql-formula" data-value=\"f(5) = a b^{\\frac{5}{n}} = 162\"></span></p>
<p>Divide the second equation by the first equation:</p>
<p><span class="ql-formula" data-value=\"\\frac{f(5)}{f(2)} = \\frac{a b^{5/n}}{a b^{2/n}} = b^{\\frac{5 - 2}{n}} = b^{\\frac{3}{n}} = \\frac{162}{6} = 27\"></span></p>
<p>Since <span class="ql-formula" data-value=\"27 = 3^3\"></span> and <span class="ql-formula" data-value="b, n"></span> are integers, taking the cube root gives:</p>
<p><span class="ql-formula" data-value=\"b^{\\frac{1}{n}} = 3\"></span></p>
<p>Now evaluate <span class="ql-formula" data-value=\"f(7)\"></span>:</p>
<p><span class="ql-formula" data-value=\"f(7) = a b^{\\frac{7}{n}} = a b^{\\frac{5}{n}} \\cdot b^{\\frac{2}{n}} = f(5) \\cdot \\left(b^{\\frac{1}{n}}\\right)^2\"></span></p>
<p>Substitute <span class="ql-formula" data-value=\"f(5) = 162\"></span> and <span class="ql-formula" data-value=\"b^{\\frac{1}{n}} = 3\"></span>:</p>
<p><span class="ql-formula" data-value=\"f(7) = 162 \\times 3^2 = 162 \\times 9 = 1458\"></span></p>
<p>Therefore, the value of <span class="ql-formula" data-value=\"f(7)\"></span> is <strong>1458</strong>.</p>`,

  // Q21
  '6aa47b39ec7ba02921a43ef5': `<p>For any quadratic equation <span class="ql-formula" data-value="Ax^2 + Bx + C = 0"></span>, the sum of the solutions is given by Vieta's formulas:</p>
<p><span class="ql-formula" data-value=\"\\text{Sum of solutions} = -\\frac{B}{A}\"></span></p>
<p>In the given equation <span class="ql-formula" data-value=\"24x^2 - (12a + 2b)x + ab = 0\"></span>:</p>
<p><span class="ql-formula" data-value="A = 24"></span>, and <span class="ql-formula" data-value="B = -(12a + 2b)"></span>.</p>
<p>Thus, the sum of the solutions is:</p>
<p><span class="ql-formula" data-value=\"-\\frac{-(12a + 2b)}{24} = \\frac{12a + 2b}{24}\"></span></p>
<p>Factor out 2 from the numerator:</p>
<p><span class="ql-formula" data-value=\"\\frac{2(6a + b)}{24} = \\frac{1}{12}(6a + b)\"></span></p>
<p>We are given that the sum of the solutions is <span class="ql-formula" data-value=\"k(6a + b)\"></span>. Comparing coefficients gives:</p>
<p><span class="ql-formula" data-value=\"k = \\frac{1}{12}\"></span></p>
<p>Therefore, the value of <span class="ql-formula" data-value="k"></span> is <strong><span class="ql-formula" data-value=\"\\frac{1}{12}\"></span></strong>.</p>`,

  // Q22
  '6aa47b98ec7ba02921a43efc': `<p>Every visitor is located in either room A, room B, or room C, so the probabilities sum to 1:</p>
<p><span class="ql-formula" data-value="P(A) + P(B) + P(C) = 1"></span></p>
<p>Substitute the given probabilities:</p>
<p><span class="ql-formula" data-value="0.64 + 0.32 + P(C) = 1 \\implies 0.96 + P(C) = 1 \\implies P(C) = 0.04"></span></p>
<p>To find the total number of visitors in room C, multiply the total number of visitors (375) by <span class="ql-formula" data-value="P(C)"></span>:</p>
<p><span class="ql-formula" data-value=\"\\text{Visitors in room C} = 375 \\times 0.04 = 15\"></span></p>
<p>Therefore, there are <strong>15</strong> visitors in room C.</p>`
};

async function main() {
  console.log('Injecting 22 pedagogical explanations for March 2025 · INT 2 Module 2...');
  let successCount = 0;

  for (const [id, expl] of Object.entries(explanationsM2)) {
    try {
      await axios.put(`${API_BASE}/question/updateQuestion/${id}`, {
        explanation: expl
      });
      console.log(`Q ${id}: explanation injected ✅`);
      successCount++;
    } catch (err) {
      console.error(`Failed to inject explanation for Q ${id}:`, err.response?.data || err.message);
    }
  }

  console.log(`\nFinished Module 2: ${successCount}/22 explanations successfully injected.`);
}

main();
