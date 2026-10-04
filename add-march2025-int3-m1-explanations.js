const axios = require('axios');

const API_BASE = 'https://sat-backend-production.up.railway.app';

// 22 explanations for March 2025 · INT 3 Module 1
const explanationsM1 = {
  // Q1
  '6aa47ca1ec7ba02921a43f38': `<p>To find the speed of the car 3 seconds after it began to accelerate, substitute <span class="ql-formula" data-value="t = 3"></span> into the given linear equation:</p>
<p><span class="ql-formula" data-value="s = 40 + 2(3) = 40 + 6 = 46"></span></p>
<p>Therefore, the speed of the car is <strong>46</strong> miles per hour.</p>`,

  // Q2
  '6aa47cdbec7ba02921a43f3c': `<p>Examine the line of best fit in the given scatterplot:</p>
<ul>
  <li>The line has a positive slope (slants upward from left to right), eliminating equations with negative slopes.</li>
  <li>The vertical intercept (<span class="ql-formula" data-value="y"></span>-intercept) is above the origin, at approximately <span class="ql-formula" data-value="y = 0.8"></span>.</li>
  <li>When <span class="ql-formula" data-value="x = 4"></span>, <span class="ql-formula" data-value="y \\approx 0.8 + 1.7(4) = 7.6"></span>, which closely matches the displayed line.</li>
</ul>
<p>Therefore, the equation that best represents the line of best fit is <strong><span class="ql-formula" data-value="y = 0.8 + 1.7x"></span></strong>.</p>`,

  // Q3
  '6aa47d03ec7ba02921a43f40': `<p>The width of the rectangle is given as 5 centimeters.</p>
<p>The length is 30 centimeters longer than the width:</p>
<p><span class="ql-formula" data-value=\"\\text{Length} = 5 + 30 = 35\\text{ cm}\"></span></p>
<p>The area of a rectangle is the product of its length and width:</p>
<p><span class="ql-formula" data-value=\"\\text{Area} = 35 \\times 5 = 175\\text{ cm}^2\"></span></p>
<p>Therefore, the area of the rectangle is <strong>175</strong> square centimeters.</p>`,

  // Q4
  '6aa47d27ec7ba02921a43f44': `<p>Notice the relationship between the given equation <span class="ql-formula" data-value="7 + x = 3"></span> and the expression <span class="ql-formula" data-value="56 + 8x"></span>:</p>
<p><span class="ql-formula" data-value="56 + 8x = 8(7 + x)"></span></p>
<p>Multiply both sides of the given equation by 8:</p>
<p><span class="ql-formula" data-value="8(7 + x) = 8(3) = 24"></span></p>
<p>Therefore, the value of <span class="ql-formula" data-value="56 + 8x"></span> is <strong>24</strong>.</p>`,

  // Q5
  '6aa47d6bec7ba02921a43f48': `<p>In the equation <span class="ql-formula" data-value="20h + 17c = 1055"></span>, the total earnings are $1,055.</p>
<p>Since <span class="ql-formula" data-value="h"></span> represents the number of hours worked at her regular job, the term <span class="ql-formula" data-value="20h"></span> represents her total regular job earnings.</p>
<p>Thus, the coefficient 20 represents <strong>The amount, in dollars, the technician earned for each hour she worked at her regular job</strong>.</p>`,

  // Q6
  '6aa47dafec7ba02921a43f4c': `<p>The table lists values and their frequencies:</p>
<ul>
  <li>Value 20 has frequency 6</li>
  <li>Value 26 has frequency 1</li>
  <li>Value 32 has frequency 6</li>
  <li>Value 38 has frequency 3</li>
</ul>
<p>The values in the data set are 20, 26, 32, and 38. The smallest (minimum) of these values is <strong>20</strong>.</p>`,

  // Q7
  '6aa47dffec7ba02921a43f50': `<p>The mean of a data set is the sum of all values divided by the number of values.</p>
<p>Summing the masses of the 5 ruffed lemurs:</p>
<p><span class="ql-formula" data-value="3810 + 3810 + 3030 + 3850 + 3050 = 17550"></span></p>
<p>Divide the sum by 5:</p>
<p><span class="ql-formula" data-value=\"\\frac{17550}{5} = 3510\"></span></p>
<p>Therefore, the mean mass is <strong>3510</strong> grams.</p>`,

  // Q8
  '6aa47e45ec7ba02921a43f54': `<p>From the first equation, solve for <span class="ql-formula" data-value="x"></span>:</p>
<p><span class="ql-formula" data-value="x + 7 = 13 \\implies x = 6"></span></p>
<p>Substitute <span class="ql-formula" data-value="x = 6"></span> into the second equation:</p>
<p><span class="ql-formula" data-value="y = 5(6^2) + 5 = 5(36) + 5 = 180 + 5 = 185"></span></p>
<p>Therefore, the point of intersection is <strong>(6, 185)</strong>.</p>`,

  // Q9
  '6aa47e74ec7ba02921a43f58': `<p>Combine like terms in the expression:</p>
<p><span class="ql-formula" data-value="19x^5 + 20x^5 - 10x^5 = (19 + 20 - 10)x^5 = 29x^5"></span></p>
<p>Comparing this to <span class="ql-formula" data-value="bx^5"></span> gives:</p>
<p><span class="ql-formula" data-value="b = 29"></span></p>
<p>Therefore, the value of <span class="ql-formula" data-value="b"></span> is <strong>29</strong>.</p>`,

  // Q10
  '6aa47ec1ec7ba02921a43f5c': `<p>The graph shows a line passing through the intercepts <span class="ql-formula" data-value="(-12, 0)"></span> and <span class="ql-formula" data-value="(0, -11)"></span>.</p>
<p>Calculate the slope of the line:</p>
<p><span class="ql-formula" data-value=\"m = \\frac{-11 - 0}{0 - (-12)} = -\\frac{11}{12}\"></span></p>
<p>The equation of the line in slope-intercept form is:</p>
<p><span class="ql-formula" data-value=\"y = -\\frac{11}{12}x - 11\"></span></p>
<p>We are given that the point <span class="ql-formula" data-value="(v, -5)"></span> lies on this line. Substitute <span class="ql-formula" data-value="y = -5"></span> and <span class="ql-formula" data-value="x = v"></span>:</p>
<p><span class="ql-formula" data-value=\"-5 = -\\frac{11}{12}v - 11\"></span></p>
<p>Add 11 to both sides:</p>
<p><span class="ql-formula" data-value=\"6 = -\\frac{11}{12}v \\implies v = 6 \\times \\left(-\\frac{12}{11}\\right) = -\\frac{72}{11}\"></span></p>
<p>Therefore, the value of <span class="ql-formula" data-value="v"></span> is <strong><span class="ql-formula" data-value=\"-\\frac{72}{11}\"></span></strong>.</p>`,

  // Q11
  '6aa47fc5ec7ba02921a43f60': `<p>Two lines cut by a transversal are parallel if and only if corresponding angles are equal.</p>
<p>In the figure, angle <span class="ql-formula" data-value="w"></span> and angle <span class="ql-formula" data-value="y"></span> are corresponding angles formed by the transversal line <span class="ql-formula" data-value="k"></span> intersecting lines <span class="ql-formula" data-value="r"></span> and <span class="ql-formula" data-value="s"></span>.</p>
<p>Given that <span class="ql-formula" data-value="w = 146"></span>, having <span class="ql-formula" data-value="y = 146"></span> proves that corresponding angles are congruent, which is sufficient to establish that line <span class="ql-formula" data-value="r"></span> is parallel to line <span class="ql-formula" data-value="s"></span>.</p>
<p>Therefore, the correct choice is <strong><span class="ql-formula" data-value="y = 146"></span></strong>.</p>`,

  // Q12
  '6aa4801bec7ba02921a43f64': `<p>Recall the definition of rational exponents: for any non-negative base <span class="ql-formula" data-value="a"></span>, <span class="ql-formula" data-value=\"a^{\\frac{1}{2}} = \\sqrt{a}\"></span>.</p>
<p>Applying this to the entire expression <span class="ql-formula" data-value="(133y)^{\\frac{1}{2}}"></span>:</p>
<p><span class="ql-formula" data-value=\"(133y)^{\\frac{1}{2}} = \\sqrt{133y}\"></span></p>
<p>Therefore, the equivalent expression is <strong><span class="ql-formula" data-value=\"\\sqrt{133y}\"></span></strong>.</p>`,

  // Q13
  '6aa48077ec7ba02921a43f6b': `<p>The angle <span class="ql-formula" data-value=\"B = \\frac{3\\pi}{4}\"></span> radians lies in Quadrant II.</p>
<p>The reference angle is <span class="ql-formula" data-value=\"\\pi - \\frac{3\\pi}{4} = \\frac{\\pi}{4}\"></span>.</p>
<p>In Quadrant II, sine is positive:</p>
<p><span class="ql-formula" data-value=\"\\sin\\left(\\frac{3\\pi}{4}\\right) = \\sin\\left(\\frac{\\pi}{4}\\right) = \\frac{\\sqrt{2}}{2}\"></span></p>
<p>Therefore, the value of <span class="ql-formula" data-value=\"\\sin(B)\"></span> is <strong><span class="ql-formula" data-value=\"\\frac{\\sqrt{2}}{2}\"></span></strong>.</p>`,

  // Q14
  '6aa480aaec7ba02921a43f6f': `<p>Calculate the total cost per tablet including 6% sales tax:</p>
<p><span class="ql-formula" data-value=\"\\text{Cost per tablet} = 164 \\times (1 + 0.06) = 164 \\times 1.06 = 173.84\\text{ dollars}\"></span></p>
<p>The school has a maximum budget of $44,800. Divide the budget by the cost per tablet:</p>
<p><span class="ql-formula" data-value=\"\\frac{44800}{173.84} \\approx 257.708\"></span></p>
<p>Since the school cannot purchase a fraction of a tablet and cannot exceed the budget, round down to the nearest whole number:</p>
<p><span class="ql-formula" data-value=\"\\lfloor 257.708 \\rfloor = 257\"></span></p>
<p>Therefore, the maximum number of tablets the school can order is <strong>257</strong>.</p>`,

  // Q15
  '6aa48108ec7ba02921a43f76': `<p>The volume <span class="ql-formula" data-value="V"></span> of a triangular prism is given by <span class="ql-formula" data-value="V = Bh"></span>, where <span class="ql-formula" data-value="B"></span> is the base area and <span class="ql-formula" data-value="h"></span> is the height.</p>
<p>Substitute the given values <span class="ql-formula" data-value="V = 60\\text{ cm}^3"></span> and <span class="ql-formula" data-value="h = 3\\text{ cm}"></span>:</p>
<p><span class="ql-formula" data-value="60 = B(3) \\implies B = \\frac{60}{3} = 20\\text{ cm}^2"></span></p>
<p>Therefore, the area of the base is <strong>20</strong> square centimeters.</p>`,

  // Q16
  '6aa48173ec7ba02921a43f7a': `<p>The solutions to <span class="ql-formula" data-value="f(x) = 0"></span> correspond to the <span class="ql-formula" data-value="x"></span>-intercepts of the graph of <span class="ql-formula" data-value="y = f(x)"></span>.</p>
<p>From the displayed graph:</p>
<ul>
  <li>As <span class="ql-formula" data-value="x \\to -\\infty"></span>, the graph approaches the horizontal asymptote <span class="ql-formula" data-value="y = -5"></span>.</li>
  <li>As <span class="ql-formula" data-value="x"></span> increases, the graph decreases further below <span class="ql-formula" data-value="y = -5"></span> towards <span class="ql-formula" data-value="-\\infty"></span>.</li>
  <li>The graph stays entirely below the horizontal line <span class="ql-formula" data-value="y = -5"></span> for all real values of <span class="ql-formula" data-value="x"></span>.</li>
</ul>
<p>Because the graph never intersects the <span class="ql-formula" data-value="x"></span>-axis (<span class="ql-formula" data-value="y = 0"></span>), there are <strong>Zero</strong> values of <span class="ql-formula" data-value="x"></span> for which <span class="ql-formula" data-value="f(x) = 0"></span>.</p>`,

  // Q17
  '6aa4819aec7ba02921a43f7e': `<p>Expand both sides of the equation:</p>
<p><span class="ql-formula" data-value="x(x + 4) - 140 = 3x(x - 10)"></span></p>
<p><span class="ql-formula" data-value="x^2 + 4x - 140 = 3x^2 - 30x"></span></p>
<p>Move all terms to one side to set the equation to zero:</p>
<p><span class="ql-formula" data-value="0 = (3x^2 - x^2) + (-30x - 4x) + 140"></span></p>
<p><span class="ql-formula" data-value="2x^2 - 34x + 140 = 0"></span></p>
<p>Divide the entire equation by 2:</p>
<p><span class="ql-formula" data-value="x^2 - 17x + 70 = 0"></span></p>
<p>By Vieta's formulas, the sum of the solutions to <span class="ql-formula" data-value="x^2 + Bx + C = 0"></span> is <span class="ql-formula" data-value="-B"></span>:</p>
<p><span class="ql-formula" data-value=\"\\text{Sum of solutions} = -(-17) = 17\"></span></p>
<p>Therefore, the sum of the solutions is <strong>17</strong>.</p>`,

  // Q18
  '6aa481edec7ba02921a43f85': `<p>Multiply the equation <span class="ql-formula" data-value="-3x^2 - 7x + 1 = 0"></span> by -1:</p>
<p><span class="ql-formula" data-value="3x^2 + 7x - 1 = 0"></span></p>
<p>Use the quadratic formula <span class="ql-formula" data-value=\"x = \\frac{-b \\pm \\sqrt{b^2 - 4ac}}{2a}\"></span> with <span class="ql-formula" data-value="a = 3, b = 7, c = -1"></span>:</p>
<p><span class="ql-formula" data-value=\"x = \\frac{-7 \\pm \\sqrt{7^2 - 4(3)(-1)}}{2(3)} = \\frac{-7 \\pm \\sqrt{49 + 12}}{6} = \\frac{-7 \\pm \\sqrt{61}}{6}\"></span></p>
<p>The greatest solution is obtained by taking the positive root:</p>
<p><span class="ql-formula" data-value=\"x = -\\frac{7}{6} + \\frac{\\sqrt{61}}{6}\"></span></p>
<p>Therefore, the correct answer is <strong><span class="ql-formula" data-value=\"-\\frac{7}{6} + \\frac{\\sqrt{61}}{6}\"></span></strong>.</p>`,

  // Q19
  '6aa48223ec7ba02921a43f89': `<p>In right triangle <span class="ql-formula" data-value="ABC"></span> with right angle at <span class="ql-formula" data-value="B"></span>, the acute angles are complementary:</p>
<p><span class="ql-formula" data-value="m\\angle A + m\\angle C = 90^\\circ"></span></p>
<p>Given <span class="ql-formula" data-value="m\\angle C = 30^\\circ"></span>:</p>
<p><span class="ql-formula" data-value="m\\angle A = 90^\\circ - 30^\\circ = 60^\\circ"></span></p>
<p>Now evaluate <span class="ql-formula" data-value=\"\\cos(A) = \\cos(60^\\circ)\"></span>:</p>
<p><span class="ql-formula" data-value=\"\\cos(60^\\circ) = \\frac{1}{2}\"></span></p>
<p>The length of side <span class="ql-formula" data-value=\"BC\"></span> is not needed to evaluate the cosine of the angle. Thus, the value of <span class="ql-formula" data-value=\"\\cos A\"></span> is <strong><span class="ql-formula" data-value=\"\\frac{1}{2}\"></span></strong> (or 0.5).</p>`,

  // Q20
  '6aa48283ec7ba02921a43f8d': `<p>We are given that:</p>
<p>1) <span class="ql-formula" data-value="a = 20.47(b + c)"></span> (since <span class="ql-formula" data-value="2047\\% = 20.47"></span>)</p>
<p>2) <span class="ql-formula" data-value="b = 0.89c \\implies c = \\frac{b}{0.89}"></span></p>
<p>Express <span class="ql-formula" data-value="b + c"></span> in terms of <span class="ql-formula" data-value="b"></span>:</p>
<p><span class="ql-formula" data-value=\"b + c = b + \\frac{b}{0.89} = b\\left(1 + \\frac{1}{0.89}\\right) = b\\left(\\frac{1.89}{0.89}\\right)\"></span></p>
<p>Substitute this into the expression for <span class="ql-formula" data-value="a"></span>:</p>
<p><span class="ql-formula" data-value=\"a = 20.47 \\cdot b\\left(\\frac{1.89}{0.89}\\right) = b \\left(\\frac{20.47 \\times 1.89}{0.89}\\right) = b \\left(\\frac{38.6883}{0.89}\\right) = 43.47b\"></span></p>
<p>To find what percent of <span class="ql-formula" data-value="b"></span> is <span class="ql-formula" data-value="a"></span>, multiply by 100%:</p>
<p><span class="ql-formula" data-value=\"43.47 \\times 100\\% = 4347\\%\"></span></p>
<p>Therefore, <span class="ql-formula" data-value="a"></span> is <strong>4,347%</strong> of <span class="ql-formula" data-value="b"></span>.</p>`,

  // Q21
  '6aa482bfec7ba02921a43f91': `<p>Isolate the absolute value in the equation <span class="ql-formula" data-value="-2|3x + 7| + 8 = -6"></span>:</p>
<p>Subtract 8 from both sides:</p>
<p><span class="ql-formula" data-value="-2|3x + 7| = -14"></span></p>
<p>Divide by -2:</p>
<p><span class="ql-formula" data-value="|3x + 7| = 7"></span></p>
<p>This gives two linear cases:</p>
<p><strong>Case 1:</strong></p>
<p><span class="ql-formula" data-value="3x + 7 = 7 \\implies 3x = 0 \\implies x = 0"></span></p>
<p><strong>Case 2:</strong></p>
<p><span class="ql-formula" data-value=\"3x + 7 = -7 \\implies 3x = -14 \\implies x = -\\frac{14}{3}\"></span></p>
<p>Therefore, the solutions are <strong><span class="ql-formula" data-value=\"0\\text{ and } -\\frac{14}{3}\"></span></strong>.</p>`,

  // Q22
  '6aa48304ec7ba02921a43f98': `<p>First, calculate the total actual distance represented by the original square map:</p>
<p><span class="ql-formula" data-value=\"55\\text{ inches} \\times 13\\text{ miles/inch} = 715\\text{ miles}\"></span></p>
<p>The smaller map has side lengths that are 70% shorter, meaning the new side length is 30% of the original:</p>
<p><span class="ql-formula" data-value=\"55 \\times (1 - 0.70) = 55 \\times 0.30 = 16.5\\text{ inches}\"></span></p>
<p>On this smaller map, 16.5 inches represents the same 715 miles. To find the actual distance represented by 1 inch on the smaller map, divide:</p>
<p><span class="ql-formula" data-value=\"\\frac{715\\text{ miles}}{16.5\\text{ inches}} \\approx 43.33\\text{ miles per inch}\"></span></p>
<p>Therefore, 1 inch represents approximately <strong>43.33</strong> miles.</p>`
};

async function main() {
  console.log('Injecting 22 pedagogical explanations for March 2025 · INT 3 Module 1...');
  let successCount = 0;

  for (const [id, expl] of Object.entries(explanationsM1)) {
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

  console.log(`\nFinished Module 1: ${successCount}/22 explanations successfully injected.`);
}

main();
