const axios = require('axios');

const API_BASE = 'https://sat-backend-production.up.railway.app';

// 22 explanations for March 2025 · INT 2 Module 1
const explanationsM1 = {
  // Q1
  '6aa46b68ec7ba02921a43dca': `<p>To find the speed of the car 4 seconds after it began to accelerate, substitute <span class="ql-formula" data-value="t = 4"></span> into the given linear equation:</p>
<p><span class="ql-formula" data-value="s = 40 + 2(4) = 40 + 8 = 48"></span></p>
<p>Therefore, the speed of the car is <strong>48</strong> miles per hour.</p>`,

  // Q2
  '6aa46bddec7ba02921a43ddd': `<p>The figure shows a right triangle with legs of length 8 and <span class="ql-formula" data-value="b"></span>, and a hypotenuse of length 20.</p>
<p>By the Pythagorean theorem, the sum of the squares of the lengths of the legs equals the square of the length of the hypotenuse:</p>
<p><span class="ql-formula" data-value="8^2 + b^2 = 20^2"></span></p>
<p>Therefore, the correct equation is <strong><span class="ql-formula" data-value="8^2 + b^2 = 20^2"></span></strong>.</p>`,

  // Q3
  '6aa46ca9ec7ba02921a43de1': `<p>The histogram organizes the data into class intervals (bins) of width 50 feet:</p>
<ul>
  <li>0 to less than 50 feet</li>
  <li>50 to less than 100 feet</li>
  <li>100 to less than 150 feet</li>
  <li>150 to less than 200 feet</li>
  <li>200 to less than 250 feet</li>
</ul>
<p>The rightmost bin with data is the interval from 200 to less than 250 feet (with frequency 5). Any maximum value of the data set must lie within this interval.</p>
<p>Among the given choices (69, 119, 169, 219), only <strong>219</strong> falls into the range <span class="ql-formula" data-value="200 \\le x < 250"></span>.</p>`,

  // Q4
  '6aa46d0aec7ba02921a43de5': `<p>Set the function <span class="ql-formula" data-value="f(x) = 8(2x + 2)"></span> equal to 80:</p>
<p><span class="ql-formula" data-value="8(2x + 2) = 80"></span></p>
<p>Divide both sides by 8:</p>
<p><span class="ql-formula" data-value="2x + 2 = 10"></span></p>
<p>Subtract 2 from both sides:</p>
<p><span class="ql-formula" data-value="2x = 8 \\implies x = 4"></span></p>
<p>Therefore, the value of <span class="ql-formula" data-value="x"></span> is <strong>4</strong>.</p>`,

  // Q5
  '6aa46d54ec7ba02921a43dec': `<p>Set the two equations equal to find where the line intersects the parabola:</p>
<p><span class="ql-formula" data-value="x^2 + 8x + a = -0.5 \\implies x^2 + 8x + (a + 0.5) = 0"></span></p>
<p>A quadratic equation <span class="ql-formula" data-value="Ax^2 + Bx + C = 0"></span> has no real solutions if and only if its discriminant is strictly negative (<span class="ql-formula" data-value="B^2 - 4AC < 0"></span>):</p>
<p><span class="ql-formula" data-value="8^2 - 4(1)(a + 0.5) < 0"></span></p>
<p><span class="ql-formula" data-value="64 - 4a - 2 < 0 \\implies 62 - 4a < 0 \\implies 4a > 62 \\implies a > 15.5"></span></p>
<p>Since <span class="ql-formula" data-value="a"></span> is a positive integer, the least possible integer value for <span class="ql-formula" data-value="a"></span> is <strong>16</strong>.</p>`,

  // Q6
  '6aa46d72ec7ba02921a43df0': `<p>Let <span class="ql-formula" data-value="x"></span> be the length of each of the two equal parts.</p>
<p>The total length of the line segment is the sum of the three parts:</p>
<p><span class="ql-formula" data-value="47 + x + x = 113"></span></p>
<p><span class="ql-formula" data-value="47 + 2x = 113 \\implies 2x = 66 \\implies x = 33"></span></p>
<p>Therefore, the length of one of the other two parts is <strong>33</strong> cm.</p>`,

  // Q7
  '6aa46d9fec7ba02921a43df4': `<p>The percent increase is given by:</p>
<p><span class="ql-formula" data-value=\"\\text{Percent Increase} = \\frac{\\text{New Value} - \\text{Original Value}}{\\text{Original Value}} \\times 100\\%\"></span></p>
<p>Substituting the given values:</p>
<p><span class="ql-formula" data-value=\"\\text{Percent Increase} = \\frac{80 - 16}{16} \\times 100\\% = \\frac{64}{16} \\times 100\\% = 4 \\times 100\\% = 400\\%\"></span></p>
<p>Therefore, the percent increase is <strong>400%</strong>.</p>`,

  // Q8
  '6aa46dd4ec7ba02921a43df8': `<p>Examine the line of best fit in the given scatterplot:</p>
<ul>
  <li>The line has a negative slope (slants downwards from left to right).</li>
  <li>When <span class="ql-formula" data-value="x = 0"></span>, the line crosses the <span class="ql-formula" data-value="y"></span>-axis slightly above 2, at approximately <span class="ql-formula" data-value="y = 2.3"></span>.</li>
  <li>When <span class="ql-formula" data-value="x = -14"></span>, the line passes through approximately <span class="ql-formula" data-value="y = 16.3"></span>.</li>
</ul>
<p>Calculating the slope <span class="ql-formula" data-value="m"></span>:</p>
<p><span class="ql-formula" data-value=\"m = \\frac{2.3 - 16.3}{0 - (-14)} = \\frac{-14}{14} = -1\"></span></p>
<p>Using the slope-intercept form <span class="ql-formula" data-value="y = mx + b"></span> with <span class="ql-formula" data-value="m = -1"></span> and <span class="ql-formula" data-value="b = 2.3"></span>:</p>
<p><span class="ql-formula" data-value="y = -x + 2.3"></span></p>
<p>Therefore, the best representing equation is <strong><span class="ql-formula" data-value="y = -x + 2.3"></span></strong>.</p>`,

  // Q9
  '6aa46e0bec7ba02921a43dfc': `<p>Combine the like terms in the expression:</p>
<p><span class="ql-formula" data-value="7x^6 + 9x^6 - 8x^6 = (7 + 9 - 8)x^6 = 8x^6"></span></p>
<p>We are given that this is equivalent to <span class="ql-formula" data-value="bx^6"></span>. Comparing coefficients gives:</p>
<p><span class="ql-formula" data-value="b = 8"></span></p>
<p>Therefore, the value of <span class="ql-formula" data-value="b"></span> is <strong>8</strong>.</p>`,

  // Q10
  '6aa46e9aec7ba02921a43e12': `<p>To find the point of intersection, set the two equations equal to each other:</p>
<p><span class="ql-formula" data-value="6x - 2 = 5x + 8"></span></p>
<p>Subtract <span class="ql-formula" data-value="5x"></span> from both sides and add 2 to both sides:</p>
<p><span class="ql-formula" data-value="x = 10"></span></p>
<p>Substitute <span class="ql-formula" data-value="x = 10"></span> into the first equation to find <span class="ql-formula" data-value="y"></span>:</p>
<p><span class="ql-formula" data-value="y = 5(10) + 8 = 50 + 8 = 58"></span></p>
<p>Thus, the point of intersection is <strong>(10, 58)</strong>.</p>`,

  // Q11
  '6aa46f36ec7ba02921a43e29': `<p>The area of a rectangle is given by the formula:</p>
<p><span class="ql-formula" data-value=\"\\text{Area} = \\text{length} \\times \\text{width}\"></span></p>
<p>The problem states that the width is <span class="ql-formula" data-value="w"></span> and the length is 72 times its width, which is <span class="ql-formula" data-value="72w"></span>.</p>
<p>In the formula <span class="ql-formula" data-value=\"y = (72w)(w)\"></span>, the factor <span class="ql-formula" data-value="72w"></span> represents <strong>The length of the rectangle, in feet</strong>.</p>`,

  // Q12
  '6aa46fbfec7ba02921a43e2d': `<p>Two lines cut by a transversal are parallel if and only if their corresponding angles or alternate interior angles are equal.</p>
<p>In the figure, angle <span class="ql-formula" data-value="w"></span> and angle <span class="ql-formula" data-value="y"></span> are corresponding angles formed by the transversal line <span class="ql-formula" data-value="k"></span> intersecting lines <span class="ql-formula" data-value="r"></span> and <span class="ql-formula" data-value="s"></span>.</p>
<p>Given that <span class="ql-formula" data-value="w = 160"></span>, having <span class="ql-formula" data-value="y = 160"></span> ensures that the corresponding angles are congruent, which is sufficient to prove that line <span class="ql-formula" data-value="r"></span> is parallel to line <span class="ql-formula" data-value="s"></span>.</p>
<p>Therefore, the correct choice is <strong><span class="ql-formula" data-value="y = 160"></span></strong>.</p>`,

  // Q13
  '6aa46feaec7ba02921a43e31': `<p>Complete the square for both <span class="ql-formula" data-value="x"></span> and <span class="ql-formula" data-value="y"></span> in the equation of the circle:</p>
<p><span class="ql-formula" data-value="(x^2 - 4x + 4) + (y^2 - 8y + 16) = 80 + 4 + 16"></span></p>
<p><span class="ql-formula" data-value="(x - 2)^2 + (y - 4)^2 = 100 = 10^2"></span></p>
<p>The radius of the circle is <span class="ql-formula" data-value="r = 10"></span>, which means its diameter is <span class="ql-formula" data-value="d = 2r = 20"></span>.</p>
<p>When a circle is inscribed in a square, the side length of the square equals the diameter of the circle:</p>
<p><span class="ql-formula" data-value=\"\\text{side length} = 20\"></span></p>
<p>The perimeter of the square is:</p>
<p><span class="ql-formula" data-value=\"\\text{Perimeter} = 4 \\times 20 = 80\"></span></p>
<p>Therefore, the perimeter of the square is <strong>80</strong>.</p>`,

  // Q14
  '6aa47009ec7ba02921a43e35': `<p>Calculate the attendance step-by-step:</p>
<ol>
  <li>First webinar attendance: 1,250 people.</li>
  <li>Second webinar attendance (46% of the first webinar):
    <p><span class="ql-formula" data-value=\"1250 \\times 0.46 = 575\\text{ people}\"></span></p>
  </li>
  <li>Third webinar attendance (32% of those who attended the first and second webinars):
    <p><span class="ql-formula" data-value=\"575 \\times 0.32 = 184\\text{ people}\"></span></p>
  </li>
</ol>
<p>Therefore, <strong>184</strong> people attended all three webinars.</p>`,

  // Q15
  '6aa47063ec7ba02921a43e39': `<p>Evaluate the given exponential function <span class="ql-formula" data-value=\"f(x) = 24(2)^{\\frac{x}{6}}\"></span> for the values in the table:</p>
<ul>
  <li>For <span class="ql-formula" data-value="x = -6"></span>: <span class="ql-formula" data-value=\"f(-6) = 24(2)^{-6/6} = 24(2)^{-1} = 24 \\cdot \\frac{1}{2} = 12\"></span></li>
  <li>For <span class="ql-formula" data-value="x = 0"></span>: <span class="ql-formula" data-value=\"f(0) = 24(2)^0 = 24 \\cdot 1 = 24\"></span></li>
  <li>For <span class="ql-formula" data-value="x = 6"></span>: <span class="ql-formula" data-value=\"f(6) = 24(2)^{6/6} = 24(2)^1 = 48\"></span></li>
  <li>For <span class="ql-formula" data-value="x = 12"></span>: <span class="ql-formula" data-value=\"f(12) = 24(2)^{12/6} = 24(2)^2 = 24 \\cdot 4 = 96\"></span></li>
</ul>
<p>The table with values <span class="ql-formula" data-value=\"(-6, 12), (0, 24), (6, 48), (12, 96)\"></span> is the correct table.</p>`,

  // Q16
  '6aa470a9ec7ba02921a43e3d': `<p>The standard equation of a circle with center <span class="ql-formula" data-value="(h, k)"></span> and radius <span class="ql-formula" data-value="r"></span> is:</p>
<p><span class="ql-formula" data-value="(x - h)^2 + (y - k)^2 = r^2"></span></p>
<p>Substitute the center <span class="ql-formula" data-value="(h, k) = (18, 16)"></span> and radius <span class="ql-formula" data-value="r = 6k"></span>:</p>
<p><span class="ql-formula" data-value="(x - 18)^2 + (y - 16)^2 = (6k)^2 = 36k^2"></span></p>
<p>Therefore, the equation is <strong><span class="ql-formula" data-value="(x - 18)^2 + (y - 16)^2 = 36k^2"></span></strong>.</p>`,

  // Q17
  '6aa470e6ec7ba02921a43e41': `<p>The volume <span class="ql-formula" data-value="V"></span> of a cube with edge length <span class="ql-formula" data-value="s = 3.000"></span> cm is:</p>
<p><span class="ql-formula" data-value=\"V = s^3 = 3.000^3 = 27.000\\text{ cm}^3\"></span></p>
<p>Mass is the product of density and volume:</p>
<p><span class="ql-formula" data-value=\"\\text{Mass} = \\text{Density} \\times \\text{Volume} = 0.250\\text{ g/cm}^3 \\times 27\\text{ cm}^3 = 6.75\\text{ grams}\"></span></p>
<p>In fractional form, <span class="ql-formula" data-value=\"6.75 = \\frac{27}{4}\"></span> grams.</p>`,

  // Q18
  '6aa47145ec7ba02921a43e45': `<p>To convert an angle from radians to degrees, multiply the angle measure by the conversion factor <span class="ql-formula" data-value=\"\\frac{180^\\circ}{\\pi}\"></span>:</p>
<p><span class="ql-formula" data-value=\"\\text{Degrees} = \\text{Radians} \\cdot \\frac{180^\\circ}{\\pi}\"></span></p>
<p>Given the difference is <span class="ql-formula" data-value=\"-\\frac{5}{12}\\pi\"></span> radians:</p>
<p><span class="ql-formula" data-value=\"-\\frac{5}{12}\\pi \\cdot \\frac{180^\\circ}{\\pi}\"></span></p>
<p>Therefore, the correct expression is <strong><span class="ql-formula" data-value=\"-\\frac{5}{12}\\pi \\cdot \\frac{180^\\circ}{\\pi}\"></span></strong>.</p>`,

  // Q19
  '6aa47179ec7ba02921a43e49': `<p>For a quadratic equation in standard form <span class="ql-formula" data-value="Ax^2 + Bx + C = 0"></span>, the sum of the solutions is given by Vieta's formulas:</p>
<p><span class="ql-formula" data-value=\"\\text{Sum of solutions} = -\\frac{B}{A}\"></span></p>
<p>In the equation <span class="ql-formula" data-value="x^2 - 84x - 14 = 0"></span>, <span class="ql-formula" data-value="A = 1"></span> and <span class="ql-formula" data-value="B = -84"></span>:</p>
<p><span class="ql-formula" data-value=\"\\text{Sum} = -\\frac{-84}{1} = 84\"></span></p>
<p>Therefore, the sum of the solutions is <strong>84</strong>.</p>`,

  // Q20
  '6aa471cfec7ba02921a43e4d': `<p>In a right circular cone, the height <span class="ql-formula" data-value="h"></span>, base radius <span class="ql-formula" data-value="r"></span>, and slant height <span class="ql-formula" data-value="AB"></span> satisfy the Pythagorean theorem:</p>
<p><span class="ql-formula" data-value="r^2 + h^2 = AB^2"></span></p>
<p>Given <span class="ql-formula" data-value="h = 16"></span> cm and <span class="ql-formula" data-value="AB = 32"></span> cm:</p>
<p><span class="ql-formula" data-value="r^2 + 16^2 = 32^2"></span></p>
<p><span class="ql-formula" data-value="r^2 = 1024 - 256 = 768"></span></p>
<p>The volume <span class="ql-formula" data-value="V"></span> of a right circular cone is:</p>
<p><span class="ql-formula" data-value=\"V = \\frac{1}{3}\\pi r^2 h = \\frac{1}{3}\\pi (768)(16) = \\pi (256)(16) = 4096\\pi\"></span></p>
<p>Since the volume is given as <span class="ql-formula" data-value="k\\pi"></span>, the value of <span class="ql-formula" data-value="k"></span> is <strong>4096</strong>.</p>`,

  // Q21
  '6aa47237ec7ba02921a43e51': `<p>Line <span class="ql-formula" data-value="k"></span> has slope <span class="ql-formula" data-value="m"></span>. Since line <span class="ql-formula" data-value="l"></span> is perpendicular to line <span class="ql-formula" data-value="k"></span>, its slope is the negative reciprocal:</p>
<p><span class="ql-formula" data-value=\"m_l = -\\frac{1}{m}\"></span></p>
<p>Line <span class="ql-formula" data-value="l"></span> passes through <span class="ql-formula" data-value="(2, 8)"></span>, so its point-slope equation is:</p>
<p><span class="ql-formula" data-value=\"y - 8 = -\\frac{1}{m}(x - 2)\"></span></p>
<p>Substitute <span class="ql-formula" data-value="x = 3"></span> into this equation:</p>
<p><span class="ql-formula" data-value=\"y - 8 = -\\frac{1}{m}(3 - 2) = -\\frac{1}{m} \\implies y = 8 - \\frac{1}{m}\"></span></p>
<p>Therefore, the point <strong><span class="ql-formula" data-value=\"(3, 8 - \\frac{1}{m})\"></span></strong> lies on line <span class="ql-formula" data-value="l"></span>.</p>`,

  // Q22
  '6aa4729bec7ba02921a43e58': `<p>Set the function <span class="ql-formula" data-value="f(x) = 8(2x + 2)"></span> equal to 80:</p>
<p><span class="ql-formula" data-value="8(2x + 2) = 80"></span></p>
<p>Divide both sides by 8:</p>
<p><span class="ql-formula" data-value="2x + 2 = 10"></span></p>
<p>Subtract 2 from both sides:</p>
<p><span class="ql-formula" data-value="2x = 8 \\implies x = 4"></span></p>
<p>Therefore, the value of <span class="ql-formula" data-value="x"></span> is <strong>4</strong>.</p>`
};

async function main() {
  console.log('Injecting 22 pedagogical explanations for March 2025 · INT 2 Module 1...');
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
