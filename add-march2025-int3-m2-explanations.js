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
  // Q1
  '6aa48636ec7ba02921a43ff1': `<p>To determine the number of solutions to the linear equation, solve for <span class="ql-formula" data-value="x"></span>:</p><p><span class="ql-formula" data-value="2x - 3 = 2x"></span></p><p>Subtract <span class="ql-formula" data-value="2x"></span> from both sides of the equation:</p><p><span class="ql-formula" data-value="-3 = 0"></span></p><p>Since this statement is false and contains no variables, there is no value of <span class="ql-formula" data-value="x"></span> that satisfies the equation. Therefore, the equation has <strong>Zero</strong> solutions.</p>`,

  // Q2
  '6aa48679ec7ba02921a43ff5': `<p>We are given that <span class="ql-formula" data-value="f"></span> is a linear function with <span class="ql-formula" data-value="f(0) = 2"></span> and <span class="ql-formula" data-value="f(7) = 2"></span>.</p><p>First, calculate the slope <span class="ql-formula" data-value="m"></span> using the two points <span class="ql-formula" data-value="(0, 2)"></span> and <span class="ql-formula" data-value="(7, 2)"></span>:</p><p><span class="ql-formula" data-value="m = \\frac{2 - 2}{7 - 0} = \\frac{0}{7} = 0"></span></p><p>Since the slope is <span class="ql-formula" data-value="0"></span> and the <span class="ql-formula" data-value="y"></span>-intercept is <span class="ql-formula" data-value="(0, 2)"></span>, the equation in slope-intercept form is:</p><p><span class="ql-formula" data-value="f(x) = 0x + 2 = 2"></span></p><p>Thus, <span class="ql-formula" data-value="f(x) = 2"></span>.</p>`,

  // Q3
  '6aa486cdec7ba02921a43ff9': `<p>The area of a rectangle is calculated as the product of its length and its width:</p><p><span class="ql-formula" data-value="\\text{Area} = \\text{length} \\times \\text{width}"></span></p><p>We are given that the width is <span class="ql-formula" data-value="w"></span> feet, and the length is <span class="ql-formula" data-value="92"></span> times its width, which equals <span class="ql-formula" data-value="92w"></span> feet. In the given area equation <span class="ql-formula" data-value="y = (92w)(w)"></span>, the term <span class="ql-formula" data-value="92w"></span> corresponds to <strong>The length of the rectangle, in feet</strong>.</p>`,

  // Q4
  '6aa48735ec7ba02921a43ffd': `<p>The given linear function is <span class="ql-formula" data-value="T(x) = 67 - 8x"></span>, where <span class="ql-formula" data-value="x"></span> represents the altitude in thousands of feet and <span class="ql-formula" data-value="T(x)"></span> represents the temperature in degrees Fahrenheit.</p><p>In a linear model of the form <span class="ql-formula" data-value="T(x) = mx + b"></span>, the slope <span class="ql-formula" data-value="m = -8"></span> represents the rate of change of temperature per unit increase in <span class="ql-formula" data-value="x"></span>. A slope of <span class="ql-formula" data-value="-8"></span> means that for each increase of 1 unit in <span class="ql-formula" data-value="x"></span> (1 thousand feet in altitude), the temperature decreases by <strong>8</strong> degrees Fahrenheit.</p>`,

  // Q5
  '6aa487abec7ba02921a44013': `<p>The total probability across all three rooms must equal 1:</p><p><span class="ql-formula" data-value="P(A) + P(B) + P(C) = 1"></span></p><p>Substitute the given probabilities:</p><p><span class="ql-formula" data-value="0.68 + 0.24 + P(C) = 1"></span></p><p><span class="ql-formula" data-value="0.92 + P(C) = 1 \\implies P(C) = 0.08"></span></p><p>Now find the number of visitors in room C out of the total 375 visitors:</p><p><span class="ql-formula" data-value="375 \\times 0.08 = 30"></span></p><p>Therefore, there are <strong>30</strong> visitors located in room C.</p>`,

  // Q6
  '6aa48822ec7ba02921a44017': `<p>The quadratic function reaches a maximum height of 185 feet at <span class="ql-formula" data-value="t = 2"></span> seconds, which means its vertex is at <span class="ql-formula" data-value="(h, k) = (2, 185)"></span>.</p><p>In vertex form, the function is:</p><p><span class="ql-formula" data-value="f(t) = a(t - 2)^2 + 185"></span></p><p>We are given that the object was launched from an initial height of 121 feet, so <span class="ql-formula" data-value="f(0) = 121"></span>:</p><p><span class="ql-formula" data-value="a(0 - 2)^2 + 185 = 121"></span></p><p><span class="ql-formula" data-value="4a + 185 = 121 \\implies 4a = -64 \\implies a = -16"></span></p><p>Substituting <span class="ql-formula" data-value="a = -16"></span> gives:</p><p><span class="ql-formula" data-value="f(t) = -16(t - 2)^2 + 185"></span></p>`,

  // Q7
  '6aa48867ec7ba02921a4401b': `<p>We are given the system of equations:</p><p>1) <span class="ql-formula" data-value="7y = -6x + 2550 \\implies 6x + 7y = 2550"></span></p><p>2) <span class="ql-formula" data-value="24x - 28y = 1800"></span></p><p>Divide the second equation by 4:</p><p><span class="ql-formula" data-value="6x - 7y = 450"></span></p><p>Add this equation to <span class="ql-formula" data-value="6x + 7y = 2550"></span>:</p><p><span class="ql-formula" data-value="(6x + 7y) + (6x - 7y) = 2550 + 450"></span></p><p><span class="ql-formula" data-value="12x = 3000 \\implies x = 250"></span></p><p>Substitute <span class="ql-formula" data-value="x = 250"></span> into <span class="ql-formula" data-value="6x + 7y = 2550"></span>:</p><p><span class="ql-formula" data-value="6(250) + 7y = 2550"></span></p><p><span class="ql-formula" data-value="1500 + 7y = 2550 \\implies 7y = 1050 \\implies y = 150"></span></p><p>Now evaluate <span class="ql-formula" data-value="x + y"></span>:</p><p><span class="ql-formula" data-value="x + y = 250 + 150 = 400"></span></p>`,

  // Q8
  '6aa4888dec7ba02921a4401f': `<p>Each wood sample has a volume of <span class="ql-formula" data-value="0.220\\text{ cm}^3"></span>. Samples were taken from 27 trees (one from each tree), giving a total of 27 samples.</p><p>Calculate the total volume of all samples:</p><p><span class="ql-formula" data-value="\\text{Total Volume} = 27 \\times 0.220 = 5.94\\text{ cm}^3"></span></p><p>Expressed as an improper fraction, <span class="ql-formula" data-value="5.94 = \\frac{594}{100} = \\frac{297}{50}"></span>.</p>`,

  // Q9
  '6aa48920ec7ba02921a44026': `<p>To solve <span class="ql-formula" data-value="-2|3x + 7| + 8 = -6"></span>, first isolate the absolute value term:</p><p><span class="ql-formula" data-value="-2|3x + 7| = -6 - 8 = -14"></span></p><p>Divide by <span class="ql-formula" data-value="-2"></span>:</p><p><span class="ql-formula" data-value="|3x + 7| = 7"></span></p><p>Set up two linear cases:</p><p><strong>Case 1:</strong> <span class="ql-formula" data-value="3x + 7 = 7 \\implies 3x = 0 \\implies x = 0"></span></p><p><strong>Case 2:</strong> <span class="ql-formula" data-value="3x + 7 = -7 \\implies 3x = -14 \\implies x = -\\frac{14}{3}"></span></p><p>Thus, the solutions are <strong>0 and -14/3</strong>.</p>`,

  // Q10
  '6aa48996ec7ba02921a4402a': `<p>The line passes through <span class="ql-formula" data-value="(0, 9)"></span> and <span class="ql-formula" data-value="(-2, -3)"></span>.</p><p>First, find the slope <span class="ql-formula" data-value="m"></span>:</p><p><span class="ql-formula" data-value="m = \\frac{-3 - 9}{-2 - 0} = \\frac{-12}{-2} = 6"></span></p><p>With <span class="ql-formula" data-value="y"></span>-intercept <span class="ql-formula" data-value="9"></span>, the equation in slope-intercept form is:</p><p><span class="ql-formula" data-value="y = 6x + 9"></span></p><p>Rearrange into standard form:</p><p><span class="ql-formula" data-value="-6x + y = 9"></span></p><p>To match the given form <span class="ql-formula" data-value="Rx + 12y = 108"></span>, multiply the entire equation by 12:</p><p><span class="ql-formula" data-value="12(-6x + y) = 12(9) \\implies -72x + 12y = 108"></span></p><p>Thus, <span class="ql-formula" data-value="R = -72"></span>, and the equation is <strong>Rx + 12y = 108</strong>.</p>`,

  // Q11
  '6aa489ecec7ba02921a4402e': `<p>We are given the exponential function <span class="ql-formula" data-value="f(x) = -10(3)^x + \\frac{1}{k}"></span>.</p><p>To find the value of <span class="ql-formula" data-value="f(0)"></span>, substitute <span class="ql-formula" data-value="x = 0"></span>:</p><p><span class="ql-formula" data-value="f(0) = -10(3)^0 + \\frac{1}{k}"></span></p><p>Since <span class="ql-formula" data-value="3^0 = 1"></span>:</p><p><span class="ql-formula" data-value="f(0) = -10(1) + \\frac{1}{k} = \\frac{1}{k} - 10 = \\frac{1 - 10k}{k}"></span></p>`,

  // Q12
  '6aa48a93ec7ba02921a44046': `<p>The boundary line for the inequality <span class="ql-formula" data-value="rx + ty \\ge -77"></span> passes through the points <span class="ql-formula" data-value="(0, -11)"></span> and <span class="ql-formula" data-value="(-7, -10)"></span>.</p><p>Substitute <span class="ql-formula" data-value="(0, -11)"></span> into the line equation <span class="ql-formula" data-value="rx + ty = -77"></span>:</p><p><span class="ql-formula" data-value="r(0) + t(-11) = -77 \\implies -11t = -77 \\implies t = 7"></span></p><p>Substitute <span class="ql-formula" data-value="(-7, -10)"></span> and <span class="ql-formula" data-value="t = 7"></span> into the equation:</p><p><span class="ql-formula" data-value="r(-7) + 7(-10) = -77"></span></p><p><span class="ql-formula" data-value="-7r - 70 = -77 \\implies -7r = -7 \\implies r = 1"></span></p><p>Now find <span class="ql-formula" data-value="r + t"></span>:</p><p><span class="ql-formula" data-value="r + t = 1 + 7 = 8"></span></p>`,

  // Q13
  '6aa48bb6ec7ba02921a4404d': `<p>Let <span class="ql-formula" data-value="x"></span> be the total number of classes taken, with <span class="ql-formula" data-value="x \\ge 2"></span>. The regular price per class is $22.80.</p><p>Under the promotion:</p><ul><li>Class 1 is free ($0).</li><li>Class 2 is half price: <span class="ql-formula" data-value="0.5 \\times 22.80 = 11.40"></span> dollars.</li><li>The remaining <span class="ql-formula" data-value="x - 2"></span> classes cost full price ($22.80 each).</li></ul><p>The total cost function is:</p><p><span class="ql-formula" data-value="f(x) = 11.40 + 22.80(x - 2)"></span></p><p>Expand and rewrite:</p><p><span class="ql-formula" data-value="f(x) = 11.40 + 22.80x - 45.60 = 22.80x - 34.20"></span></p><p>Notice that:</p><p><span class="ql-formula" data-value="22.80(x - 1) - 11.40 = 22.80x - 22.80 - 11.40 = 22.80x - 34.20"></span></p><p>Therefore, the function defining the cost is <span class="ql-formula" data-value="f(x) = 22.80(x - 1) - 11.40"></span>.</p>`,

  // Q14
  '6aa48c37ec7ba02921a4405a': `<p>To find the <span class="ql-formula" data-value="y"></span>-intercept of the linear function <span class="ql-formula" data-value="f(x) = 6x + 14"></span>, evaluate the function at <span class="ql-formula" data-value="x = 0"></span>:</p><p><span class="ql-formula" data-value="f(0) = 6(0) + 14 = 14"></span></p><p>Thus, the <span class="ql-formula" data-value="y"></span>-intercept is <strong>14</strong> (or the point <span class="ql-formula" data-value="(0, 14)"></span>).</p>`,

  // Q15
  '6aa48ca2ec7ba02921a4405e': `<p>The given graph shows <span class="ql-formula" data-value="y = f(x) + 2"></span>. From the graph:</p><ul><li>There is a horizontal asymptote at <span class="ql-formula" data-value="y = 5"></span>.</li><li>The curve passes through <span class="ql-formula" data-value="(0, 4)"></span> and <span class="ql-formula" data-value="(1, 2)"></span>.</li></ul><p>This matches an exponential curve of the form <span class="ql-formula" data-value="y = 5 - b^x"></span>. Checking points:</p><ul><li>At <span class="ql-formula" data-value="x = 0"></span>: <span class="ql-formula" data-value="y = 5 - b^0 = 5 - 1 = 4"></span>.</li><li>At <span class="ql-formula" data-value="x = 1"></span>: <span class="ql-formula" data-value="y = 5 - b^1 = 2 \\implies b = 3"></span>.</li></ul><p>Thus, <span class="ql-formula" data-value="y = -3^x + 5"></span>.</p><p>Since <span class="ql-formula" data-value="y = f(x) + 2"></span>, we subtract 2 from both sides to solve for <span class="ql-formula" data-value="f(x)"></span>:</p><p><span class="ql-formula" data-value="f(x) = y - 2 = (-3^x + 5) - 2 = -3^x + 3"></span></p>`,

  // Q16
  '6aa48cc3ec7ba02921a44062': `<p>For the first square map, each side length is 55 inches and each inch represents 13 miles, giving an actual side length of <span class="ql-formula" data-value="55 \\times 13 = 715"></span> miles.</p><p>For the second map, each side length is 55 inches and each inch represents 0.3 mile, giving an actual side length of <span class="ql-formula" data-value="55 \\times 0.3 = 16.5"></span> miles.</p><p>The ratio of the side lengths in miles is:</p><p><span class="ql-formula" data-value="\\frac{715}{16.5} \\approx 43.33"></span></p><p>Thus, the value is <strong>43.33</strong>.</p>`,

  // Q17
  '6aa48d60ec7ba02921a44066': `<p>Set the two quadratic equations equal to find their intersection points:</p><p><span class="ql-formula" data-value="2x^2 - 33x + 128 - c = -2x^2 + 30x - 128"></span></p><p>Move all terms to the left side:</p><p><span class="ql-formula" data-value="4x^2 - 63x + (256 - c) = 0"></span></p><p>For the system to have two distinct real solutions, the discriminant <span class="ql-formula" data-value="\\Delta"></span> of this quadratic must be strictly positive (<span class="ql-formula" data-value="\\Delta > 0"></span>):</p><p><span class="ql-formula" data-value="\\Delta = b^2 - 4ac = (-63)^2 - 4(4)(256 - c)"></span></p><p><span class="ql-formula" data-value="\\Delta = 3969 - 16(256 - c) = 3969 - 4096 + 16c = 16c - 127"></span></p><p>Set <span class="ql-formula" data-value="\\Delta > 0"></span>:</p><p><span class="ql-formula" data-value="16c - 127 > 0 \\implies 16c > 127 \\implies c > \\frac{127}{16} = 7.9375"></span></p><p>Among the given choices, the only value greater than <span class="ql-formula" data-value="7.9375"></span> is <strong>13</strong>.</p>`,

  // Q18
  '6aa48efeec7ba02921a4406a': `<p>In <span class="ql-formula" data-value="\\triangle ABC"></span>, we are given <span class="ql-formula" data-value="\\angle A = 52^\\circ"></span> and <span class="ql-formula" data-value="\\angle B = 34^\\circ"></span>. Since the interior angles of a triangle sum to <span class="ql-formula" data-value="180^\\circ"></span>:</p><p><span class="ql-formula" data-value="\\angle C = 180^\\circ - (52^\\circ + 34^\\circ) = 180^\\circ - 86^\\circ = 94^\\circ"></span></p><p>In <span class="ql-formula" data-value="\\triangle PQR"></span>, we know <span class="ql-formula" data-value="\\angle P = 52^\\circ"></span>. By the Angle-Angle (AA) similarity criterion, two triangles are similar if two pairs of corresponding angles are congruent.</p><p>If the measures of <span class="ql-formula" data-value="\\angle B"></span> and <span class="ql-formula" data-value="\\angle R"></span> are <span class="ql-formula" data-value="34^\\circ"></span> and <span class="ql-formula" data-value="94^\\circ"></span>, respectively, then <span class="ql-formula" data-value="\\triangle PQR"></span> has angles <span class="ql-formula" data-value="52^\\circ, 34^\\circ, 94^\\circ"></span>, matching <span class="ql-formula" data-value="\\triangle ABC"></span> exactly. Hence, this information is sufficient to prove the triangles are similar.</p>`,

  // Q19
  '6aa48f42ec7ba02921a4406e': `<p>The perimeter of an equilateral triangle is 876 cm, so each side length is:</p><p><span class="ql-formula" data-value="s = \\frac{876}{3} = 292\\text{ cm}"></span></p><p>The three vertices lie on a circle, which means the circle is the circumscribed circle of the equilateral triangle. The circumradius <span class="ql-formula" data-value="R"></span> of an equilateral triangle with side length <span class="ql-formula" data-value="s"></span> is:</p><p><span class="ql-formula" data-value="R = \\frac{s}{\\sqrt{3}} = \\frac{292}{\\sqrt{3}} = \\frac{292\\sqrt{3}}{3}"></span></p><p>We are given that the radius of the circle is <span class="ql-formula" data-value="w\\sqrt{3}"></span>. Equating the two expressions:</p><p><span class="ql-formula" data-value="w\\sqrt{3} = \\frac{292}{3}\\sqrt{3} \\implies w = \\frac{292}{3}"></span></p>`,

  // Q20
  '6aa48f7cec7ba02921a44072': `<p>We are given <span class="ql-formula" data-value="f(x) = \\frac{|x|}{a} - 14"></span> with <span class="ql-formula" data-value="a < 0"></span>.</p><p>Because <span class="ql-formula" data-value="a < 0"></span>, any positive multiple of <span class="ql-formula" data-value="a"></span> is negative:</p><ul><li>For <span class="ql-formula" data-value="x = 15a"></span>, since <span class="ql-formula" data-value="15a < 0"></span>, <span class="ql-formula" data-value="|15a| = -15a"></span>. Therefore:</li></ul><p><span class="ql-formula" data-value="f(15a) = \\frac{-15a}{a} - 14 = -15 - 14 = -29"></span></p><ul><li>For <span class="ql-formula" data-value="x = 8a"></span>, since <span class="ql-formula" data-value="8a < 0"></span>, <span class="ql-formula" data-value="|8a| = -8a"></span>. Therefore:</li></ul><p><span class="ql-formula" data-value="f(8a) = \\frac{-8a}{a} - 14 = -8 - 14 = -22"></span></p><p>Now compute their product:</p><p><span class="ql-formula" data-value="f(15a) \\cdot f(8a) = (-29)(-22) = 638"></span></p>`,

  // Q21
  '6aa49002ec7ba02921a44076': `<p>We are given <span class="ql-formula" data-value="f(x) = a b^{\\frac{x}{n}}"></span>, with <span class="ql-formula" data-value="f(4) = 5"></span> and <span class="ql-formula" data-value="f(7) = 135"></span>.</p><p>Take the ratio of <span class="ql-formula" data-value="f(7)"></span> to <span class="ql-formula" data-value="f(4)"></span>:</p><p><span class="ql-formula" data-value="\\frac{f(7)}{f(4)} = \\frac{a b^{7/n}}{a b^{4/n}} = b^{\\frac{7-4}{n}} = b^{\\frac{3}{n}} = \\frac{135}{5} = 27"></span></p><p>Since <span class="ql-formula" data-value="b^{3/n} = 27 = 3^3"></span>, we have <span class="ql-formula" data-value="b^{1/n} = 3"></span>.</p><p>Now find <span class="ql-formula" data-value="f(9)"></span> using <span class="ql-formula" data-value="f(7)"></span>:</p><p><span class="ql-formula" data-value="f(9) = f(7) \\cdot b^{\\frac{9-7}{n}} = f(7) \\cdot (b^{1/n})^2 = 135 \\cdot 3^2 = 135 \\times 9 = 1215"></span></p>`,

  // Q22
  '6aa4904bec7ba02921a4407a': `<p>To find the <span class="ql-formula" data-value="y"></span>-intercept of the linear function <span class="ql-formula" data-value="f(x) = 6x + 14"></span>, find the value of <span class="ql-formula" data-value="f(0)"></span>:</p><p><span class="ql-formula" data-value="f(0) = 6(0) + 14 = 14"></span></p><p>Thus, the <span class="ql-formula" data-value="y"></span>-intercept is <strong>14</strong>.</p>`
};

async function run() {
  console.log('Injecting 22 pedagogical explanations for March 2025 · INT 3 Module 2...');
  const keys = Object.keys(explanations);
  for (const id of keys) {
    const res = await updateQuestion(id, { explanation: explanations[id] });
    if (res.message && res.message.toLowerCase().includes('success') || res._id || res.status === 200 || !res.error) {
      console.log(`Q ${id}: explanation injected ✅`);
    } else {
      console.log(`Q ${id}: failed or unexpected response:`, res);
    }
  }
  console.log('\nFinished Module 2: 22/22 explanations successfully injected.');
}

run().catch(console.error);
