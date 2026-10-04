const axios = require('axios');

const API_BASE = 'https://sat-backend-production.up.railway.app';

// 22 explanations for March 2025 · INT 1 Module 2
const explanationsM2 = {
  // Q1
  '6aa112fffebc2d25093882c4': `<p>We are given that:</p>
<p>1) <span class="ql-formula" data-value="a = 21.36(b + c)"></span> (since <span class="ql-formula" data-value="2136\\% = 21.36"></span>)</p>
<p>2) <span class="ql-formula" data-value="b = 0.89c \\implies c = \\frac{b}{0.89}"></span></p>
<p>Substitute <span class="ql-formula" data-value="c = \\frac{b}{0.89}"></span> into the expression for <span class="ql-formula" data-value="b + c"></span>:</p>
<p><span class="ql-formula" data-value=\"b + c = b + \\frac{b}{0.89} = b\\left(1 + \\frac{1}{0.89}\\right) = b\\left(\\frac{1.89}{0.89}\\right)\"></span></p>
<p>Now substitute this into the equation for <span class="ql-formula" data-value="a"></span>:</p>
<p><span class="ql-formula" data-value=\"a = 21.36 \\cdot b\\left(\\frac{1.89}{0.89}\\right) = b \\left(\\frac{21.36 \\times 1.89}{0.89}\\right)\"></span></p>
<p>Calculate the coefficient of <span class="ql-formula" data-value="b"></span>:</p>
<p><span class="ql-formula" data-value=\"\\frac{40.3704}{0.89} = 45.36\"></span></p>
<p>So, <span class="ql-formula" data-value="a = 45.36b"></span>. To express what percent of <span class="ql-formula" data-value="b"></span> is <span class="ql-formula" data-value="a"></span>, multiply by 100%:</p>
<p><span class="ql-formula" data-value=\"45.36 \\times 100\\% = 4536\\%\"></span></p>
<p>Therefore, <span class="ql-formula" data-value="a"></span> is <strong><span class="ql-formula" data-value="4536\\%"></span></strong> of <span class="ql-formula" data-value="b"></span>.</p>`,

  // Q2
  '6aa11386febc2d25093882c8': `<p>For the linear function <span class="ql-formula" data-value="p(x)"></span>, the slope is 7 and <span class="ql-formula" data-value="p(3) = 23"></span>. In point-slope form:</p>
<p><span class="ql-formula" data-value="p(x) - 23 = 7(x - 3) \\implies p(x) = 7x + 2"></span></p>
<p>We are given that <span class="ql-formula" data-value="p(c) = -5"></span>. Solve for <span class="ql-formula" data-value="c"></span>:</p>
<p><span class="ql-formula" data-value="7c + 2 = -5 \\implies 7c = -7 \\implies c = -1"></span></p>
<p>For the linear function <span class="ql-formula" data-value="t(x)"></span>, we are given two points on its graph: <span class="ql-formula" data-value="(c, -6) = (-1, -6)"></span> and <span class="ql-formula" data-value="(4, 34)"></span>.</p>
<p>The slope of line <span class="ql-formula" data-value="t"></span> is:</p>
<p><span class="ql-formula" data-value=\"\\text{slope} = \\frac{34 - (-6)}{4 - (-1)} = \\frac{40}{5} = 8\"></span></p>
<p>Therefore, the slope is <strong>8</strong>.</p>`,

  // Q3
  '6aa113c0febc2d25093882cc': `<p>Notice that the expression <span class="ql-formula" data-value="(3 - 7x)"></span> appears on both sides of the equation. Let <span class="ql-formula" data-value="u = 3 - 7x"></span>.</p>
<p>Substitute <span class="ql-formula" data-value="u"></span> into the given equation:</p>
<p><span class="ql-formula" data-value="16 - 5u = 4 - 6u"></span></p>
<p>Add <span class="ql-formula" data-value="6u"></span> to both sides:</p>
<p><span class="ql-formula" data-value="16 + u = 4"></span></p>
<p>Subtract 16 from both sides:</p>
<p><span class="ql-formula" data-value="u = 4 - 16 = -12"></span></p>
<p>Since <span class="ql-formula" data-value="u = 3 - 7x"></span>, the value of <span class="ql-formula" data-value="3 - 7x"></span> is <strong>-12</strong>.</p>`,

  // Q4
  '6aa115d2febc2d25093882d0': `<p>In right triangle <span class="ql-formula" data-value="ABC"></span> with acute angles <span class="ql-formula" data-value="A"></span> and <span class="ql-formula" data-value="B"></span>, the tangent of angle <span class="ql-formula" data-value="B"></span> is defined as the ratio of the length of the opposite leg to the adjacent leg:</p>
<p><span class="ql-formula" data-value=\"\\tan(B) = \\frac{AC}{BC}\"></span></p>
<p>We are given that <span class="ql-formula" data-value=\"\\tan(B) = \\frac{1}{3}\"></span> and <span class="ql-formula" data-value="AC = 28.2"></span>:</p>
<p><span class="ql-formula" data-value=\"\\frac{1}{3} = \\frac{28.2}{BC}\"></span></p>
<p>Cross-multiplying gives:</p>
<p><span class="ql-formula" data-value=\"BC = 3 \\times 28.2 = 84.6\"></span></p>
<p>Therefore, the length of side <span class="ql-formula" data-value="BC"></span> is <strong>84.6</strong>.</p>`,

  // Q5
  '6aa1169efebc2d25093882d4': `<p>First, evaluate <span class="ql-formula" data-value="g(-10)"></span> using the definition <span class="ql-formula" data-value="g(x) = |12x - 7|"></span>:</p>
<p><span class="ql-formula" data-value="g(-10) = |12(-10) - 7| = |-120 - 7| = |-127| = 127"></span></p>
<p>Next, substitute <span class="ql-formula" data-value="g(-10) = 127"></span> into the definition of <span class="ql-formula" data-value="f(x) = 5(g(x)) - 3"></span>:</p>
<p><span class="ql-formula" data-value="f(-10) = 5(127) - 3 = 635 - 3 = 632"></span></p>
<p>Therefore, the value of <span class="ql-formula" data-value="f(-10)"></span> is <strong>632</strong>.</p>`,

  // Q6
  '6aa1172ef5c99543faeb6316': `<p>Every visitor is in room A, room B, or room C, so the probabilities must sum to 1:</p>
<p><span class="ql-formula" data-value="P(A) + P(B) + P(C) = 1"></span></p>
<p>Substitute the given probabilities:</p>
<p><span class="ql-formula" data-value="0.72 + 0.24 + P(C) = 1 \\implies 0.96 + P(C) = 1 \\implies P(C) = 0.04"></span></p>
<p>To find the number of visitors in room C, multiply the total number of visitors by the probability <span class="ql-formula" data-value="P(C)"></span>:</p>
<p><span class="ql-formula" data-value=\"\\text{Number of visitors in room C} = 0.04 \\times 225 = 9\"></span></p>
<p>Therefore, there are <strong>9</strong> visitors located in room C.</p>`,

  // Q7
  '6aa11773f5c99543faeb631a': `<p>The function is defined as <span class="ql-formula" data-value="f(x) = 293\\% \\text{ of } x"></span>. Converting the percentage to a decimal:</p>
<p><span class="ql-formula" data-value="f(x) = 2.93x"></span></p>
<p>This is of the form <span class="ql-formula" data-value="f(x) = mx"></span> with positive constant rate of change <span class="ql-formula" data-value="m = 2.93 > 0"></span>.</p>
<p>Since the variable <span class="ql-formula" data-value="x"></span> is raised to the first power and has a constant positive rate of change, the function is <strong>Increasing linear</strong>.</p>`,

  // Q8
  '6aa117aef5c99543faeb63ec': `<p>To find the equivalent expression for <span class="ql-formula" data-value="11x^{10} - 11x^9 + 77x"></span>, factor out the greatest common factor (GCF):</p>
<p>The coefficients 11, -11, and 77 share a common factor of 11. The terms <span class="ql-formula" data-value="x^{10}, x^9, x"></span> share a common factor of <span class="ql-formula" data-value="x"></span>. Thus, the GCF is <span class="ql-formula" data-value="11x"></span>.</p>
<p>Factoring out <span class="ql-formula" data-value="11x"></span>:</p>
<p><span class="ql-formula" data-value=\"11x^{10} - 11x^9 + 77x = 11x(x^9 - x^8 + 7)\"></span></p>
<p>Therefore, the equivalent expression is <strong><span class="ql-formula" data-value=\"11x(x^9 - x^8 + 7)\"></span></strong>.</p>`,

  // Q9
  '6aa117e7f5c99543faeb6410': `<p>The area of a rectangle is given by <span class="ql-formula" data-value=\"\\text{Area} = \\text{length} \\times \\text{width}\"></span>.</p>
<p>The problem states that the width is <span class="ql-formula" data-value="w"></span>, and the length is 31 times its width, which is <span class="ql-formula" data-value="31w"></span>.</p>
<p>In the formula <span class="ql-formula" data-value=\"y = (31w)(w)\"></span>, the factor <span class="ql-formula" data-value="31w"></span> represents the length of the rectangle.</p>
<p>Therefore, the best interpretation of <span class="ql-formula" data-value="31w"></span> is <strong>The length of the rectangle, in feet</strong>.</p>`,

  // Q10
  '6aa1181bf5c99543faeb6434': `<p>In the linear equation <span class="ql-formula" data-value="0.6t + 7 = 11"></span>, <span class="ql-formula" data-value="t"></span> represents time in months and the terms represent lengths in inches:</p>
<ul>
  <li>7 is the initial length of hair in inches.</li>
  <li>11 is the final target length of hair in inches.</li>
  <li><span class="ql-formula" data-value="0.6t"></span> represents the total growth in inches after <span class="ql-formula" data-value="t"></span> months.</li>
</ul>
<p>Therefore, the coefficient 0.6 represents the constant monthly rate of hair growth: <strong>The length, in inches, Audrey's hair will grow each month</strong>.</p>`,

  // Q11
  '6aa119ccf5c99543faeb65aa': `<p>The calf's birth weight is 226 pounds, which represents the initial value (the <span class="ql-formula" data-value="y"></span>-intercept when <span class="ql-formula" data-value="x = 0"></span>).</p>
<p>The calf gains an average of 3 pounds per day, which represents a constant rate of change (slope) of +3 pounds per day.</p>
<p>After <span class="ql-formula" data-value="x"></span> days, the total weight gained is <span class="ql-formula" data-value="3x"></span>.</p>
<p>Adding this to the birth weight gives the equation:</p>
<p><span class="ql-formula" data-value="y = 226 + 3x"></span></p>
<p>Therefore, the correct equation is <strong><span class="ql-formula" data-value="y = 226 + 3x"></span></strong>.</p>`,

  // Q12
  '6aa11a4ef5c99543faeb65ae': `<p>Set the two expressions for <span class="ql-formula" data-value="y"></span> equal to each other:</p>
<p><span class="ql-formula" data-value="3x^2 + 13 = 3x + 13"></span></p>
<p>Subtract 13 from both sides:</p>
<p><span class="ql-formula" data-value="3x^2 = 3x"></span></p>
<p>Subtract <span class="ql-formula" data-value="3x"></span> from both sides and factor:</p>
<p><span class="ql-formula" data-value="3x(x - 1) = 0"></span></p>
<p>This gives two possible values for <span class="ql-formula" data-value="x"></span>: <span class="ql-formula" data-value="x = 0"></span> or <span class="ql-formula" data-value="x = 1"></span>.</p>
<p>When <span class="ql-formula" data-value="x = 0"></span>, <span class="ql-formula" data-value="y = 3(0) + 13 = 13"></span>, giving the solution point <span class="ql-formula" data-value="(0, 13)"></span>.</p>
<p>Among the given choices, <strong>(0, 13)</strong> is the correct ordered pair.</p>`,

  // Q13
  '6aa11d8eec7ba02921a31b72': `<p>The linear relation between temperature in degrees Fahrenheit <span class="ql-formula" data-value="F"></span> and kelvins <span class="ql-formula" data-value="x"></span> is:</p>
<p><span class="ql-formula" data-value=\"F(x) = \\frac{9}{5}(x - 273.15) + 32 = \\frac{9}{5}x + C\"></span></p>
<p>Since the relationship is linear with slope <span class="ql-formula" data-value=\"\\frac{9}{5}\"></span>, any change in kelvins <span class="ql-formula" data-value=\"\\Delta x\"></span> causes a change in Fahrenheit <span class="ql-formula" data-value=\"\\Delta F\"></span> given by:</p>
<p><span class="ql-formula" data-value=\"\\Delta F = \\frac{9}{5}\\Delta x\"></span></p>
<p>Given <span class="ql-formula" data-value=\"\\Delta x = 7.70\"></span>:</p>
<p><span class="ql-formula" data-value=\"\\Delta F = \\frac{9}{5}(7.70) = 9 \\times 1.54 = 13.86\"></span></p>
<p>Therefore, the temperature increased by <strong>13.86</strong> degrees Fahrenheit (or <span class="ql-formula" data-value=\"\\frac{693}{50}\"></span>).</p>`,

  // Q14
  '6aa11dc5ec7ba02921a31b76': `<p>Since the quadratic function has its vertex at <span class="ql-formula" data-value="(1, 4)"></span>, its equation in vertex form is:</p>
<p><span class="ql-formula" data-value="f(x) = a(x - 1)^2 + 4"></span></p>
<p>Use the point <span class="ql-formula" data-value="(2, 27)"></span> to determine <span class="ql-formula" data-value="a"></span>:</p>
<p><span class="ql-formula" data-value="27 = a(2 - 1)^2 + 4 = a(1) + 4 \\implies a = 23"></span></p>
<p>Check with <span class="ql-formula" data-value="(-1, 96)"></span>: <span class="ql-formula" data-value="f(-1) = 23(-1 - 1)^2 + 4 = 23(4) + 4 = 92 + 4 = 96"></span>, which confirms <span class="ql-formula" data-value="a = 23"></span>.</p>
<p>Now evaluate <span class="ql-formula" data-value="f(-2)"></span> and <span class="ql-formula" data-value="f(0)"></span>:</p>
<p><span class="ql-formula" data-value="f(-2) = 23(-2 - 1)^2 + 4 = 23(-3)^2 + 4 = 23(9) + 4 = 207 + 4 = 211"></span></p>
<p><span class="ql-formula" data-value="f(0) = 23(0 - 1)^2 + 4 = 23(1) + 4 = 27"></span></p>
<p>Finally, find the difference:</p>
<p><span class="ql-formula" data-value="f(-2) - f(0) = 211 - 27 = 184"></span></p>
<p>Therefore, the correct answer is <strong>184</strong>.</p>`,

  // Q15
  '6aa11e02ec7ba02921a31b7a': `<p>Find the slope <span class="ql-formula" data-value="m"></span> using two points from the table, <span class="ql-formula" data-value="(-2s, 28)"></span> and <span class="ql-formula" data-value="(-s, 23)"></span>:</p>
<p><span class="ql-formula" data-value=\"m = \\frac{23 - 28}{-s - (-2s)} = \\frac{-5}{s} = -\\frac{5}{s}\"></span></p>
<p>Now use the point-slope form with point <span class="ql-formula" data-value="(s, 13)"></span>:</p>
<p><span class="ql-formula" data-value=\"y - 13 = -\\frac{5}{s}(x - s)\"></span></p>
<p>Multiply both sides by <span class="ql-formula" data-value="s"></span>:</p>
<p><span class="ql-formula" data-value="s(y - 13) = -5(x - s)"></span></p>
<p><span class="ql-formula" data-value="sy - 13s = -5x + 5s"></span></p>
<p>Rearrange terms to group <span class="ql-formula" data-value="x"></span> and <span class="ql-formula" data-value="y"></span> on the left side:</p>
<p><span class="ql-formula" data-value="5x + sy = 13s + 5s = 18s"></span></p>
<p>Thus, the equation is <strong><span class="ql-formula" data-value="5x + sy = 18s"></span></strong>.</p>`,

  // Q16
  '6aa11e30ec7ba02921a31b7e': `<p>By the Triangle Inequality Theorem, the length of any side of a triangle must be strictly greater than the positive difference of the other two sides and strictly less than their sum.</p>
<p>For side lengths 7 and 10:</p>
<p><span class="ql-formula" data-value="10 - 7 < x < 10 + 7"></span></p>
<p><span class="ql-formula" data-value="3 < x < 17"></span></p>
<p>Therefore, the possible lengths for the third side are given by <strong><span class="ql-formula" data-value="3 < x < 17"></span></strong>.</p>`,

  // Q17
  '6aa11e8aec7ba02921a31b82': `<p>The graph shows the function <span class="ql-formula" data-value="y = f(x) + 4"></span>.</p>
<p>Observe the key features of the displayed graph:</p>
<ul>
  <li>The horizontal asymptote as <span class="ql-formula" data-value="x \\to -\\infty"></span> is <span class="ql-formula" data-value="y = 9"></span>.</li>
  <li>The <span class="ql-formula" data-value="y"></span>-intercept is at <span class="ql-formula" data-value="(0, 8)"></span>.</li>
</ul>
<p>Since the displayed curve is <span class="ql-formula" data-value="y = f(x) + 4"></span>, we have:</p>
<p><span class="ql-formula" data-value="f(0) + 4 = 8 \\implies f(0) = 4"></span></p>
<p>Now evaluate <span class="ql-formula" data-value="f(0)"></span> for the given options:</p>
<ul>
  <li>If <span class="ql-formula" data-value="f(x) = -6^x + 5"></span>: <span class="ql-formula" data-value="f(0) = -(6^0) + 5 = -1 + 5 = 4"></span>. Then <span class="ql-formula" data-value="y = f(x) + 4 = -6^x + 5 + 4 = -6^x + 9"></span>, which has horizontal asymptote <span class="ql-formula" data-value="y = 9"></span> and <span class="ql-formula" data-value="y"></span>-intercept <span class="ql-formula" data-value="(0, 8)"></span>.</li>
</ul>
<p>This matches the graph perfectly. Therefore, the function is <strong><span class="ql-formula" data-value="f(x) = -6^x + 5"></span></strong>.</p>`,

  // Q18
  '6aa11f14ec7ba02921a31b86': `<p>Because <span class="ql-formula" data-value=\"LM \\parallel PQ\"></span>, alternate interior angles are equal:</p>
<p><span class="ql-formula" data-value=\"\\angle MLR = \\angle PQR\"></span> and <span class="ql-formula" data-value=\"\\angle LMR = \\angle QPR\"></span></p>
<p>Also, the vertical angles at <span class="ql-formula" data-value="R"></span> are equal (<span class="ql-formula" data-value=\"\\angle LRM = \\angle QRP\"></span>). Therefore, <span class="ql-formula" data-value=\"\\Delta LMR \\sim \\Delta QPR\"></span> by AA similarity.</p>
<p>The scale factor of corresponding sides is:</p>
<p><span class="ql-formula" data-value=\"k = \\frac{RP}{MR} = \\frac{14}{8} = \\frac{7}{4}\"></span></p>
<p>The ratio of the areas of similar triangles equals the square of the scale factor of their sides:</p>
<p><span class="ql-formula" data-value=\"\\frac{\\text{Area}(\\Delta PQR)}{\\text{Area}(\\Delta LMR)} = k^2 = \\left(\\frac{7}{4}\\right)^2 = \\frac{49}{16}\"></span></p>
<p>We are given that <span class="ql-formula" data-value=\"\\text{Area}(\\Delta LMR) = 36\"></span>:</p>
<p><span class="ql-formula" data-value=\"\\text{Area}(\\Delta PQR) = 36 \\times \\frac{49}{16} = 9 \\times \\frac{49}{4} = \\frac{441}{4}\"></span></p>
<p>Therefore, the area of <span class="ql-formula" data-value=\"\\Delta PQR\"></span> is <strong><span class="ql-formula" data-value=\"\\frac{441}{4}\"></span></strong> (or 110.25).</p>`,

  // Q19
  '6aa11f34ec7ba02921a31b8a': `<p>Set the function <span class="ql-formula" data-value="g(x) = 3x"></span> equal to 12:</p>
<p><span class="ql-formula" data-value="3x = 12"></span></p>
<p>Divide both sides by 3:</p>
<p><span class="ql-formula" data-value="x = 4"></span></p>
<p>Therefore, the value of <span class="ql-formula" data-value="x"></span> is <strong>4</strong>.</p>`,

  // Q20
  '6aa11f82ec7ba02921a31b8e': `<p>For two similar three-dimensional solids, the ratio of their surface areas is the square of the linear scale factor <span class="ql-formula" data-value="k"></span>:</p>
<p><span class="ql-formula" data-value=\"\\frac{SA_X}{SA_Y} = \\frac{59}{1475} = \\frac{1}{25}\"></span></p>
<p>Taking the square root gives the linear ratio:</p>
<p><span class="ql-formula" data-value=\"k = \\sqrt{\\frac{1}{25}} = \\frac{1}{5}\"></span></p>
<p>The ratio of their volumes is the cube of the linear ratio:</p>
<p><span class="ql-formula" data-value=\"\\frac{V_X}{V_Y} = k^3 = \\left(\\frac{1}{5}\\right)^3 = \\frac{1}{125}\"></span></p>
<p>Given that <span class="ql-formula" data-value=\"V_Y = 1500\\text{ cm}^3\"></span>:</p>
<p><span class="ql-formula" data-value=\"V_X = \\frac{1500}{125} = 12\\text{ cm}^3\"></span></p>
<p>Now compute the sum of the volumes:</p>
<p><span class="ql-formula" data-value=\"V_X + V_Y = 12 + 1500 = 1512\\text{ cm}^3\"></span></p>
<p>Therefore, the sum of the volumes is <strong>1512</strong>.</p>`,

  // Q21
  '6aa11fe6ec7ba02921a31b92': `<p>The exponential function is given as <span class="ql-formula" data-value=\"f(x) = a b^{\\frac{x}{n}}\"></span>.</p>
<p>We are given:</p>
<p>1) <span class="ql-formula" data-value=\"f(3) = a b^{\\frac{3}{n}} = 6\"></span></p>
<p>2) <span class="ql-formula" data-value=\"f(5) = a b^{\\frac{5}{n}} = 150\"></span></p>
<p>Divide the second equation by the first equation:</p>
<p><span class="ql-formula" data-value=\"\\frac{f(5)}{f(3)} = \\frac{a b^{5/n}}{a b^{3/n}} = b^{\\frac{5 - 3}{n}} = b^{\\frac{2}{n}} = \\frac{150}{6} = 25\"></span></p>
<p>Since <span class="ql-formula" data-value=\"b^{\\frac{2}{n}} = 25 = 5^2\"></span> and <span class="ql-formula" data-value="b, n"></span> are integers, taking the square root gives:</p>
<p><span class="ql-formula" data-value=\"b^{\\frac{1}{n}} = 5\"></span></p>
<p>Now, to find <span class="ql-formula" data-value=\"f(6)\"></span>:</p>
<p><span class="ql-formula" data-value=\"f(6) = a b^{\\frac{6}{n}} = a b^{\\frac{5}{n}} \\cdot b^{\\frac{1}{n}} = f(5) \\cdot b^{\\frac{1}{n}}\"></span></p>
<p>Substitute <span class="ql-formula" data-value=\"f(5) = 150\"></span> and <span class="ql-formula" data-value=\"b^{1/n} = 5\"></span>:</p>
<p><span class="ql-formula" data-value=\"f(6) = 150 \\times 5 = 750\"></span></p>
<p>Therefore, the value of <span class="ql-formula" data-value="f(6)"></span> is <strong>750</strong>.</p>`,

  // Q22
  '6aa12018ec7ba02921a31b9b': `<p>For any quadratic equation <span class="ql-formula" data-value="Ax^2 + Bx + C = 0"></span>, by Vieta's formulas, the sum of the solutions is:</p>
<p><span class="ql-formula" data-value=\"\\text{Sum of solutions} = -\\frac{B}{A}\"></span></p>
<p>In the given equation <span class="ql-formula" data-value=\"24x^2 - (12a + 2b)x + ab = 0\"></span>:</p>
<p><span class="ql-formula" data-value="A = 24"></span>, and <span class="ql-formula" data-value="B = -(12a + 2b)"></span>.</p>
<p>Thus, the sum of the solutions is:</p>
<p><span class="ql-formula" data-value=\"-\\frac{-(12a + 2b)}{24} = \\frac{12a + 2b}{24}\"></span></p>
<p>Factor out 2 from the numerator:</p>
<p><span class="ql-formula" data-value=\"\\frac{2(6a + b)}{24} = \\frac{1}{12}(6a + b)\"></span></p>
<p>We are given that the sum of the solutions is <span class="ql-formula" data-value=\"k(6a + b)\"></span>. Comparing coefficients gives:</p>
<p><span class="ql-formula" data-value=\"k = \\frac{1}{12}\"></span></p>
<p>Therefore, the value of <span class="ql-formula" data-value="k"></span> is <strong><span class="ql-formula" data-value=\"\\frac{1}{12}\"></span></strong>.</p>`
};

async function main() {
  console.log('Injecting 22 pedagogical explanations for March 2025 · INT 1 Module 2...');
  let successCount = 0;

  for (const [id, explanation] of Object.entries(explanationsM2)) {
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

  console.log(`\nFinished Module 2: ${successCount}/22 explanations successfully injected.`);
}

main();
