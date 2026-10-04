const axios = require('axios');

const BASE_URL = 'https://sat-backend-production.up.railway.app';

function mathSpan(latex) {
  return `<span class="ql-formula" data-value="${latex}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow></mrow><annotation encoding="application/x-tex">${latex}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.7em;"></span><span class="mord">${latex}</span></span></span></span></span>﻿</span>`;
}

const explanations = [
  // M2 Q1: ID 6a53ba6d4d554e04aa1bf703 (Grid-in: 28.2 or 141/5)
  {
    id: '6a53ba6d4d554e04aa1bf703',
    qNum: 'M2 Q1',
    text: `<p><strong>The correct answer is 28.2 (or 141/5).</strong></p>` +
      `<p>To convert the rate from meters per second squared (${mathSpan('\\text{m/s}^2')}) to miles per minute squared (${mathSpan('\\text{mi/min}^2')}), we convert the distance units and the time units step by step:</p>` +
      `<p>1. Convert meters to miles: Since ${mathSpan('1\\text{ mile} = 1.609\\text{ km}')} and ${mathSpan('1\\text{ km} = 1{,}000\\text{ m}')}, ${mathSpan('1\\text{ mile} = 1{,}609\\text{ meters}')}. Therefore, ${mathSpan('1\\text{ meter} = \\frac{1}{1{,}609}\\text{ miles}')}.</p>` +
      `<p>2. Convert seconds to minutes: Since ${mathSpan('1\\text{ minute} = 60\\text{ seconds}')}, ${mathSpan('1\\text{ second} = \\frac{1}{60}\\text{ minutes}')}, which means ${mathSpan('1\\text{ s}^2 = \\left(\\frac{1}{60}\\text{ min}\\right)^2 = \\frac{1}{3{,}600}\\text{ min}^2')}.</p>` +
      `<p>Now substitute these conversions into the rate:</p>` +
      `<p>${mathSpan('12.60 \\times \\frac{\\frac{1}{1{,}609}\\text{ miles}}{\\frac{1}{3{,}600}\\text{ min}^2} = 12.60 \\times \\frac{3{,}600}{1{,}609} = \\frac{45{,}360}{1{,}609} \\approx 28.1914\\dots')}</p>` +
      `<p>Rounding to the nearest tenth yields <strong>28.2</strong>.</p>`
  },

  // M2 Q2: ID 6a53bae04d554e04aa1bf715 (MCQ: Choice A)
  {
    id: '6a53bae04d554e04aa1bf715',
    qNum: 'M2 Q2',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>The amount of pure saline contributed by ${mathSpan('x')} liters of a 6% solution is ${mathSpan('0.06x')} liters. The amount of pure saline contributed by ${mathSpan('y')} liters of a 9% solution is ${mathSpan('0.09y')} liters.</p>` +
      `<p>Since the volumes are additive, the total volume of the mixture is ${mathSpan('x + y')} liters. In a 7% saline solution, the total amount of pure saline is ${mathSpan('0.07(x + y)')} liters.</p>` +
      `<p>Equating the total pure saline before and after mixing gives:</p>` +
      `<p>${mathSpan('0.06x + 0.09y = 0.07(x + y)')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because it uses 7 rather than the decimal equivalent of 7% (${mathSpan('0.07')}) on the right side.</p>` +
      `<p>Choice C is incorrect because 0.6 and 0.9 represent 60% and 90%, not 6% and 9%, and it uses 7 instead of 0.07.</p>` +
      `<p>Choice D is incorrect because 0.6, 0.9, and 0.7 represent 60%, 90%, and 70%, respectively.</p>`
  },

  // M2 Q3: ID 6a53bb7c4d554e04aa1bf721 (Grid-in: 8)
  {
    id: '6a53bb7c4d554e04aa1bf721',
    qNum: 'M2 Q3',
    text: `<p><strong>The correct answer is 8.</strong></p>` +
      `<p>The given expression is ${mathSpan('3x + 5x^2 - 8')}. Writing this quadratic expression in standard form ${mathSpan('ax^2 + bx + c')} by ordering terms in descending powers of ${mathSpan('x')} yields:</p>` +
      `<p>${mathSpan('5x^2 + 3x - 8')}</p>` +
      `<p>Comparing coefficients:</p>` +
      `<p>${mathSpan('a = 5')}, ${mathSpan('b = 3')}, and ${mathSpan('c = -8')}.</p>` +
      `<p>Thus, the value of ${mathSpan('a + b')} is ${mathSpan('5 + 3 = 8')}.</p>`
  },

  // M2 Q4: ID 6a53bc0d4d554e04aa1bf742 (MCQ: Choice A, 7)
  {
    id: '6a53bc0d4d554e04aa1bf742',
    qNum: 'M2 Q4',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>The area of a rectangle is the product of its length and width: ${mathSpan('\\text{Area} = \\text{length} \\times \\text{width}')}. Given length ${mathSpan('x')} and width ${mathSpan('x - 3')}, the area is 28 square units:</p>` +
      `<p>${mathSpan('x(x - 3) = 28')}</p>` +
      `<p>Expanding and rearranging into standard quadratic form:</p>` +
      `<p>${mathSpan('x^2 - 3x - 28 = 0')}</p>` +
      `<p>Factoring the quadratic equation:</p>` +
      `<p>${mathSpan('(x - 7)(x + 4) = 0')}</p>` +
      `<p>This gives solutions ${mathSpan('x = 7')} or ${mathSpan('x = -4')}. Since length must be positive, ${mathSpan('x = 7')} units.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because 4 is the width of the rectangle (${mathSpan('7 - 3 = 4')}), not the length ${mathSpan('x')}.</p>` +
      `<p>Choice C is incorrect because 11 results in an area of ${mathSpan('11 \\times (11 - 3) = 11 \\times 8 = 88 \\neq 28')}.</p>` +
      `<p>Choice D is incorrect because 28 is the area, not the length.</p>`
  },

  // M2 Q5: ID 6a53bc734d554e04aa1bf758 (Grid-in: -3)
  {
    id: '6a53bc734d554e04aa1bf758',
    qNum: 'M2 Q5',
    text: `<p><strong>The correct answer is -3.</strong></p>` +
      `<p>Translate the verbal statement into an inequality:</p>` +
      `<p>"3 times the value of ${mathSpan('y')}" is ${mathSpan('3y')}.</p>` +
      `<p>"27 less than 3 times the value of ${mathSpan('y')}" is ${mathSpan('3y - 27')}.</p>` +
      `<p>"${mathSpan('x')} is at most 27 less than 3 times the value of ${mathSpan('y')}" means ${mathSpan('x \\le 3y - 27')}.</p>` +
      `<p>Substitute ${mathSpan('y = 8')}:</p>` +
      `<p>${mathSpan('x \\le 3(8) - 27 = 24 - 27 = -3')}</p>` +
      `<p>Therefore, the greatest possible value of ${mathSpan('x')} is <strong>-3</strong>.</p>`
  },

  // M2 Q6: ID 6a53bcea4d554e04aa1bf764 (MCQ: Choice A, 2.5)
  {
    id: '6a53bcea4d554e04aa1bf764',
    qNum: 'M2 Q6',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>We are given the rational equation:</p>` +
      `<p>${mathSpan('\\frac{1}{3 - x} = \\frac{x - 1}{x} + 1.4')}</p>` +
      `<p>Rewrite ${mathSpan('1.4')} as a fraction: ${mathSpan('1.4 = \\frac{7}{5}')}. Combine the right side over a common denominator ${mathSpan('5x')}:</p>` +
      `<p>${mathSpan('\\frac{x - 1}{x} + \\frac{7}{5} = \\frac{5(x - 1) + 7x}{5x} = \\frac{12x - 5}{5x}')}</p>` +
      `<p>Now equate the fractions and cross-multiply:</p>` +
      `<p>${mathSpan('\\frac{1}{3 - x} = \\frac{12x - 5}{5x}')}</p>` +
      `<p>${mathSpan('5x = (3 - x)(12x - 5)')}</p>` +
      `<p>${mathSpan('5x = 36x - 15 - 12x^2 + 5x')}</p>` +
      `<p>${mathSpan('12x^2 - 36x + 15 = 0')}</p>` +
      `<p>Divide every term by 3:</p>` +
      `<p>${mathSpan('4x^2 - 12x + 5 = 0')}</p>` +
      `<p>Factor the quadratic:</p>` +
      `<p>${mathSpan('(2x - 5)(2x - 1) = 0')}</p>` +
      `<p>Setting each factor to zero gives ${mathSpan('x = \\frac{5}{2} = 2.5')} or ${mathSpan('x = \\frac{1}{2} = 0.5')}.</p>` +
      `<p>Among the given choices, <strong>2.5</strong> is the solution.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect; testing ${mathSpan('x = 0.75')} yields ${mathSpan('\\frac{1}{3 - 0.75} = \\frac{1}{2.25} = \\frac{4}{9}')}, whereas ${mathSpan('\\frac{0.75 - 1}{0.75} + 1.4 = -\\frac{1}{3} + 1.4 = 1.067 \\neq \\frac{4}{9}')}.</p>` +
      `<p>Choice C is incorrect because ${mathSpan('x = 3')} makes the denominator ${mathSpan('3 - x = 0')}, which is undefined.</p>` +
      `<p>Choice D is incorrect because ${mathSpan('x = 4')} yields ${mathSpan('\\frac{1}{3 - 4} = -1')}, whereas ${mathSpan('\\frac{4 - 1}{4} + 1.4 = 0.75 + 1.4 = 2.15 \\neq -1')}.</p>`
  },

  // M2 Q7: ID 6a53bd664d554e04aa1bf770 (MCQ: Choice A)
  {
    id: '6a53bd664d554e04aa1bf770',
    qNum: 'M2 Q7',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>The table provides three points ${mathSpan('(c, p)')}: (2, 81), (5, 189), and (10, 369). We find the slope ${mathSpan('m')} of the linear relationship:</p>` +
      `<p>${mathSpan('m = \\frac{189 - 81}{5 - 2} = \\frac{108}{3} = 36')}</p>` +
      `<p>Using the point-slope form with ${mathSpan('(2, 81)')}:</p>` +
      `<p>${mathSpan('p - 81 = 36(c - 2)')}</p>` +
      `<p>${mathSpan('p - 81 = 36c - 72')}</p>` +
      `<p>${mathSpan('p = 36c + 9')}</p>` +
      `<p>Rearranging this equation into standard form by subtracting ${mathSpan('p')} and 9 from both sides yields:</p>` +
      `<p>${mathSpan('36c - p = -9')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because ${mathSpan('36c - p = 9')} would mean ${mathSpan('p = 36c - 9')}, which gives ${mathSpan('p = 36(2) - 9 = 63 \\neq 81')}.</p>` +
      `<p>Choice C is incorrect because it swaps the variables ${mathSpan('c')} and ${mathSpan('p')}.</p>` +
      `<p>Choice D is incorrect because it swaps the variables and has an incorrect constant sign.</p>`
  },

  // M2 Q8: ID 6a53bdbb4d554e04aa1bf77c (MCQ: Choice A)
  {
    id: '6a53bdbb4d554e04aa1bf77c',
    qNum: 'M2 Q8',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>A system of two linear equations has no solution if the lines have the same slope but different ${mathSpan('y')}-intercepts (parallel distinct lines).</p>` +
      `<p>First, write the given equation in slope-intercept form ${mathSpan('y = mx + b')}:</p>` +
      `<p>${mathSpan('20x = 1{,}200y - 2{,}000')}</p>` +
      `<p>${mathSpan('1{,}200y = 20x + 2{,}000')}</p>` +
      `<p>${mathSpan('y = \\frac{20}{1{,}200}x + \\frac{2{,}000}{1{,}200} = \\frac{1}{60}x + \\frac{5}{3}')}</p>` +
      `<p>The slope of this line is ${mathSpan('m = \\frac{1}{60}')} and its ${mathSpan('y')}-intercept is ${mathSpan('\\frac{5}{3}')}.</p>` +
      `<p>Now examine Choice A: ${mathSpan('\\frac{1}{20}x = 3y')}. Solving for ${mathSpan('y')}:</p>` +
      `<p>${mathSpan('y = \\frac{1}{60}x')}</p>` +
      `<p>This line has the identical slope ${mathSpan('\\frac{1}{60}')} but a different ${mathSpan('y')}-intercept (0 vs ${mathSpan('\\frac{5}{3}')}). Therefore, the two lines are parallel and distinct, meaning the system has no solution.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because ${mathSpan('\\frac{-1}{20}x = 60y - 100')} gives slope ${mathSpan('m = -\\frac{1}{1{,}200}')}, so the lines intersect at one point.</p>` +
      `<p>Choice C is incorrect because ${mathSpan('x = 3y \\implies y = \\frac{1}{3}x')}, which has slope ${mathSpan('\\frac{1}{3} \\neq \\frac{1}{60}')}.</p>` +
      `<p>Choice D is incorrect because ${mathSpan('x = 60y - 100 \\implies 60y = x + 100 \\implies y = \\frac{1}{60}x + \\frac{5}{3}')}, which is identical to the first equation and would result in infinitely many solutions, not no solution.</p>`
  },

  // M2 Q9: ID 6a53be6e4d554e04aa1bf788 (Grid-in: 2353)
  {
    id: '6a53be6e4d554e04aa1bf788',
    qNum: 'M2 Q9',
    text: `<p><strong>The correct answer is 2353.</strong></p>` +
      `<p>Let circle center be ${mathSpan('G')}, and radii to the points of tangency be ${mathSpan('GM')} and ${mathSpan('GN')}. By definition, ${mathSpan('GM = GN = 247\\text{ mm}')}.</p>` +
      `<p>Tangents drawn to a circle from an external point are equal in length, so ${mathSpan('MH = NH')}.</p>` +
      `<p>The perimeter of quadrilateral ${mathSpan('GMHN')} is:</p>` +
      `<p>${mathSpan('\\text{Perimeter} = GM + GN + MH + NH = 2(247) + 2(MH) = 494 + 2(MH) = 5{,}174')}</p>` +
      `<p>${mathSpan('2(MH) = 5{,}174 - 494 = 4{,}680')}</p>` +
      `<p>${mathSpan('MH = 2{,}340\\text{ mm}')}</p>` +
      `<p>Since a tangent line is perpendicular to the radius at the point of tangency, ${mathSpan('\\angle GMH = 90^\\circ')}. Therefore, ${mathSpan('\\triangle GMH')} is a right triangle with legs ${mathSpan('GM = 247')} and ${mathSpan('MH = 2{,}340')}, and hypotenuse ${mathSpan('GH')}.</p>` +
      `<p>By the Pythagorean theorem:</p>` +
      `<p>${mathSpan('GH = \\sqrt{GM^2 + MH^2} = \\sqrt{247^2 + 2{,}340^2} = \\sqrt{61{,}009 + 5{,}475{,}600} = \\sqrt{5{,}536{,}609} = 2{,}353')}</p>` +
      `<p>Thus, the distance between points ${mathSpan('G')} and ${mathSpan('H')} is <strong>2353</strong> mm.</p>`
  },

  // M2 Q10: ID 6a53bf424d554e04aa1bf794 (MCQ: Choice A)
  {
    id: '6a53bf424d554e04aa1bf794',
    qNum: 'M2 Q10',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>In triangle ${mathSpan('JKL')}, the sum of interior angles is ${mathSpan('180^\\circ')}:</p>` +
      `<p>${mathSpan('90b^\\circ + 60a^\\circ + 24a^\\circ = 180^\\circ')}</p>` +
      `<p>${mathSpan('90b + 84a = 180')}</p>` +
      `<p>Since ${mathSpan('a')} and ${mathSpan('b')} are constants without additional constraints, the angle measures cannot be uniquely determined:</p>` +
      `<p>• If ${mathSpan('b = 1')}, then ${mathSpan('90 + 84a = 180 \\implies 84a = 90 \\implies a = \\frac{15}{14}')}. Then ${mathSpan('\\angle J = 90^\\circ')}, so angles ${mathSpan('K')} and ${mathSpan('L')} are complementary (${mathSpan('K + L = 90^\\circ')}). In any right triangle, the cosine of an acute angle equals the sine of its complementary angle, so ${mathSpan('\\cos L = \\sin K')}.</p>` +
      `<p>• However, if ${mathSpan('b \\neq 1')}, for example if ${mathSpan('b = 0.5')}, then ${mathSpan('\\angle J = 45^\\circ')} and ${mathSpan('K + L = 135^\\circ \\neq 90^\\circ')}. In this case, ${mathSpan('K')} and ${mathSpan('L')} are not complementary, so ${mathSpan('\\cos L \\neq \\sin K')}.</p>` +
      `<p>Because the comparison depends on the unknown value of ${mathSpan('b')}, there is not enough information to compare the values of ${mathSpan('\\cos L')} and ${mathSpan('\\sin K')}.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choices B, C, and D are incorrect because each claims a specific relationship (${mathSpan('>')}, ${mathSpan('=')}, or ${mathSpan('<')}$) that is not guaranteed to hold for all valid values of ${mathSpan('a')} and ${mathSpan('b')}.</p>`
  },

  // M2 Q11: ID 6a53bfff4d554e04aa1bf79e (MCQ: Choice A, 53)
  {
    id: '6a53bfff4d554e04aa1bf79e',
    qNum: 'M2 Q11',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>The variable ${mathSpan('x')} represents the number of months since April 2015. April 2016 is exactly 12 months after April 2015, which corresponds to ${mathSpan('x = 12')}.</p>` +
      `<p>Locating ${mathSpan('x = 12')} on the horizontal axis and reading the corresponding value on the linear graph on the vertical axis, the line is just above 50, at approximately <strong>53</strong>.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because 23 corresponds to ${mathSpan('x \\approx 27')} months (around July 2017).</p>` +
      `<p>Choice C is incorrect because 33 corresponds to ${mathSpan('x \\approx 22')} months.</p>` +
      `<p>Choice D is incorrect because 43 corresponds to ${mathSpan('x \\approx 17')} months.</p>`
  },

  // M2 Q12: ID 6a53c3a14d554e04aa1bf7f5 (MCQ: Choice A, y < 3x + 5)
  {
    id: '6a53c3a14d554e04aa1bf7f5',
    qNum: 'M2 Q12',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>To determine the inequality represented by the graph, find the boundary line equation and check the shaded region:</p>` +
      `<p>1. <strong>Boundary Line:</strong> The dashed line passes through the ${mathSpan('y')}-intercept ${mathSpan('(0, 5)')} and the point ${mathSpan('(1, 8)')} (or ${mathSpan('(-1, 2)')}). The slope is:</p>` +
      `<p>${mathSpan('m = \\frac{8 - 5}{1 - 0} = 3')}</p>` +
      `<p>Thus, the equation of the boundary line is ${mathSpan('y = 3x + 5')}.</p>` +
      `<p>2. <strong>Inequality Direction:</strong> The line is dashed, indicating a strict inequality (${mathSpan('<')} or ${mathSpan('>')}). The origin ${mathSpan('(0, 0)')} lies in the shaded region. Testing ${mathSpan('(0, 0)')}:</p>` +
      `<p>${mathSpan('0 < 3(0) + 5 \\implies 0 < 5')} (True).</p>` +
      `<p>Therefore, the inequality is ${mathSpan('y < 3x + 5')}.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because ${mathSpan('y > 3x + 5')} shades the region above the line (not containing the origin).</p>` +
      `<p>Choice C is incorrect because ${mathSpan('y < \\frac{1}{3}x + 5')} has an inverted slope of ${mathSpan('\\frac{1}{3}')}.</p>` +
      `<p>Choice D is incorrect because ${mathSpan('y > \\frac{1}{3}x + 5')} has both the wrong slope and wrong inequality direction.</p>`
  },

  // M2 Q13: ID 6a53c5924d554e04aa1bf807 (Grid-in: 18.49)
  {
    id: '6a53c5924d554e04aa1bf807',
    qNum: 'M2 Q13',
    text: `<p><strong>The correct answer is 18.49.</strong></p>` +
      `<p>The area ${mathSpan('A')} of a circle with radius ${mathSpan('r')} is given by the formula:</p>` +
      `<p>${mathSpan('A = \\pi r^2')}</p>` +
      `<p>Given ${mathSpan('r = 4.3')} inches:</p>` +
      `<p>${mathSpan('A = \\pi (4.3)^2 = 18.49\\pi')}</p>` +
      `<p>The problem states that the area is ${mathSpan('b\\pi')}. Equating ${mathSpan('b\\pi = 18.49\\pi')} yields:</p>` +
      `<p>${mathSpan('b = 18.49')}</p>`
  },

  // M2 Q14: ID 6a53c67c4d554e04aa1bf813 (MCQ: Choice A, (5, 0))
  {
    id: '6a53c67c4d554e04aa1bf813',
    qNum: 'M2 Q14',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>To be a solution to the system, a point ${mathSpan('(x, y)')} must satisfy both inequalities:</p>` +
      `<p>1. ${mathSpan('y \\le x + 8')}</p>` +
      `<p>2. ${mathSpan('y \\ge -3x - 8')}</p>` +
      `<p>Test Choice A: ${mathSpan('(5, 0)')}:</p>` +
      `<p>• First inequality: ${mathSpan('0 \\le 5 + 8 = 13')} (True).</p>` +
      `<p>• Second inequality: ${mathSpan('0 \\ge -3(5) - 8 = -15 - 8 = -23')} (True).</p>` +
      `<p>Since both inequalities are satisfied, ${mathSpan('(5, 0)')} is a solution to the system.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because testing ${mathSpan('(0, -9)')}: ${mathSpan('-9 \\ge -3(0) - 8 = -8')} is False (${mathSpan('-9 < -8')}).</p>` +
      `<p>Choice C is incorrect because testing ${mathSpan('(0, 9)')}: ${mathSpan('9 \\le 0 + 8 = 8')} is False (${mathSpan('9 > 8')}).</p>` +
      `<p>Choice D is incorrect because testing ${mathSpan('(-5, 0)')}: ${mathSpan('0 \\ge -3(-5) - 8 = 15 - 8 = 7')} is False (${mathSpan('0 < 7')}).</p>`
  },

  // M2 Q15: ID 6a53c8194d554e04aa1bf81f (Grid-in: 580.6)
  {
    id: '6a53c8194d554e04aa1bf81f',
    qNum: 'M2 Q15',
    text: `<p><strong>The correct answer is 580.6.</strong></p>` +
      `<p>A right rectangular pyramid has a rectangular base with length ${mathSpan('l = 16')} units and width ${mathSpan('w = 8')} units, and height ${mathSpan('h = 18')} units.</p>` +
      `<p>The total surface area consists of the rectangular base plus the four triangular faces (two opposite pairs):</p>` +
      `<p>1. <strong>Base Area:</strong> ${mathSpan('B = l \\times w = 16 \\times 8 = 128')}.</p>` +
      `<p>2. <strong>Slant height to the sides of length ${mathSpan('l = 16')}:</strong> The distance from the center of the base to the sides of length ${mathSpan('l')} is ${mathSpan('\\frac{w}{2} = 4')}. The slant height is:</p>` +
      `<p>${mathSpan('s_1 = \\sqrt{h^2 + \\left(\\frac{w}{2}\\right)^2} = \\sqrt{18^2 + 4^2} = \\sqrt{324 + 16} = \\sqrt{340} \\approx 18.439')}</p>` +
      `<p>The area of these two triangular faces is ${mathSpan('2 \\times \\left(\\frac{1}{2} \\times 16 \\times \\sqrt{340}\\right) = 16\\sqrt{340} \\approx 295.025')}.</p>` +
      `<p>3. <strong>Slant height to the sides of width ${mathSpan('w = 8')}:</strong> The distance from the center of the base to the sides of width ${mathSpan('w')} is ${mathSpan('\\frac{l}{2} = 8')}. The slant height is:</p>` +
      `<p>${mathSpan('s_2 = \\sqrt{h^2 + \\left(\\frac{l}{2}\\right)^2} = \\sqrt{18^2 + 8^2} = \\sqrt{324 + 64} = \\sqrt{388} \\approx 19.698')}</p>` +
      `<p>The area of these two triangular faces is ${mathSpan('2 \\times \\left(\\frac{1}{2} \\times 8 \\times \\sqrt{388}\\right) = 8\\sqrt{388} \\approx 157.582')}.</p>` +
      `<p>4. <strong>Total Surface Area:</strong></p>` +
      `<p>${mathSpan('\\text{Surface Area} = 128 + 16\\sqrt{340} + 8\\sqrt{388} \\approx 128 + 295.025 + 157.582 = 580.607\\dots')}</p>` +
      `<p>Rounding to the nearest tenth yields <strong>580.6</strong>.</p>`
  },

  // M2 Q16: ID 6a53cd9b4d554e04aa1bf825 (MCQ: Choice A, 0)
  {
    id: '6a53cd9b4d554e04aa1bf825',
    qNum: 'M2 Q16',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>We are given the equation:</p>` +
      `<p>${mathSpan('76 - (x + 3) = 73')}</p>` +
      `<p>Distribute the negative sign:</p>` +
      `<p>${mathSpan('76 - x - 3 = 73')}</p>` +
      `<p>${mathSpan('73 - x = 73')}</p>` +
      `<p>Subtract 73 from both sides:</p>` +
      `<p>${mathSpan('-x = 0 \\implies x = 0')}</p>` +
      `<p>Since ${mathSpan('x = 0')} is the only solution, the sum of the solutions is <strong>0</strong>.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choices B, C, and D are incorrect because they result from arithmetic or sign errors when distributing the negative sign.</p>`
  },

  // M2 Q17: ID 6a53cdfc4d554e04aa1bf832 (MCQ: Choice A, 5/4)
  {
    id: '6a53cdfc4d554e04aa1bf832',
    qNum: 'M2 Q17',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>We are given the linear equation in one variable:</p>` +
      `<p>${mathSpan('\\frac{8cx + 7}{5} = 2x - 7')}</p>` +
      `<p>Multiply both sides by 5:</p>` +
      `<p>${mathSpan('8cx + 7 = 5(2x - 7)')}</p>` +
      `<p>${mathSpan('8cx + 7 = 10x - 35')}</p>` +
      `<p>Rearrange all terms with ${mathSpan('x')} to the left side and constants to the right side:</p>` +
      `<p>${mathSpan('8cx - 10x = -35 - 7')}</p>` +
      `<p>${mathSpan('(8c - 10)x = -42')}</p>` +
      `<p>A linear equation in the form ${mathSpan('kx = d')} has no solution if and only if the coefficient of ${mathSpan('x')} is zero (${mathSpan('k = 0')}) and the constant term is non-zero (${mathSpan('d \\neq 0')}).</p>` +
      `<p>Since ${mathSpan('-42 \\neq 0')}, setting the coefficient of ${mathSpan('x')} to zero gives:</p>` +
      `<p>${mathSpan('8c - 10 = 0')}</p>` +
      `<p>${mathSpan('8c = 10')}</p>` +
      `<p>${mathSpan('c = \\frac{10}{8} = \\frac{5}{4}')}</p>` +
      `<p>When ${mathSpan('c = \\frac{5}{4}')}, the equation reduces to ${mathSpan('0 \\cdot x = -42')}$, which has no solution.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect; ${mathSpan('c = \\frac{1}{4}')} is obtained if a student forgets to multiply the right side by 5 and incorrectly solves ${mathSpan('8c = 2 \\implies c = \\frac{1}{4}')}.</p>` +
      `<p>Choice C is incorrect; ${mathSpan('c = \\frac{1}{5}')} comes from dividing 1 by 5 rather than solving for the equal slope coefficient.</p>` +
      `<p>Choice D is incorrect; ${mathSpan('c = 2')} results in ${mathSpan('8(2) = 16 \\neq 10')}, giving a unique solution ${mathSpan('6x = -42 \\implies x = -7')}.</p>`
  },

  // M2 Q18: ID 6a53ce624d554e04aa1bf83e (MCQ: Choice A, 1)
  {
    id: '6a53ce624d554e04aa1bf83e',
    qNum: 'M2 Q18',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>The function is defined by ${mathSpan('f(x) = 3x - 4')}.</p>` +
      `<p>Substitute ${mathSpan('a + 1')} into the function:</p>` +
      `<p>${mathSpan('f(a + 1) = 3(a + 1) - 4 = 3a + 3 - 4 = 3a - 1')}</p>` +
      `<p>We are given that ${mathSpan('f(a + 1) = 2a')}. Set the two expressions equal:</p>` +
      `<p>${mathSpan('3a - 1 = 2a')}</p>` +
      `<p>Subtract ${mathSpan('2a')} and add 1 to both sides:</p>` +
      `<p>${mathSpan('a = 1')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because testing ${mathSpan('a = -1')} gives ${mathSpan('f(-1 + 1) = f(0) = -4')}, but ${mathSpan('2(-1) = -2 \\neq -4')}.</p>` +
      `<p>Choice C is incorrect because testing ${mathSpan('a = 5')} gives ${mathSpan('f(6) = 18 - 4 = 14')}, but ${mathSpan('2(5) = 10 \\neq 14')}.</p>` +
      `<p>Choice D is incorrect because testing ${mathSpan('a = 6')} gives ${mathSpan('f(7) = 21 - 4 = 17')}, but ${mathSpan('2(6) = 12 \\neq 17')}.</p>`
  },

  // M2 Q19: ID 6a53cf164d554e04aa1bf842 (MCQ: Choice A)
  {
    id: '6a53cf164d554e04aa1bf842',
    qNum: 'M2 Q19',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>1. At month 4 (${mathSpan('x = 4')}), the balance increased by 0.6% of the original 700 dollars balance:</p>` +
      `<p>${mathSpan('700 + 700(0.006) = 700(1.006) = 704.20')}\\text{ dollars}.</p>` +
      `<p>2. After month 4, the balance increases by 0.2% every 2 months. An increase of 0.2% corresponds to multiplying by a growth factor of ${mathSpan('1 + 0.002 = 1.002')}.</p>` +
      `<p>3. The number of 2-month periods that elapse between month 4 and month ${mathSpan('x')} is:</p>` +
      `<p>${mathSpan('\\frac{x - 4}{2} = \\frac{x}{2} - 2')}</p>` +
      `<p>Therefore, the balance ${mathSpan('B_x')} for ${mathSpan('x \\ge 4')} is given by:</p>` +
      `<p>${mathSpan('B_x = 704.20 \\cdot (1.002)^{\\frac{x}{2} - 2')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because an exponent of ${mathSpan('\\frac{x}{2}')} fails to account for the first 4 months when this 0.2% rate was not active.</p>` +
      `<p>Choice C is incorrect because it compounds monthly instead of every 2 months and subtracts 8 instead of dividing by 2.</p>` +
      `<p>Choice D is incorrect because it compounds every single month (${mathSpan('x - 4')}) instead of every 2 months (${mathSpan('\\frac{x - 4}{2}')}).</p>`
  },

  // M2 Q20: ID 6a53cfef4d554e04aa1bf848 (MCQ: Choice A, (12, 10))
  {
    id: '6a53cfef4d554e04aa1bf848',
    qNum: 'M2 Q20',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>The circle has its center at ${mathSpan('C(-5, 5)')} and is tangent to line ${mathSpan('t')} at ${mathSpan('P(6, -1)')}.</p>` +
      `<p>1. Find the slope of the radius connecting the center ${mathSpan('C')} to the point of tangency ${mathSpan('P')}:</p>` +
      `<p>${mathSpan('m_{\\text{radius}} = \\frac{-1 - 5}{6 - (-5)} = \\frac{-6}{11} = -\\frac{6}{11}')}</p>` +
      `<p>2. A tangent line is perpendicular to the radius at the point of tangency. Therefore, the slope of tangent line ${mathSpan('t')} is the negative reciprocal of ${mathSpan('-\\frac{6}{11}')}:</p>` +
      `<p>${mathSpan('m_{\\text{tangent}} = \\frac{11}{6}')}</p>` +
      `<p>3. Write the point-slope equation of line ${mathSpan('t')} passing through ${mathSpan('(6, -1)')}:</p>` +
      `<p>${mathSpan('y - (-1) = \\frac{11}{6}(x - 6) \\implies y + 1 = \\frac{11}{6}(x - 6)')}</p>` +
      `<p>4. Test Choice A: ${mathSpan('(12, 10)')}:</p>` +
      `<p>Left side: ${mathSpan('10 + 1 = 11')}.</p>` +
      `<p>Right side: ${mathSpan('\\frac{11}{6}(12 - 6) = \\frac{11}{6}(6) = 11')}.</p>` +
      `<p>Since both sides equal 11, the point ${mathSpan('(12, 10)')} lies on line ${mathSpan('t')}.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because testing ${mathSpan('(0, \\frac{11}{6})')}: ${mathSpan('\\frac{11}{6} + 1 = \\frac{17}{6}')}, but ${mathSpan('\\frac{11}{6}(0 - 6) = -11 \\neq \\frac{17}{6}')}.</p>` +
      `<p>Choice C is incorrect because testing ${mathSpan('(1, 16)')}: ${mathSpan('16 + 1 = 17')}, but ${mathSpan('\\frac{11}{6}(1 - 6) = -\\frac{55}{6} \\neq 17')}.</p>` +
      `<p>Choice D is incorrect because testing ${mathSpan('(17, 5)')}: ${mathSpan('5 + 1 = 6')}, but ${mathSpan('\\frac{11}{6}(17 - 6) = \\frac{121}{6} \\neq 6')}.</p>`
  },

  // M2 Q21: ID 6a53d0854d554e04aa1bf853 (MCQ: Choice A, 64)
  {
    id: '6a53d0854d554e04aa1bf853',
    qNum: 'M2 Q21',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>We are given the quadratic equation:</p>` +
      `<p>${mathSpan('4x^2 - px + w = -85')}</p>` +
      `<p>Rewrite in standard form ${mathSpan('ax^2 + bx + c = 0')}:</p>` +
      `<p>${mathSpan('4x^2 - px + (w + 85) = 0')}</p>` +
      `<p>For a quadratic equation to have exactly one real solution, its discriminant ${mathSpan('b^2 - 4ac')} must equal zero:</p>` +
      `<p>${mathSpan('(-p)^2 - 4(4)(w + 85) = 0')}</p>` +
      `<p>${mathSpan('p^2 - 16(w + 85) = 0')}</p>` +
      `<p>${mathSpan('p^2 = 16(w + 85)')}</p>` +
      `<p>Taking the square root gives ${mathSpan('p = 4\\sqrt{w + 85}')}. Since ${mathSpan('p')} is an integer, ${mathSpan('w + 85')} must be a perfect square.</p>` +
      `<p>Test the choices to see which value does NOT produce a perfect square:</p>` +
      `<p>• Choice A: If ${mathSpan('w = 64')}, ${mathSpan('w + 85 = 64 + 85 = 149')}. Since 149 is not a perfect square (${mathSpan('\\sqrt{149} \\approx 12.207')}), ${mathSpan('p')} would not be an integer. Therefore, 64 is <strong>NOT</strong> a possible value of ${mathSpan('w')}.</p>` +
      `<p>• Choice B: If ${mathSpan('w = -21')}, ${mathSpan('w + 85 = -21 + 85 = 64 = 8^2')} (a perfect square, ${mathSpan('p = 32')}).</p>` +
      `<p>• Choice C: If ${mathSpan('w = 15')}, ${mathSpan('w + 85 = 15 + 85 = 100 = 10^2')} (a perfect square, ${mathSpan('p = 40')}).</p>` +
      `<p>• Choice D: If ${mathSpan('w = 315')}, ${mathSpan('w + 85 = 315 + 85 = 400 = 20^2')} (a perfect square, ${mathSpan('p = 80')}).</p>`
  },

  // M2 Q22: ID 6a72b5fefb6980734c71b71a (MCQ: Choice A, f(x) = -4x + 7)
  {
    id: '6a72b5fefb6980734c71b71a',
    qNum: 'M2 Q22',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>The graph of linear function ${mathSpan('f')} has slope ${mathSpan('m = -4')} and passes through the point ${mathSpan('(3, -5)')}.</p>` +
      `<p>Using the point-slope equation of a line:</p>` +
      `<p>${mathSpan('y - y_1 = m(x - x_1)')}</p>` +
      `<p>${mathSpan('y - (-5) = -4(x - 3)')}</p>` +
      `<p>${mathSpan('y + 5 = -4x + 12')}</p>` +
      `<p>Subtract 5 from both sides:</p>` +
      `<p>${mathSpan('y = -4x + 7')}</p>` +
      `<p>Therefore, ${mathSpan('f(x) = -4x + 7')}.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because ${mathSpan('f(x) = 4x - 17')} has slope ${mathSpan('+4')} rather than ${mathSpan('-4')}.</p>` +
      `<p>Choice C is incorrect because ${mathSpan('f(x) = -4x - 17')} subtracts 5 from ${mathSpan('-12')} instead of subtracting 5 from ${mathSpan('+12')}.</p>` +
      `<p>Choice D is incorrect because ${mathSpan('f(x) = 4x + 7')} has a positive slope ${mathSpan('+4')} instead of ${mathSpan('-4')}.</p>`
  }
];

async function updateExplanations() {
  console.log(`🚀 Uploading explanations for March 2026 US 2 Module 2 (${explanations.length} questions)...\\n`);

  for (const exp of explanations) {
    process.stdout.write(`Updating ${exp.qNum} (${exp.id})... `);
    try {
      const res = await axios.put(`${BASE_URL}/question/updateQuestion/${exp.id}`, {
        explanation: exp.text
      });
      if (res.data.message === 'success' || res.status === 200) {
        console.log('✅ Success');
      } else {
        console.log(`⚠️ Unexpected response:`, res.data);
      }
    } catch (err) {
      console.log('❌ Failed:', err.response?.data || err.message);
    }
  }

  console.log('\\n🎉 Finished Module 2 explanations (22 questions updated).');
}

updateExplanations();
