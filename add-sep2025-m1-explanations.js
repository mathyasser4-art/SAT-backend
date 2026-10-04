const axios = require('axios');

const BASE_URL = 'https://sat-backend-production.up.railway.app';

function mathSpan(latex) {
  return `<span class="ql-formula" data-value="${latex}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow></mrow><annotation encoding="application/x-tex">${latex}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.7em;"></span><span class="mord">${latex}</span></span></span></span></span>﻿</span>`;
}

const explanations = [
  // M1 Q1: ID 6a6857eec3d08d90637d3b63 (MCQ: Choice A, 18)
  {
    id: '6a6857eec3d08d90637d3b63',
    qNum: 'M1 Q1',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>Population density is calculated by dividing the total population by the total area:</p>` +
      `<p>${mathSpan('\\text{Population Density} = \\frac{\\text{Total Population}}{\\text{Total Area}}')}</p>` +
      `<p>Given that there are 2,070 muskrats in a 115-acre area:</p>` +
      `<p>${mathSpan('\\text{Population Density} = \\frac{2{,}070}{115} = 18\\text{ muskrats per acre}')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect and may result from dividing 2,070 by 1,000 or a decimal placement error.</p>` +
      `<p>Choice C is incorrect because 115 is the total number of acres, not the density.</p>` +
      `<p>Choice D is incorrect and may result from adding 18 to 115.</p>`
  },

  // M1 Q2: ID 6a685934c3d08d90637d3b6f (MCQ: Choice A, x + 2y = 63)
  {
    id: '6a685934c3d08d90637d3b6f',
    qNum: 'M1 Q2',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>The perimeter of any triangle is the sum of the lengths of its three sides. The triangle has one side with a length of ${mathSpan('x')} inches and two sides each with a length of ${mathSpan('y')} inches.</p>` +
      `<p>Summing the lengths of the three sides gives:</p>` +
      `<p>${mathSpan('x + y + y = x + 2y')}</p>` +
      `<p>Since the perimeter is given as 63 inches, the equation representing this situation is:</p>` +
      `<p>${mathSpan('x + 2y = 63')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because ${mathSpan('2x + y = 63')} represents a triangle with two sides of length ${mathSpan('x')} and one side of length ${mathSpan('y')}.</p>` +
      `<p>Choice C is incorrect because ${mathSpan('2x + 2y = 63')} represents a four-sided figure, such as a rectangle.</p>` +
      `<p>Choice D is incorrect because ${mathSpan('x + y = 63')} only sums two sides of the triangle.</p>`
  },

  // M1 Q3: ID 6a685d34c3d08d90637d3b75 (Grid-in: 34)
  {
    id: '6a685d34c3d08d90637d3b75',
    qNum: 'M1 Q3',
    text: `<p><strong>The correct answer is 34.</strong></p>` +
      `<p>To find the number of green buttons, multiply the total number of buttons by the decimal equivalent of 20%:</p>` +
      `<p>${mathSpan('20\\% = 0.20')}</p>` +
      `<p>${mathSpan('\\text{Green Buttons} = 0.20 \\times 170 = 34')}</p>` +
      `<p>Thus, there are <strong>34</strong> green buttons in the jar.</p>`
  },

  // M1 Q4: ID 6a685da9c3d08d90637d3b7f (MCQ: Choice A, 700x = 3,500)
  {
    id: '6a685da9c3d08d90637d3b7f',
    qNum: 'M1 Q4',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>Each kilogram of soil contains 700 milligrams of phosphorus. For a sample of ${mathSpan('x')} kilograms, the total mass of phosphorus is ${mathSpan('700x')} milligrams.</p>` +
      `<p>Since the sample contains a total of 3,500 milligrams of phosphorus, we equate these two expressions:</p>` +
      `<p>${mathSpan('700x = 3{,}500')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because it divides the total phosphorus by the rate per kilogram incorrectly.</p>` +
      `<p>Choice C and Choice D are incorrect because they add the mass in kilograms to the mass of phosphorus in milligrams rather than multiplying by the rate.</p>`
  },

  // M1 Q5: ID 6a685e2fc3d08d90637d3b85 (MCQ: Choice A, 7)
  {
    id: '6a685e2fc3d08d90637d3b85',
    qNum: 'M1 Q5',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>The function is defined by ${mathSpan('f(x) = \\frac{1}{2}(x + 11)')}.</p>` +
      `<p>Substitute ${mathSpan('x = 3')} into the function:</p>` +
      `<p>${mathSpan('f(3) = \\frac{1}{2}(3 + 11) = \\frac{1}{2}(14) = 7')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect and may result from multiplying 11 by 2 instead of dividing 14 by 2.</p>` +
      `<p>Choice C is incorrect and may result from calculating ${mathSpan('2 \\times 14 = 28')}.</p>` +
      `<p>Choice D is incorrect because 14 is the value inside the parentheses before multiplying by ${mathSpan('\\frac{1}{2}')}.</p>`
  },

  // M1 Q6: ID 6a685e95c3d08d90637d3b8b (MCQ: Choice A, 44)
  {
    id: '6a685e95c3d08d90637d3b8b',
    qNum: 'M1 Q6',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>We are given that ${mathSpan('7x + 5 = 22')}.</p>` +
      `<p>Notice that the expression to evaluate, ${mathSpan('2(7x + 5)')}, is simply 2 times the quantity ${mathSpan('(7x + 5)')}.</p>` +
      `<p>Substitute 22 for ${mathSpan('7x + 5')}:</p>` +
      `<p>${mathSpan('2(7x + 5) = 2(22) = 44')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choices B, C, and D represent arithmetic errors from solving for ${mathSpan('x')} or miscalculating the product.</p>`
  },

  // M1 Q7: ID 6a685f72c3d08d90637d3b8f (Grid-in: 27)
  {
    id: '6a685f72c3d08d90637d3b8f',
    qNum: 'M1 Q7',
    text: `<p><strong>The correct answer is 27.</strong></p>` +
      `<p>Since ${mathSpan('\\triangle ABC \\cong \\triangle DEF')}, corresponding angles are equal in measure:</p>` +
      `<p>• Angle ${mathSpan('A')} corresponds to angle ${mathSpan('D')}, so ${mathSpan('m\\angle D = m\\angle A = 63^\\circ')}.</p>` +
      `<p>• Angles ${mathSpan('B')} and ${mathSpan('E')} are right angles, so ${mathSpan('m\\angle E = 90^\\circ')}.</p>` +
      `<p>The sum of the angles in right triangle ${mathSpan('\\triangle DEF')} is ${mathSpan('180^\\circ')}:</p>` +
      `<p>${mathSpan('m\\angle D + m\\angle E + m\\angle F = 180^\\circ')}</p>` +
      `<p>${mathSpan('63^\\circ + 90^\\circ + m\\angle F = 180^\\circ')}</p>` +
      `<p>${mathSpan('153^\\circ + m\\angle F = 180^\\circ')}</p>` +
      `<p>${mathSpan('m\\angle F = 180^\\circ - 153^\\circ = 27^\\circ')}</p>` +
      `<p>Thus, the measure of angle ${mathSpan('F')} is <strong>27</strong> degrees.</p>`
  },

  // M1 Q8: ID 6a686055c3d08d90637d3b93 (MCQ: Choice A)
  {
    id: '6a686055c3d08d90637d3b93',
    qNum: 'M1 Q8',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>In the function ${mathSpan('f(t) = 9000(1.02)^{2t}')}, ${mathSpan('t')} represents the number of years after the initial deposit, and ${mathSpan('f(t)')} represents the total amount of money, in dollars, in the savings account.</p>` +
      `<p>Therefore, the statement ${mathSpan('f(9) \\approx 12{,}854.22')} means that 9 years after the initial deposit, the total amount of money in the account is approximately 12,854.22 dollars.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because 12,854.22 is the total account balance at year 9, not a recurring increase every 9 years.</p>` +
      `<p>Choice C is incorrect because 12,854.22 represents the total balance, not the net increase (the increase from the initial 9,000 deposit is ${mathSpan('12{,}854.22 - 9{,}000 = 3{,}854.22')}).</p>` +
      `<p>Choice D is incorrect because the account balance is increasing exponentially, not decreasing.</p>`
  },

  // M1 Q9: ID 6a686213c3d08d90637d3baa (MCQ: Choice A)
  {
    id: '6a686213c3d08d90637d3baa',
    qNum: 'M1 Q9',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>The given quadratic equation is ${mathSpan('y = (x - 7)(x + 3)')}. We evaluate this function for the given values of ${mathSpan('x')}:</p>` +
      `<p>• For ${mathSpan('x = -1')}: ${mathSpan('y = (-1 - 7)(-1 + 3) = (-8)(2) = -16')}.</p>` +
      `<p>• For ${mathSpan('x = 0')}: ${mathSpan('y = (0 - 7)(0 + 3) = (-7)(3) = -21')}.</p>` +
      `<p>• For ${mathSpan('x = 1')}: ${mathSpan('y = (1 - 7)(1 + 3) = (-6)(4) = -24')}.</p>` +
      `<p>• For ${mathSpan('x = 2')}: ${mathSpan('y = (2 - 7)(2 + 3) = (-5)(5) = -25')}.</p>` +
      `<p>The table in Choice A correctly matches all four pairs: ${mathSpan('(-1, -16)')}, ${mathSpan('(0, -21)')}, ${mathSpan('(1, -24)')}, and ${mathSpan('(2, -25)')}.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choices B, C, and D contain incorrect values for ${mathSpan('y')} that do not satisfy the equation ${mathSpan('y = (x - 7)(x + 3)')}.</p>`
  },

  // M1 Q10: ID 6a6862d4c3d08d90637d3bb0 (MCQ: Choice A, f(x) = 9)
  {
    id: '6a6862d4c3d08d90637d3bb0',
    qNum: 'M1 Q10',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>A linear function has constant slope. Using the two given points ${mathSpan('(0, 9)')} and ${mathSpan('(7, 9)')}, we calculate the slope ${mathSpan('m')}:</p>` +
      `<p>${mathSpan('m = \\frac{9 - 9}{7 - 0} = \\frac{0}{7} = 0')}</p>` +
      `<p>Since the slope is 0 and the ${mathSpan('y')}-intercept is 9, the equation defining ${mathSpan('f')} is:</p>` +
      `<p>${mathSpan('f(x) = 0x + 9 \\implies f(x) = 9')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because ${mathSpan('f(x) = x + 9')} has a slope of 1, which gives ${mathSpan('f(7) = 7 + 9 = 16 \\neq 9')}.</p>` +
      `<p>Choice C is incorrect because ${mathSpan('f(x) = 7')} gives ${mathSpan('f(0) = 7 \\neq 9')}.</p>` +
      `<p>Choice D is incorrect because ${mathSpan('f(x) = 0')} gives ${mathSpan('f(0) = 0 \\neq 9')}.</p>`
  },

  // M1 Q11: ID 6a68634ac3d08d90637d3bbc (Grid-in: 5500)
  {
    id: '6a68634ac3d08d90637d3bbc',
    qNum: 'M1 Q11',
    text: `<p><strong>The correct answer is 5500.</strong></p>` +
      `<p>We are given that ${mathSpan('1\\text{ meter} = 10\\text{ decimeters}')}.</p>` +
      `<p>To convert 550 meters to decimeters, multiply by the conversion factor:</p>` +
      `<p>${mathSpan('550\\text{ meters} \\times 10\\frac{\\text{decimeters}}{\\text{meter}} = 5{,}500\\text{ decimeters}')}</p>` +
      `<p>Thus, 550 meters is equal to <strong>5500</strong> decimeters.</p>`
  },

  // M1 Q12: ID 6a6863acc3d08d90637d3bc0 (MCQ: Choice A, 280 <= x <= 490)
  {
    id: '6a6863acc3d08d90637d3bc0',
    qNum: 'M1 Q12',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>The density of hickory trees is at least 40 and no more than 70 trees per acre:</p>` +
      `<p>${mathSpan('40 \\le \\text{trees per acre} \\le 70')}</p>` +
      `<p>In a 7-acre section of forest, the minimum estimated number of trees is:</p>` +
      `<p>${mathSpan('40 \\times 7 = 280')}</p>` +
      `<p>The maximum estimated number of trees is:</p>` +
      `<p>${mathSpan('70 \\times 7 = 490')}</p>` +
      `<p>Therefore, the inequality representing the total number of hickory trees ${mathSpan('x')} is:</p>` +
      `<p>${mathSpan('280 \\le x \\le 490')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect and results from multiplying by 14 instead of 7.</p>` +
      `<p>Choice C is incorrect because it adds 7 to 40 and 70 instead of multiplying.</p>` +
      `<p>Choice D is incorrect because it gives the tree count for only a 1-acre section.</p>`
  },

  // M1 Q13: ID 6a686423c3d08d90637d3bc6 (Grid-in: 12)
  {
    id: '6a686423c3d08d90637d3bc6',
    qNum: 'M1 Q13',
    text: `<p><strong>The correct answer is 12.</strong></p>` +
      `<p>The graph of ${mathSpan('y = p(x)')} passes through the point ${mathSpan('(0, 12)')}.</p>` +
      `<p>By definition of a function's coordinates on a graph, the point ${mathSpan('(x, y) = (0, 12)')} indicates that when the input is ${mathSpan('x = 0')}, the output is ${mathSpan('y = 12')}.</p>` +
      `<p>Therefore, ${mathSpan('p(0) = 12')}.</p>`
  },

  // M1 Q14: ID 6a6864c2c3d08d90637d3bca (Grid-in: -15125)
  {
    id: '6a6864c2c3d08d90637d3bca',
    qNum: 'M1 Q14',
    text: `<p><strong>The correct answer is -15125.</strong></p>` +
      `<p>We find the intercepts of the linear equation ${mathSpan('-11x + 2.2y = -605')}:</p>` +
      `<p>1. <strong>Find ${mathSpan('a')} (${mathSpan('x')}-intercept at ${mathSpan('(a, 0)')}):</strong> Set ${mathSpan('y = 0')}:</p>` +
      `<p>${mathSpan('-11a + 2.2(0) = -605')}</p>` +
      `<p>${mathSpan('-11a = -605 \\implies a = \\frac{-605}{-11} = 55')}</p>` +
      `<p>2. <strong>Find ${mathSpan('b')} (${mathSpan('y')}-intercept at ${mathSpan('(0, b)')}):</strong> Set ${mathSpan('x = 0')}:</p>` +
      `<p>${mathSpan('-11(0) + 2.2b = -605')}</p>` +
      `<p>${mathSpan('2.2b = -605 \\implies b = \\frac{-605}{2.2} = -275')}</p>` +
      `<p>3. <strong>Calculate the product ${mathSpan('ab')}:</strong></p>` +
      `<p>${mathSpan('ab = (55)(-275) = -15{,}125')}</p>` +
      `<p>Thus, the value of ${mathSpan('ab')} is <strong>-15125</strong>.</p>`
  },

  // M1 Q15: ID 6a6865ebc3d08d90637d3bce (Grid-in: 5/3 or 1.667)
  {
    id: '6a6865ebc3d08d90637d3bce',
    qNum: 'M1 Q15',
    text: `<p><strong>The correct answer is 5/3 (or 1.666, 1.667).</strong></p>` +
      `<p>We are given the system of linear equations:</p>` +
      `<p>1. ${mathSpan('x + 21y = 38')}</p>` +
      `<p>2. ${mathSpan('4x + 3y = 17')}</p>` +
      `<p>From equation (1), solve for ${mathSpan('x')}:</p>` +
      `<p>${mathSpan('x = 38 - 21y')}</p>` +
      `<p>Substitute this expression into equation (2):</p>` +
      `<p>${mathSpan('4(38 - 21y) + 3y = 17')}</p>` +
      `<p>${mathSpan('152 - 84y + 3y = 17')}</p>` +
      `<p>${mathSpan('152 - 81y = 17')}</p>` +
      `<p>Subtract 152 from both sides:</p>` +
      `<p>${mathSpan('-81y = 17 - 152 = -135')}</p>` +
      `<p>Divide by -81 and simplify:</p>` +
      `<p>${mathSpan('y = \\frac{-135}{-81} = \\frac{135}{81} = \\frac{15}{9} = \\frac{5}{3} \\approx 1.667')}</p>` +
      `<p>Thus, the value of ${mathSpan('y')} is <strong>5/3</strong>.</p>`
  },

  // M1 Q16: ID 6a686698c3d08d90637d3bd2 (MCQ: Choice A, -0.17)
  {
    id: '6a686698c3d08d90637d3bd2',
    qNum: 'M1 Q16',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>To approximate the slope of the line of best fit, select two representative points on the line:</p>` +
      `<p>• At depth ${mathSpan('x_1 = 10')} meters, the temperature is approximately ${mathSpan('y_1 \\approx 22.1^\\circ\\text{C}')}.</p>` +
      `<p>• At depth ${mathSpan('x_2 = 70')} meters, the temperature is approximately ${mathSpan('y_2 \\approx 13.0^\\circ\\text{C}')}.</p>` +
      `<p>Calculate the slope ${mathSpan('m')}:</p>` +
      `<p>${mathSpan('m = \\frac{y_2 - y_1}{x_2 - x_1} = \\frac{13.0 - 22.1}{70 - 10} = \\frac{-9.1}{60} \\approx -0.152')}</p>` +
      `<p>Among the given choices, <strong>-0.17</strong> is the closest and best approximation.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choices B and C are incorrect because slopes of -8.05 and -6.05 represent an extremely steep drop that does not match the scale of the scatterplot.</p>` +
      `<p>Choice D is incorrect because -2.17 represents a slope over 10 times steeper than the actual data.</p>`
  },

  // M1 Q17: ID 6a686850c3d08d90637d3bdc (MCQ: Choice A)
  {
    id: '6a686850c3d08d90637d3bdc',
    qNum: 'M1 Q17',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>The given equation is:</p>` +
      `<p>${mathSpan('a = \\frac{4}{9}b + 8')}</p>` +
      `<p>Subtract 8 from both sides to isolate the term with ${mathSpan('b')}:</p>` +
      `<p>${mathSpan('a - 8 = \\frac{4}{9}b')}</p>` +
      `<p>Multiply both sides by the reciprocal ${mathSpan('\\frac{9}{4}')}:</p>` +
      `<p>${mathSpan('b = \\frac{9}{4}(a - 8)')}</p>` +
      `<p>Distribute ${mathSpan('\\frac{9}{4}')}:</p>` +
      `<p>${mathSpan('b = \\frac{9}{4}a - \\frac{9}{4}(8) = \\frac{9}{4}a - 18')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because it uses the un-inverted coefficient ${mathSpan('\\frac{4}{9}')}.</p>` +
      `<p>Choice C is incorrect because it fails to distribute ${mathSpan('\\frac{9}{4}')} to the constant 8.</p>` +
      `<p>Choice D is incorrect because it does not invert the coefficient and adds 8 instead of subtracting 18.</p>`
  },

  // M1 Q18: ID 6a68694ec3d08d90637d3be6 (MCQ: Choice A)
  {
    id: '6a68694ec3d08d90637d3be6',
    qNum: 'M1 Q18',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>To convert an angle from radians to degrees, multiply by the conversion factor ${mathSpan('\\frac{180^\\circ}{\\pi\\text{ radians}}')}:</p>` +
      `<p>${mathSpan('\\text{Angle in degrees} = (99)(2)\\pi \\times \\frac{180}{\\pi}')}</p>` +
      `<p>The factor of ${mathSpan('\\pi')} cancels out:</p>` +
      `<p>${mathSpan('(99)(2)(180)')}</p>` +
      `<p>Since ${mathSpan('2 \\times 180 = 360')}:</p>` +
      `<p>${mathSpan('(99)(360)')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because it doubles the angle, multiplying by 2 twice.</p>` +
      `<p>Choice C is incorrect because it divides 99 by 2 instead of multiplying by 2.</p>` +
      `<p>Choice D is incorrect because it includes an extra factor of 180.</p>`
  },

  // M1 Q19: ID 6a686a09c3d08d90637d3bec (MCQ: Choice A, 107)
  {
    id: '6a686a09c3d08d90637d3bec',
    qNum: 'M1 Q19',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>A quadratic equation ${mathSpan('Ax^2 + Bx + C = 0')} has exactly one real solution if and only if its discriminant equals zero: ${mathSpan('B^2 - 4AC = 0')}.</p>` +
      `<p>In the equation ${mathSpan('x^2 + (\\sqrt{k - 3})x + 26 = 0')}, we have:</p>` +
      `<p>${mathSpan('A = 1')}, ${mathSpan('B = \\sqrt{k - 3}')}, and ${mathSpan('C = 26')}.</p>` +
      `<p>Set the discriminant to zero:</p>` +
      `<p>${mathSpan('(\\sqrt{k - 3})^2 - 4(1)(26) = 0')}</p>` +
      `<p>${mathSpan('(k - 3) - 104 = 0')}</p>` +
      `<p>${mathSpan('k - 3 = 104 \\implies k = 107')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because 29 results from ${mathSpan('26 + 3')}.</p>` +
      `<p>Choice C is incorrect because 104 is the value of ${mathSpan('k - 3')}, not ${mathSpan('k')}.</p>` +
      `<p>Choice D is incorrect because 101 results from subtracting 3 from 104 instead of adding 3.</p>`
  },

  // M1 Q20: ID 6a686b1cc3d08d90637d3bf0 (MCQ: Choice A, 299/349)
  {
    id: '6a686b1cc3d08d90637d3bf0',
    qNum: 'M1 Q20',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>1. In right triangle ${mathSpan('\\triangle RST')}, ${mathSpan('\\angle T = 90^\\circ')}. The two acute angles are complementary: ${mathSpan('R + S = 90^\\circ')}.</p>` +
      `<p>2. We are given ${mathSpan('\\overline{XY} \\parallel \\overline{TS}')}. Since line ${mathSpan('RS')} intersects these parallel lines, the alternate interior angle ${mathSpan('\\angle YXZ')} is equal to angle ${mathSpan('S')}:</p>` +
      `<p>${mathSpan('m\\angle YXZ = m\\angle S')}</p>` +
      `<p>3. Therefore, ${mathSpan('\\sin X = \\sin(\\angle YXZ) = \\sin S')}.</p>` +
      `<p>4. In any right triangle, the sine of an acute angle equals the cosine of its complementary angle:</p>` +
      `<p>${mathSpan('\\sin S = \\cos R')}</p>` +
      `<p>5. We are given ${mathSpan('\\tan R = \\frac{180}{299}')}. Think of a right triangle with opposite leg 180 and adjacent leg 299. The hypotenuse is:</p>` +
      `<p>${mathSpan('\\text{Hypotenuse} = \\sqrt{180^2 + 299^2} = \\sqrt{32{,}400 + 89{,}401} = \\sqrt{121{,}801} = 349')}</p>` +
      `<p>6. Thus, ${mathSpan('\\cos R = \\frac{\\text{adjacent}}{\\text{hypotenuse}} = \\frac{299}{349}')}.</p>` +
      `<p>Therefore, ${mathSpan('\\sin X = \\frac{299}{349}')}.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because ${mathSpan('\\frac{180}{349} = \\sin R = \\cos S')}.</p>` +
      `<p>Choice C is incorrect because ${mathSpan('\\frac{180}{479}')} adds the legs together in the denominator.</p>` +
      `<p>Choice D is incorrect because ${mathSpan('\\frac{299}{180} = \\cot R')}.</p>`
  },

  // M1 Q21: ID 6a686b70c3d08d90637d3bfa (Grid-in: 7/3 or 2.333)
  {
    id: '6a686b70c3d08d90637d3bfa',
    qNum: 'M1 Q21',
    text: `<p><strong>The correct answer is 7/3 (or 2.33, 2.333).</strong></p>` +
      `<p>We are given the equation:</p>` +
      `<p>${mathSpan('|x + 4| + 4 = |2x - 11| + 4')}</p>` +
      `<p>Subtract 4 from both sides:</p>` +
      `<p>${mathSpan('|x + 4| = |2x - 11|')}</p>` +
      `<p>An absolute value equation ${mathSpan('|u| = |v|')} splits into two linear cases: ${mathSpan('u = v')} or ${mathSpan('u = -v')}:</p>` +
      `<p>• <strong>Case 1:</strong> ${mathSpan('x + 4 = 2x - 11')}</p>` +
      `<p>${mathSpan('4 + 11 = 2x - x \\implies x = 15')}</p>` +
      `<p>• <strong>Case 2:</strong> ${mathSpan('x + 4 = -(2x - 11) = -2x + 11')}</p>` +
      `<p>${mathSpan('x + 2x = 11 - 4')}</p>` +
      `<p>${mathSpan('3x = 7 \\implies x = \\frac{7}{3} \\approx 2.333')}</p>` +
      `<p>Comparing the two solutions, ${mathSpan('\\frac{7}{3} < 15')}. Thus, the smallest solution is <strong>7/3</strong> (or <strong>2.333</strong>).</p>`
  },

  // M1 Q22: ID 6a686c26c3d08d90637d3bfe (MCQ: Choice A)
  {
    id: '6a686c26c3d08d90637d3bfe',
    qNum: 'M1 Q22',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>We are given the system of equations:</p>` +
      `<p>1. ${mathSpan('y = 3x^2 - 12x + 18')}</p>` +
      `<p>2. ${mathSpan('y + 2 = 0 \\implies y = -2')}</p>` +
      `<p>Substitute ${mathSpan('y = -2')} into the quadratic equation:</p>` +
      `<p>${mathSpan('-2 = 3x^2 - 12x + 18')}</p>` +
      `<p>${mathSpan('3x^2 - 12x + 20 = 0')}</p>` +
      `<p>The number of real solutions is determined by the discriminant ${mathSpan('b^2 - 4ac')}:</p>` +
      `<p>${mathSpan('\\Delta = (-12)^2 - 4(3)(20) = 144 - 240 = -96')}</p>` +
      `<p>Since the discriminant is negative (${mathSpan('\\Delta < 0')}), the quadratic equation has no real solutions. Therefore, there are no solutions to the system.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choices B, C, and D are incorrect because a negative discriminant strictly implies 0 real intersection points between the parabola and the horizontal line.</p>`
  }
];

async function updateExplanations() {
  console.log(`🚀 Uploading explanations for September 2025 INT 1 Module 1 (${explanations.length} questions)...\n`);

  for (const exp of explanations) {
    process.stdout.write(`Updating ${exp.qNum} (${exp.id})... `);
    try {
      const res = await axios.put(`${BASE_URL}/question/updateQuestion/${exp.id}`, {
        explanation: exp.text
      });
      if (res.data.message === 'success' || res.status === 200) {
        console.log('✅ Success');
      } else {
        console.log(`⚠️ Response:`, res.data);
      }
    } catch (err) {
      console.log('❌ Failed:', err.response?.data || err.message);
    }
  }

  console.log('\n🎉 Finished Module 1 explanations (22 questions updated).');
}

updateExplanations();
