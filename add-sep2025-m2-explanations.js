const axios = require('axios');

const BASE_URL = 'https://sat-backend-production.up.railway.app';

function mathSpan(latex) {
  return `<span class="ql-formula" data-value="${latex}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow></mrow><annotation encoding="application/x-tex">${latex}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.7em;"></span><span class="mord">${latex}</span></span></span></span></span>﻿</span>`;
}

const explanations = [
  // M2 Q1: ID 6a687f82c3d08d90637d3c12 (MCQ: Choice A, 158 deg)
  {
    id: '6a687f82c3d08d90637d3c12',
    qNum: 'M2 Q1',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>The sum of the interior angle measures of any triangle is ${mathSpan('180^\\circ')}:</p>` +
      `<p>${mathSpan('m\\angle E + m\\angle F + m\\angle G = 180^\\circ')}</p>` +
      `<p>We are given that the sum of angles ${mathSpan('E')} and ${mathSpan('F')} is ${mathSpan('22^\\circ')}:</p>` +
      `<p>${mathSpan('22^\\circ + m\\angle G = 180^\\circ')}</p>` +
      `<p>${mathSpan('m\\angle G = 180^\\circ - 22^\\circ = 158^\\circ')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect and results from subtracting 22 twice from 180.</p>` +
      `<p>Choice C is incorrect and results from subtracting 22 from 90.</p>` +
      `<p>Choice D is incorrect because 22 is the sum of angles ${mathSpan('E')} and ${mathSpan('F')}, not the measure of angle ${mathSpan('G')}.</p>`
  },

  // M2 Q2: ID 6a687fbbc3d08d90637d3c16 (MCQ: Choice A)
  {
    id: '6a687fbbc3d08d90637d3c16',
    qNum: 'M2 Q2',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>Standard deviation measures the spread or dispersion of a data set relative to its mean. The closer the data values are clustered together, the smaller the standard deviation.</p>` +
      `<p>In Choice A, the values are 84, 85, 85, 85, 86. The mean is 85. Three of the five values are equal to the mean (deviation of 0), and the other two values deviate by only 1 unit (${mathSpan('|84 - 85| = 1')} and ${mathSpan('|86 - 85| = 1')}). This data set has the tightest clustering and therefore the smallest standard deviation.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choices B, C, and D all have wider spreads around the mean with larger individual deviations (e.g., deviations of 2 and 3 units).</p>`
  },

  // M2 Q3: ID 6a688096c3d08d90637d3c1d (MCQ: Choice A, 75)
  {
    id: '6a688096c3d08d90637d3c1d',
    qNum: 'M2 Q3',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>The intersection points of the system occur where the two equations have equal ${mathSpan('y')}-values:</p>` +
      `<p>${mathSpan('(x - 25)(x - 75) = 0')}</p>` +
      `<p>By the zero product property, setting each factor to zero gives:</p>` +
      `<p>${mathSpan('x - 25 = 0 \\implies x = 25')}</p>` +
      `<p>${mathSpan('x - 75 = 0 \\implies x = 75')}</p>` +
      `<p>Among the given choices, <strong>75</strong> is a possible value of ${mathSpan('x')}.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because 100 is the sum of the two solutions (${mathSpan('25 + 75 = 100')}), not a solution itself.</p>` +
      `<p>Choice C is incorrect because 3 is the ratio ${mathSpan('75 / 25 = 3')}.</p>` +
      `<p>Choice D is incorrect because substituting ${mathSpan('x = 0')} yields ${mathSpan('y = (-25)(-75) = 1{,}875 \\neq 0')}.</p>`
  },

  // M2 Q4: ID 6a68813fc3d08d90637d3c27 (MCQ: Choice A, f(x) = 30x + 5)
  {
    id: '6a68813fc3d08d90637d3c27',
    qNum: 'M2 Q4',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>The table provides two points ${mathSpan('(x, f(x))')}: (2, 65) and (4, 125). First, find the hourly rate (the slope ${mathSpan('m')}):</p>` +
      `<p>${mathSpan('m = \\frac{125 - 65}{4 - 2} = \\frac{60}{2} = 30\\text{ dollars per hour}')}</p>` +
      `<p>Now use the point-slope form with ${mathSpan('(2, 65)')}:</p>` +
      `<p>${mathSpan('f(x) - 65 = 30(x - 2)')}</p>` +
      `<p>${mathSpan('f(x) - 65 = 30x - 60')}</p>` +
      `<p>${mathSpan('f(x) = 30x + 5')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because ${mathSpan('f(x) = 35x')} assumes the cost is purely proportional with no fixed fee and gives ${mathSpan('f(2) = 70 \\neq 65')}.</p>` +
      `<p>Choice C is incorrect because ${mathSpan('f(x) = 30x + 65')} uses the 2-hour cost as the initial fee rather than the true ${mathSpan('y')}-intercept of 5.</p>` +
      `<p>Choice D is incorrect because ${mathSpan('f(x) = 30x')} omits the fixed fee entirely, giving ${mathSpan('f(2) = 60 \\neq 65')}.</p>`
  },

  // M2 Q5: ID 6a68820dc3d08d90637d3c2d (MCQ: Choice A, 1.5)
  {
    id: '6a68820dc3d08d90637d3c2d',
    qNum: 'M2 Q5',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>The function ${mathSpan('g(x) = (38 - 2x)(32 + 2x)')} is a downward-opening parabola because the product of the ${mathSpan('x')}-terms has a negative coefficient (${mathSpan('-2x \\times 2x = -4x^2')}).</p>` +
      `<p>The maximum of any parabola occurs at its vertex, which lies exactly halfway between the two ${mathSpan('x')}-intercepts (roots):</p>` +
      `<p>1. Find the roots by setting each factor to zero:</p>` +
      `<p>${mathSpan('38 - 2x = 0 \\implies 2x = 38 \\implies x = 19')}</p>` +
      `<p>${mathSpan('32 + 2x = 0 \\implies 2x = -32 \\implies x = -16')}</p>` +
      `<p>2. Calculate the midpoint of the roots:</p>` +
      `<p>${mathSpan('x = \\frac{19 + (-16)}{2} = \\frac{3}{2} = 1.5')}</p>` +
      `<p>Therefore, ${mathSpan('g(x)')} reaches its maximum at ${mathSpan('x = 1.5')}.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because 3 is the difference of the roots (${mathSpan('19 - 16 = 3')}) without dividing by 2.</p>` +
      `<p>Choice C is incorrect because 35 is the distance between the roots (${mathSpan('19 - (-16) = 35')}).</p>` +
      `<p>Choice D is incorrect because 17.5 is half the distance between the roots (${mathSpan('35 / 2 = 17.5')}), rather than the coordinate of the vertex.</p>`
  },

  // M2 Q6: ID 6a6882fbc3d08d90637d3c31 (MCQ: Choice A, 2)
  {
    id: '6a6882fbc3d08d90637d3c31',
    qNum: 'M2 Q6',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>1. Calculate the area of rectangle ${mathSpan('X')}:</p>` +
      `<p>${mathSpan('\\text{Area of } X = \\text{length} \\times \\text{width} = 24\\text{ mm} \\times 7.5\\text{ mm} = 180\\text{ mm}^2')}</p>` +
      `<p>2. We are given that the area of rectangle ${mathSpan('X')} is 3 times the area of right triangle ${mathSpan('Y')}:</p>` +
      `<p>${mathSpan('\\text{Area of } Y = \\frac{\\text{Area of } X}{3} = \\frac{180}{3} = 60\\text{ mm}^2')}</p>` +
      `<p>3. Use the area formula for right triangle ${mathSpan('Y')} with base ${mathSpan('b = 60\\text{ mm}')} and height ${mathSpan('h')}:</p>` +
      `<p>${mathSpan('\\text{Area of } Y = \\frac{1}{2} \\times \\text{base} \\times \\text{height} = \\frac{1}{2}(60)h = 30h')}</p>` +
      `<p>${mathSpan('30h = 60 \\implies h = 2\\text{ mm}')}</p>` +
      `<p>Thus, the height of right triangle ${mathSpan('Y')} is <strong>2</strong> mm.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect and results from omitting the factor of ${mathSpan('\\frac{1}{2}')} in the triangle area formula (${mathSpan('60h = 360')}).</p>` +
      `<p>Choice C is incorrect and may result from dividing 180 by 60 directly.</p>` +
      `<p>Choice D is incorrect because ${mathSpan('h = 1')} would give an area of ${mathSpan('30\\text{ mm}^2')}.</p>`
  },

  // M2 Q7: ID 6a6883b5c3d08d90637d3c35 (MCQ: Choice A, 21/4)
  {
    id: '6a6883b5c3d08d90637d3c35',
    qNum: 'M2 Q7',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>The table provides points ${mathSpan('(x, y)')}: (0, n), (4, n + 21), and (8, n + 42). The slope ${mathSpan('m')} of the line is the change in ${mathSpan('y')} divided by the change in ${mathSpan('x')}:</p>` +
      `<p>${mathSpan('m = \\frac{(n + 21) - n}{4 - 0} = \\frac{21}{4}')}</p>` +
      `<p>Verifying with the next point:</p>` +
      `<p>${mathSpan('m = \\frac{(n + 42) - (n + 21)}{8 - 4} = \\frac{21}{4}')}</p>` +
      `<p>The slope is consistently <strong>21/4</strong>.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because 21 is the change in ${mathSpan('y')} alone, without dividing by the change in ${mathSpan('x')} of 4.</p>` +
      `<p>Choice C is incorrect and represents an arithmetic approximation.</p>` +
      `<p>Choice D is incorrect because ${mathSpan('\\frac{1}{2}')} does not match the rate of change.</p>`
  },

  // M2 Q8: ID 6a68849ec3d08d90637d3c4e (MCQ: Choice A, -3k + 17r - 3)
  {
    id: '6a68849ec3d08d90637d3c4e',
    qNum: 'M2 Q8',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>We are given the expressions ${mathSpan('a = 5k + 6r')} and ${mathSpan('b = 8k - 11r + 3')}.</p>` +
      `<p>To find ${mathSpan('a - b')}, subtract ${mathSpan('b')} from ${mathSpan('a')}, ensuring the negative sign is distributed to every term in ${mathSpan('b')}:</p>` +
      `<p>${mathSpan('a - b = (5k + 6r) - (8k - 11r + 3)')}</p>` +
      `<p>${mathSpan('a - b = 5k + 6r - 8k - (-11r) - 3')}</p>` +
      `<p>${mathSpan('a - b = 5k + 6r - 8k + 11r - 3')}</p>` +
      `<p>Combine like terms:</p>` +
      `<p>• For ${mathSpan('k')}: ${mathSpan('5k - 8k = -3k')}</p>` +
      `<p>• For ${mathSpan('r')}: ${mathSpan('6r + 11r = 17r')}</p>` +
      `<p>• Constant term: ${mathSpan('-3')}</p>` +
      `<p>Putting it together:</p>` +
      `<p>${mathSpan('a - b = -3k + 17r - 3')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because ${mathSpan('-3k - 5r - 3')} results from failing to distribute the negative sign to ${mathSpan('-11r')} (${mathSpan('6r - 11r = -5r')}).</p>` +
      `<p>Choice C is incorrect because ${mathSpan('-3k + 17r + 3')} fails to distribute the negative sign to the constant 3.</p>` +
      `<p>Choice D is incorrect because it has both sign errors.</p>`
  },

  // M2 Q9: ID 6a6884fcc3d08d90637d3c52 (Grid-in: 5)
  {
    id: '6a6884fcc3d08d90637d3c52',
    qNum: 'M2 Q9',
    text: `<p><strong>The correct answer is 5.</strong></p>` +
      `<p>The exponential function is defined by ${mathSpan('f(x) = c^x')}.</p>` +
      `<p>Evaluate ${mathSpan('f(6)')} and ${mathSpan('f(4)')}:</p>` +
      `<p>${mathSpan('f(6) = c^6')}</p>` +
      `<p>${mathSpan('f(4) = c^4')}</p>` +
      `<p>We are given that ${mathSpan('f(6) = 25 \\cdot f(4)')}:</p>` +
      `<p>${mathSpan('c^6 = 25 \\cdot c^4')}</p>` +
      `<p>Divide both sides by ${mathSpan('c^4')} (since ${mathSpan('c > 1')}, ${mathSpan('c^4 \\neq 0')}):</p>` +
      `<p>${mathSpan('\\frac{c^6}{c^4} = 25')}</p>` +
      `<p>${mathSpan('c^{6 - 4} = 25 \\implies c^2 = 25')}</p>` +
      `<p>Since ${mathSpan('c > 1')}, take the positive square root: ${mathSpan('c = \\sqrt{25} = 5')}.</p>`
  },

  // M2 Q10: ID 6a688580c3d08d90637d3c56 (Grid-in: 1/6)
  {
    id: '6a688580c3d08d90637d3c56',
    qNum: 'M2 Q10',
    text: `<p><strong>The correct answer is 1/6 (or 0.166, 0.167).</strong></p>` +
      `<p>We are given ${mathSpan('g(x) = 18x + 31')} and want to find ${mathSpan('x')} such that ${mathSpan('g(x) = 34')}:</p>` +
      `<p>${mathSpan('18x + 31 = 34')}</p>` +
      `<p>Subtract 31 from both sides:</p>` +
      `<p>${mathSpan('18x = 3')}</p>` +
      `<p>Divide by 18 and simplify:</p>` +
      `<p>${mathSpan('x = \\frac{3}{18} = \\frac{1}{6}')}</p>` +
      `<p>Thus, the value of ${mathSpan('x')} is <strong>1/6</strong>.</p>`
  },

  // M2 Q11: ID 6a68860dc3d08d90637d3c5a (Grid-in: 725)
  {
    id: '6a68860dc3d08d90637d3c5a',
    qNum: 'M2 Q11',
    text: `<p><strong>The correct answer is 725.</strong></p>` +
      `<p>We are given the formula relating temperature in Fahrenheit ${mathSpan('h')} to temperature in kelvins ${mathSpan('v')}:</p>` +
      `<p>${mathSpan('h = \\frac{9(v - 273.15)}{5} + 32')}</p>` +
      `<p>Substitute ${mathSpan('h = 845.33')}:</p>` +
      `<p>${mathSpan('845.33 = \\frac{9(v - 273.15)}{5} + 32')}</p>` +
      `<p>Subtract 32 from both sides:</p>` +
      `<p>${mathSpan('813.33 = \\frac{9(v - 273.15)}{5}')}</p>` +
      `<p>Multiply both sides by 5:</p>` +
      `<p>${mathSpan('4{,}066.65 = 9(v - 273.15)')}</p>` +
      `<p>Divide both sides by 9:</p>` +
      `<p>${mathSpan('v - 273.15 = \\frac{4{,}066.65}{9} = 451.85')}</p>` +
      `<p>Add 273.15 to both sides:</p>` +
      `<p>${mathSpan('v = 451.85 + 273.15 = 725')}</p>` +
      `<p>Thus, the substance has a temperature of <strong>725</strong> kelvins.</p>`
  },

  // M2 Q12: ID 6a68868ac3d08d90637d3c5e (MCQ: Choice A, 39)
  {
    id: '6a68868ac3d08d90637d3c5e',
    qNum: 'M2 Q12',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>A quadratic equation ${mathSpan('Ax^2 + Bx + C = 0')} has exactly one real solution if and only if its discriminant equals zero: ${mathSpan('B^2 - 4AC = 0')}.</p>` +
      `<p>In the given equation ${mathSpan('25x^2 + 10\\sqrt{39}x + p = 0')}:</p>` +
      `<p>${mathSpan('A = 25')}, ${mathSpan('B = 10\\sqrt{39}')}, and ${mathSpan('C = p')}.</p>` +
      `<p>Set the discriminant to zero:</p>` +
      `<p>${mathSpan('(10\\sqrt{39})^2 - 4(25)(p) = 0')}</p>` +
      `<p>${mathSpan('100(39) - 100p = 0')}</p>` +
      `<p>${mathSpan('3{,}900 - 100p = 0')}</p>` +
      `<p>${mathSpan('100p = 3{,}900 \\implies p = 39')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because ${mathSpan('39\\sqrt{39}')} leaves an extra square root.</p>` +
      `<p>Choice C is incorrect because ${mathSpan('2\\sqrt{39}')} does not square the coefficient properly.</p>` +
      `<p>Choice D is incorrect because ${mathSpan('\\frac{39}{2}')} divides by an extra factor of 2.</p>`
  },

  // M2 Q13: ID 6a688775c3d08d90637d3c68 (MCQ: Choice A, 72)
  {
    id: '6a688775c3d08d90637d3c68',
    qNum: 'M2 Q13',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>The function is given by ${mathSpan('f(x) = 2{,}570(0.28)^{\\frac{x}{12}')}, where ${mathSpan('x')} is the number of months of use.</p>` +
      `<p>Since there are 12 months in one year, after each additional year (${mathSpan('x = 12')}), the exponent increases by ${mathSpan('\\frac{12}{12} = 1')}. This means the value of the equipment is multiplied by 0.28 each year.</p>` +
      `<p>If the value is multiplied by a factor of 0.28, the value remaining is 28% of its value the preceding year. The percentage decrease is:</p>` +
      `<p>${mathSpan('100\\% - 28\\% = 72\\%')}</p>` +
      `<p>Therefore, the value decreases each year by 72% of its preceding value, so ${mathSpan('p = 72')}.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect and represents an unrelated base value.</p>` +
      `<p>Choice C is incorrect because 28% is the percentage of value retained, not the percentage decrease.</p>` +
      `<p>Choice D is incorrect because 2% does not reflect the annual multiplier of 0.28.</p>`
  },

  // M2 Q14: ID 6a6889a5c3d08d90637d3c6c (MCQ: Choice A, 168)
  {
    id: '6a6889a5c3d08d90637d3c6c',
    qNum: 'M2 Q14',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>In triangle ${mathSpan('\\triangle RST')}, we are given ${mathSpan('RS = ST')}, which means ${mathSpan('\\triangle RST')} is an isosceles triangle with base ${mathSpan('\\overline{RT}')} of length 48.</p>` +
      `<p>1. Draw the altitude from vertex ${mathSpan('S')} perpendicular to base ${mathSpan('\\overline{RT}')} meeting at midpoint ${mathSpan('M')}. In an isosceles triangle, this altitude bisects the base:</p>` +
      `<p>${mathSpan('RM = MT = \\frac{48}{2} = 24')}</p>` +
      `<p>2. In the right triangle ${mathSpan('\\triangle RMS')}, the tangent of angle ${mathSpan('R')} is defined as:</p>` +
      `<p>${mathSpan('\\tan R = \\frac{\\text{opposite}}{\\text{adjacent}} = \\frac{SM}{RM} = \\frac{SM}{24}')}</p>` +
      `<p>We are given ${mathSpan('\\tan R = \\frac{7}{24}')}:</p>` +
      `<p>${mathSpan('\\frac{SM}{24} = \\frac{7}{24} \\implies SM = 7')}</p>` +
      `<p>So the height of the triangle is ${mathSpan('h = 7')}.</p>` +
      `<p>3. Calculate the area of ${mathSpan('\\triangle RST')}:</p>` +
      `<p>${mathSpan('\\text{Area} = \\frac{1}{2} \\times \\text{base} \\times \\text{height} = \\frac{1}{2} \\times 48 \\times 7 = 24 \\times 7 = 168\\text{ square units}')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because 288 results from using 12 instead of 7 as the height.</p>` +
      `<p>Choice C is incorrect because 84 is the area of half the triangle (${mathSpan('\\triangle RMS')}).</p>` +
      `<p>Choice D is incorrect because 336 results from forgetting the factor of ${mathSpan('\\frac{1}{2}')} in the area formula (${mathSpan('48 \\times 7 = 336')}).</p>`
  },

  // M2 Q15: ID 6a688a19c3d08d90637d3c70 (MCQ: Choice A, 42)
  {
    id: '6a688a19c3d08d90637d3c70',
    qNum: 'M2 Q15',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>In an equilateral triangle with side length ${mathSpan('s')}, drawing the altitude creates two ${mathSpan('30^\\circ-60^\\circ-90^\\circ')} special right triangles with side ratio ${mathSpan('1 : \\sqrt{3} : 2')}.</p>` +
      `<p>The relationship between the side length ${mathSpan('s')} and height ${mathSpan('h')} is:</p>` +
      `<p>${mathSpan('h = \\frac{s\\sqrt{3}}{2}')}</p>` +
      `<p>We are given that ${mathSpan('h = 21\\sqrt{3}')}:</p>` +
      `<p>${mathSpan('21\\sqrt{3} = \\frac{s\\sqrt{3}}{2}')}</p>` +
      `<p>Divide both sides by ${mathSpan('\\sqrt{3}')}:</p>` +
      `<p>${mathSpan('21 = \\frac{s}{2} \\implies s = 42')}</p>` +
      `<p>Thus, the length of one side of the equilateral triangle is <strong>42</strong> units.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because ${mathSpan('21\\sqrt{3}')} is the height, not the side length.</p>` +
      `<p>Choice C is incorrect because ${mathSpan('42\\sqrt{3}')} incorrectly multiplies by ${mathSpan('\\sqrt{3}')}.</p>` +
      `<p>Choice D is incorrect because 21 is half the side length (${mathSpan('s/2')}).</p>`
  },

  // M2 Q16: ID 6a688aa5c3d08d90637d3c76 (MCQ: Choice A)
  {
    id: '6a688aa5c3d08d90637d3c76',
    qNum: 'M2 Q16',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>We factor the expression ${mathSpan('1{,}440x^4 - 56{,}250')} step by step:</p>` +
      `<p>1. Factor out the greatest common factor (GCF), 90:</p>` +
      `<p>${mathSpan('1{,}440x^4 - 56{,}250 = 90(16x^4 - 625)')}</p>` +
      `<p>2. Recognize ${mathSpan('16x^4 - 625')} as a difference of two squares:</p>` +
      `<p>${mathSpan('16x^4 - 625 = (4x^2)^2 - 25^2 = (4x^2 + 25)(4x^2 - 25)')}</p>` +
      `<p>3. Factor ${mathSpan('4x^2 - 25')} as another difference of squares:</p>` +
      `<p>${mathSpan('4x^2 - 25 = (2x + 5)(2x - 5)')}</p>` +
      `<p>Thus, the complete factorization is:</p>` +
      `<p>${mathSpan('90(4x^2 + 25)(2x + 5)(2x - 5)')}</p>` +
      `<p>The factors of the polynomial include 90, ${mathSpan('4x^2 + 25')}, ${mathSpan('2x + 5')}, and ${mathSpan('2x - 5')}.</p>` +
      `<p>The expression ${mathSpan('2x^2 - 5')} is <strong>NOT</strong> a factor.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choices B, C, and D are incorrect because each is indeed a factor of ${mathSpan('1{,}440x^4 - 56{,}250')}.</p>`
  },

  // M2 Q17: ID 6a688b1bc3d08d90637d3c80 (MCQ: Choice A)
  {
    id: '6a688b1bc3d08d90637d3c80',
    qNum: 'M2 Q17',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>We are given the linear equation in one variable:</p>` +
      `<p>${mathSpan('2970x = 5940x')}</p>` +
      `<p>Subtract ${mathSpan('2970x')} from both sides:</p>` +
      `<p>${mathSpan('5940x - 2970x = 0')}</p>` +
      `<p>${mathSpan('2970x = 0')}</p>` +
      `<p>Divide by 2970:</p>` +
      `<p>${mathSpan('x = 0')}</p>` +
      `<p>The equation has exactly one solution (${mathSpan('x = 0')}).</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect because infinitely many solutions only occur when an equation reduces to an identity such as ${mathSpan('0 = 0')}.</p>` +
      `<p>Choice C is incorrect because a degree-1 linear equation cannot have two distinct solutions.</p>` +
      `<p>Choice D is incorrect because ${mathSpan('x = 0')} is a valid solution.</p>`
  },

  // M2 Q18: ID 6a688be0c3d08d90637d3c84 (Grid-in: 42)
  {
    id: '6a688be0c3d08d90637d3c84',
    qNum: 'M2 Q18',
    text: `<p><strong>The correct answer is 42.</strong></p>` +
      `<p>1. Find the slope ${mathSpan('m_r')} of line ${mathSpan('r')} passing through ${mathSpan('(3, 12)')} and ${mathSpan('(7, 13)')}:</p>` +
      `<p>${mathSpan('m_r = \\frac{13 - 12}{7 - 3} = \\frac{1}{4}')}</p>` +
      `<p>2. Line ${mathSpan('s')} is perpendicular to line ${mathSpan('r')}, so its slope is the negative reciprocal of ${mathSpan('\\frac{1}{4}')}:</p>` +
      `<p>${mathSpan('m_s = -4')}</p>` +
      `<p>3. Write the equation of line ${mathSpan('s')} passing through ${mathSpan('(1, 2)')}:</p>` +
      `<p>${mathSpan('y - 2 = -4(x - 1)')}</p>` +
      `<p>${mathSpan('y - 2 = -4x + 4')}</p>` +
      `<p>${mathSpan('4x + y = 6')}</p>` +
      `<p>4. The equation is given in the form ${mathSpan('ax + 7y = c')}. Multiply our equation by 7 to match the coefficient of ${mathSpan('y')} (which is 7):</p>` +
      `<p>${mathSpan('7(4x + y) = 7(6)')}</p>` +
      `<p>${mathSpan('28x + 7y = 42')}</p>` +
      `<p>Comparing coefficients: ${mathSpan('a = 28')} and ${mathSpan('c = 42')}.</p>` +
      `<p>Thus, the value of ${mathSpan('c')} is <strong>42</strong>.</p>`
  },

  // M2 Q19: ID 6a688c8ec3d08d90637d3c88 (Grid-in: 61/65 or 0.938)
  {
    id: '6a688c8ec3d08d90637d3c88',
    qNum: 'M2 Q19',
    text: `<p><strong>The correct answer is 61/65 (or 0.938).</strong></p>` +
      `<p>We are asked for the conditional probability that a randomly selected neuron has a cell body diameter less than or equal to 30 micrometers, given that it is <strong>not</strong> classified as a motor neuron.</p>` +
      `<p>1. Find the total number of neurons that are not motor neurons (the given condition):</p>` +
      `<p>Total non-motor neurons = Sensory neurons + Interneurons</p>` +
      `<p>• Sensory neurons: ${mathSpan('12 + 7 + 4 = 23')}</p>` +
      `<p>• Interneurons: ${mathSpan('10 + 32 + 0 = 42')}</p>` +
      `<p>• Total non-motor = ${mathSpan('23 + 42 = 65')}</p>` +
      `<p>2. Among these 65 non-motor neurons, count those with cell body diameter ${mathSpan('\\le 30\\ \\mu\\text{m}')} ("Less than 20" or "20 to 30"):</p>` +
      `<p>• Sensory with diameter ${mathSpan('\\le 30\\ \\mu\\text{m}')}: ${mathSpan('12 + 7 = 19')}</p>` +
      `<p>• Interneurons with diameter ${mathSpan('\\le 30\\ \\mu\\text{m}')}: ${mathSpan('10 + 32 = 42')}</p>` +
      `<p>• Total favorable = ${mathSpan('19 + 42 = 61')}</p>` +
      `<p>3. Calculate the conditional probability:</p>` +
      `<p>${mathSpan('P = \\frac{61}{65} \\approx 0.93846\\dots')}</p>` +
      `<p>Entering <strong>61/65</strong> or <strong>0.938</strong> is correct.</p>`
  },

  // M2 Q20: ID 6a688d07c3d08d90637d3c8e (MCQ: Choice A, 103.67%)
  {
    id: '6a688d07c3d08d90637d3c8e',
    qNum: 'M2 Q20',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>1. An increase of 179% corresponds to multiplying by a growth factor of:</p>` +
      `<p>${mathSpan('1 + \\frac{179}{100} = 1 + 1.79 = 2.79')}</p>` +
      `<p>2. A decrease of 27% corresponds to multiplying by a decay factor of:</p>` +
      `<p>${mathSpan('1 - \\frac{27}{100} = 1 - 0.27 = 0.73')}</p>` +
      `<p>3. The overall multiplier from the end of 2017 to the end of 2019 is the product of the two factors:</p>` +
      `<p>${mathSpan('2.79 \\times 0.73 = 2.0367')}</p>` +
      `<p>4. The net percentage increase is:</p>` +
      `<p>${mathSpan('(2.0367 - 1) \\times 100\\% = 1.0367 \\times 100\\% = 103.67\\%')}</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choice B is incorrect and results from calculating ${mathSpan('179 + (179 \\times 0.27)')}.</p>` +
      `<p>Choice C is incorrect because ${mathSpan('179\\% - 27\\% = 152\\%')} ignores compounding.</p>` +
      `<p>Choice D is incorrect and represents an arithmetic error.</p>`
  },

  // M2 Q21: ID 6a688da0c3d08d90637d3c92 (MCQ: Choice A)
  {
    id: '6a688da0c3d08d90637d3c92',
    qNum: 'M2 Q21',
    text: `<p><strong>Choice A is correct.</strong></p>` +
      `<p>We are given the equation ${mathSpan('5x + 3y = 6')}. The system has at least one solution if the second equation either intersects the given line at one point or represents the exact same line (infinitely many solutions):</p>` +
      `<p>• <strong>Analyze Statement I:</strong> ${mathSpan('7.5x + 4.5y = 9')}.</p>` +
      `<p>Multiply the given equation ${mathSpan('5x + 3y = 6')} by 1.5:</p>` +
      `<p>${mathSpan('1.5(5x + 3y) = 1.5(6) \\implies 7.5x + 4.5y = 9')}</p>` +
      `<p>This is identical to the first equation, meaning the lines coincide and the system has infinitely many solutions (which is at least one solution). Thus, I is valid.</p>` +
      `<p>• <strong>Analyze Statement II:</strong> ${mathSpan('7.5x - 4.5y = 4.5')}.</p>` +
      `<p>The slope of the given equation is ${mathSpan('m_1 = -\\frac{5}{3}')}. The slope of equation II is ${mathSpan('m_2 = -\\frac{7.5}{-4.5} = \\frac{5}{3}')}. Since the slopes are different (${mathSpan('-\\frac{5}{3} \\neq \\frac{5}{3}')}), the two lines intersect at exactly one unique point. Thus, II is valid.</p>` +
      `<p>Therefore, both <strong>I and II</strong> could be the other equation in the system.</p>` +
      `<p><strong>Distractor Analysis:</strong></p>` +
      `<p>Choices B, C, and D are incorrect because each omits one or both valid equations.</p>`
  },

  // M2 Q22: ID 6a688e61c3d08d90637d3c96 (Grid-in: 97.5 or 195/2)
  {
    id: '6a688e61c3d08d90637d3c96',
    qNum: 'M2 Q22',
    text: `<p><strong>The correct answer is 97.5 (or 195/2).</strong></p>` +
      `<p>1. Angle ${mathSpan('\\angle ABC')} is an inscribed angle with a measure of ${mathSpan('90^\\circ')}. By Thales's Theorem, an inscribed right angle in a circle must intercept a semicircle, which means chord ${mathSpan('\\overline{AC}')} is a diameter of the circle.</p>` +
      `<p>2. We are given that the diameter of the circle is 197, so:</p>` +
      `<p>${mathSpan('AC = 197')}</p>` +
      `<p>Since ${mathSpan('D')} lies on ${mathSpan('\\overline{AC}')}, ${mathSpan('AD + CD = AC = 197')}.</p>` +
      `<p>3. Segment ${mathSpan('\\overline{BE}')} is perpendicular to ${mathSpan('\\overline{AC}')} at point ${mathSpan('D')}. In the right triangle ${mathSpan('\\triangle ABC')}, ${mathSpan('\\overline{BD}')} is the altitude drawn to the hypotenuse ${mathSpan('\\overline{AC}')}.</p>` +
      `<p>By the Geometric Mean (Altitude) Theorem:</p>` +
      `<p>${mathSpan('BD^2 = AD \\cdot CD')}</p>` +
      `<p>We are given ${mathSpan('BD = \\sqrt{390}')}, so ${mathSpan('BD^2 = 390')}:</p>` +
      `<p>${mathSpan('AD \\cdot CD = 390')}</p>` +
      `<p>4. We have two equations for the segment lengths ${mathSpan('AD')} and ${mathSpan('CD')}:</p>` +
      `<p>• ${mathSpan('AD + CD = 197')}</p>` +
      `<p>• ${mathSpan('AD \\cdot CD = 390')}</p>` +
      `<p>Thus, ${mathSpan('AD')} and ${mathSpan('CD')} are the roots of the quadratic equation ${mathSpan('t^2 - 197t + 390 = 0')}.</p>` +
      `<p>Notice that ${mathSpan('2 \\times 195 = 390')} and ${mathSpan('2 + 195 = 197')}:</p>` +
      `<p>${mathSpan('(t - 2)(t - 195) = 0 \\implies t = 2\\text{ or } t = 195')}</p>` +
      `<p>5. We are given ${mathSpan('AB < BC')}. The projection of a shorter leg onto the hypotenuse is shorter than the projection of the longer leg, so ${mathSpan('AD < CD')}:</p>` +
      `<p>${mathSpan('AD = 2\\text{ and } CD = 195')}</p>` +
      `<p>6. Find the ratio ${mathSpan('r = \\frac{CD}{AD}')}:</p>` +
      `<p>${mathSpan('r = \\frac{195}{2} = 97.5')}</p>` +
      `<p>Thus, the value of ${mathSpan('r')} is <strong>97.5</strong> (or <strong>195/2</strong>).</p>`
  }
];

async function updateExplanations() {
  console.log(`🚀 Uploading explanations for September 2025 INT 1 Module 2 (${explanations.length} questions)...\n`);

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

  console.log('\n🎉 Finished Module 2 explanations (22 questions updated).');
}

updateExplanations();
