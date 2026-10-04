const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';

function f(formula) {
  return `<span class="ql-formula" data-value="${formula}"></span>`;
}

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
  '6a9afa2f838c4fe747f6edc1': `<p>To find the value of ${f('-18 - 2x')}:</p>
<ol>
  <li>We are given the linear equation ${f('9 + x = 6')}.</li>
  <li>Notice the relationship between ${f('9 + x')} and ${f('-18 - 2x')}:
    <p>${f('-18 - 2x = -2(9 + x)')}</p>
  </li>
  <li>Substitute ${f('9 + x = 6')}:
    <p>${f('-18 - 2x = -2(6) = -12')}</p>
  </li>
  <li>Alternatively, solving directly for ${f('x')}:
    <p>${f('x = 6 - 9 = -3')}</p>
    <p>${f('-18 - 2(-3) = -18 + 6 = -12')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('-18 - 2x')} is <strong>-12</strong>.</p>`,

  // Q2
  '6a9afb07838c4fe747f6f030': `<p>To find the value of ${f('x')}:</p>
<ol>
  <li>Lines ${f('l')} and ${f('m')} are parallel, cut by transversal ${f('k')}.</li>
  <li>The angle labeled ${f('111^\\circ')} and the angle labeled ${f('x^\\circ')} lie on opposite sides of the transversal between the two parallel lines (alternate interior angles).</li>
  <li>When two parallel lines are cut by a transversal, alternate interior angles are equal:
    <p>${f('x = 111')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('x')} is <strong>111</strong>.</p>`,

  // Q3
  '6a9afb97838c4fe747f6f04c': `<p>To determine the equation defining linear function ${f('f')}:</p>
<ol>
  <li>Identify two points on the line from the graph:
    <ul>
      <li>The line crosses the y-axis at ${f('(0, -5)')}, so the y-intercept is ${f('b = -5')}.</li>
      <li>The line also passes through ${f('(7, -8)')}.</li>
    </ul>
  </li>
  <li>Calculate the slope ${f('m')}:
    <p>${f('m = \\frac{-8 - (-5)}{7 - 0} = \\frac{-3}{7} = -\\frac{3}{7}')}</p>
  </li>
  <li>Write the slope-intercept form ${f('f(x) = mx + b')}:
    <p>${f('f(x) = -\\frac{3}{7}x - 5')}</p>
  </li>
</ol>
<p>Thus, the correct equation is <strong>${f('f(x) = -\\frac{3}{7}x - 5')}</strong>.</p>`,

  // Q4
  '6a9afd77838c4fe747f6f052': `<p>To determine which statement is <strong>NOT true</strong>:</p>
<ol>
  <li>The graph shows estimated melting temperature ${f('f(x)')} as a function of guanine-cytosine (GC) content ${f('x')}.</li>
  <li>At ${f('x = 0')}, the melting temperature is approximately ${f('64^\\circ\\text{C}')}.</li>
  <li>The slope is positive, approximately ${f('\\frac{2}{5} = 0.4')} degrees Celsius per percentage point.</li>
  <li>At ${f('x = 98\\%')}, the estimated melting temperature is approximately:
    <p>${f('f(98) \\approx 64 + 0.41(98) \\approx 104^\\circ\\text{C}')}</p>
    This is well above ${f('90^\\circ\\text{C}')}, making the statement that the temperature is between ${f('80^\\circ\\text{C}')} and ${f('90^\\circ\\text{C}')} completely false.
  </li>
</ol>
<p>Therefore, the statement that is NOT true is: <strong>A DNA molecule with a GC content of 98% has an estimated melting temperature between 80°C and 90°C.</strong></p>`,

  // Q5
  '6a9afddf838c4fe747f6f05e': `<p>To find the slope of line ${f('t')}:</p>
<ol>
  <li>Line ${f('s')} is defined by ${f('y + 16 = 7x')}. Rewrite it in slope-intercept form ${f('y = mx + b')}:
    <p>${f('y = 7x - 16')}</p>
  </li>
  <li>The slope of line ${f('s')} is ${f('m = 7')}.</li>
  <li>Parallel lines in the xy-plane have equal slopes. Since line ${f('t')} is parallel to line ${f('s')}, the slope of line ${f('t')} is also 7.</li>
</ol>
<p>Thus, the slope of line ${f('t')} is <strong>7</strong>.</p>`,

  // Q6
  '6a9afe67838c4fe747f6f064': `<p>To find the predicted number of larvae for 39 worker ants:</p>
<ol>
  <li>The model is given by the linear equation:
    <p>${f('y = 0.67x + 2.6')}</p>
  </li>
  <li>Substitute ${f('x = 39')}:
    <p>${f('y = 0.67(39) + 2.6')}</p>
  </li>
  <li>Calculate:
    <p>${f('y = 26.13 + 2.6 = 28.73')}</p>
  </li>
  <li>Rounding to the nearest whole integer yields 29.</li>
</ol>
<p>Thus, the predicted number of larvae is closest to <strong>29</strong>.</p>`,

  // Q7
  '6a9afeff838c4fe747f6f112': `<p>To find the table where all pairs satisfy ${f('y > 5x - 4')}:</p>
<ol>
  <li>Compute the threshold value ${f('5x - 4')} for each ${f('x')}:
    <ul>
      <li>For ${f('x = 4')}: ${f('5(4) - 4 = 16')}. We need ${f('y > 16')}.</li>
      <li>For ${f('x = 6')}: ${f('5(6) - 4 = 26')}. We need ${f('y > 26')}.</li>
      <li>For ${f('x = 9')}: ${f('5(9) - 4 = 41')}. We need ${f('y > 41')}.</li>
    </ul>
  </li>
  <li>Check the table containing values ${f('(4, 21)')}, ${f('(6, 31)')}, and ${f('(9, 46)')}:
    <ul>
      <li>${f('21 > 16')} (True)</li>
      <li>${f('31 > 26')} (True)</li>
      <li>${f('46 > 41')} (True)</li>
    </ul>
  </li>
  <li>All other tables have values equal to or less than ${f('5x - 4')}.</li>
</ol>
<p>Thus, the correct table is the one with pairs <strong>(4, 21), (6, 31), and (9, 46)</strong>.</p>`,

  // Q8
  '6a9affb6838c4fe747f6f1e3': `<p>To solve the equation ${f('P = N(34 - C)')} for ${f('C')}:</p>
<ol>
  <li>Divide both sides by ${f('N')}:
    <p>${f('\\frac{P}{N} = 34 - C')}</p>
  </li>
  <li>Add ${f('C')} to both sides:
    <p>${f('C + \\frac{P}{N} = 34')}</p>
  </li>
  <li>Subtract ${f('\\frac{P}{N}')} from both sides:
    <p>${f('C = 34 - \\frac{P}{N}')}</p>
  </li>
</ol>
<p>Thus, the expression representing ${f('C')} is <strong>${f('34 - \\frac{P}{N}')}</strong>.</p>`,

  // Q9
  '6a9affeb838c4fe747f6f1e9': `<p>To find the sum of the solutions to ${f('x^2 - 15x + 12 = 0')}:</p>
<ol>
  <li>For any quadratic equation ${f('ax^2 + bx + c = 0')}, Vieta's formulas state that the sum of the solutions is:
    <p>${f('\\text{Sum} = -\\frac{b}{a}')}</p>
  </li>
  <li>Here, ${f('a = 1')}, ${f('b = -15')}, and ${f('c = 12')}.</li>
  <li>Therefore:
    <p>${f('\\text{Sum} = -\\frac{-15}{1} = 15')}</p>
  </li>
</ol>
<p>Thus, the sum of the solutions is <strong>15</strong>.</p>`,

  // Q10
  '6a9b007c838c4fe747f6f1ef': `<p>To find the total surface area of the right rectangular pyramid:</p>
<ol>
  <li>The rectangular base has length ${f('l = 18')} and width ${f('w = 9')}:
    <p>${f('\\text{Base Area} = l \\times w = 18 \\times 9 = 162\\text{ units}^2')}</p>
  </li>
  <li>The height from the apex to the center of the base is ${f('h = 12')}.</li>
  <li>Find the slant height ${f('s_w')} of the two triangular faces with base ${f('w = 9')}:
    <p>The perpendicular distance from base center to the side is ${f('l/2 = 9')}.</p>
    <p>${f('s_w = \\sqrt{12^2 + 9^2} = \\sqrt{144 + 81} = \\sqrt{225} = 15')}</p>
    <p>${f('\\text{Area of two faces} = 2 \\times \\left(\\frac{1}{2} \\times 9 \\times 15\\right) = 135')}</p>
  </li>
  <li>Find the slant height ${f('s_l')} of the two triangular faces with base ${f('l = 18')}:
    <p>The perpendicular distance from base center to the side is ${f('w/2 = 4.5')}.</p>
    <p>${f('s_l = \\sqrt{12^2 + 4.5^2} = \\sqrt{144 + 20.25} = \\sqrt{164.25} = \\sqrt{\\frac{657}{4}} = \\frac{3\\sqrt{73}}{2}')}</p>
    <p>${f('\\text{Area of two faces} = 2 \\times \\left(\\frac{1}{2} \\times 18 \\times \\frac{3\\sqrt{73}}{2}\\right) = 27\\sqrt{73}')}</p>
  </li>
  <li>Add all surface areas:
    <p>${f('\\text{Total Surface Area} = 162 + 135 + 27\\sqrt{73} = 297 + 27\\sqrt{73}')}</p>
  </li>
</ol>
<p>Thus, the surface area is <strong>${f('297 + 27\\sqrt{73}')}</strong>.</p>`,

  // Q11
  '6a9b0cea838c4fe747f71adc': `<p>To interpret the vertex of ${f('f(x) = \\frac{1}{7}(x - 6)^2 + 4')}:</p>
<ol>
  <li>The quadratic function is written in vertex form ${f('f(x) = a(x - h)^2 + k')}, where the vertex is ${f('(h, k) = (6, 4)')}.</li>
  <li>Since the leading coefficient ${f('a = \\frac{1}{7} > 0')}, the parabola opens upward, meaning the vertex represents the absolute minimum point of the function.</li>
  <li>In this context, ${f('x = 6')} is the time in seconds, and ${f('f(x) = 4')} is the height in inches.</li>
  <li>Therefore, the car reaches its minimum height of 4 inches at 6 seconds.</li>
</ol>
<p>Thus, the best interpretation is: <strong>The toy car's minimum height was 4 inches above the ground.</strong></p>`,

  // Q12
  '6a9b0d5a838c4fe747f71dc8': `<p>To find the expression representing the length of ${f('QS')}:</p>
<ol>
  <li>In right triangle ${f('QRS')} with right angle at ${f('R')}, ${f('QS')} is the hypotenuse and ${f('QR')} is adjacent to angle ${f('Q')}.</li>
  <li>By the definition of cosine:
    <p>${f('\\cos Q = \\frac{\\text{Adjacent}}{\\text{Hypotenuse}} = \\frac{QR}{QS} = \\frac{47}{QS}')}</p>
  </li>
  <li>Solve for ${f('QS')}:
    <p>${f('QS = \\frac{47}{\\cos Q}')}</p>
  </li>
</ol>
<p>Thus, the length of ${f('QS')} is represented by <strong>${f('\\frac{47}{\\cos Q}')}</strong>.</p>`,

  // Q13
  '6a9b0d96838c4fe747f71f58': `<p>To find the sum of undergraduate students and postdoctoral students:</p>
<ol>
  <li>Let ${f('U')}, ${f('G')}, and ${f('P')} represent the number of undergraduate, graduate, and postdoctoral students respectively.</li>
  <li>We are given:
    <ul>
      <li>${f('U = 7{,}150\\% \\text{ of } P = 71.5P')}</li>
      <li>${f('G = 45\\% \\text{ of } U = 0.45U = 6{,}435')}</li>
    </ul>
  </li>
  <li>Solve for ${f('U')}:
    <p>${f('U = \\frac{6{,}435}{0.45} = 14{,}300')}</p>
  </li>
  <li>Solve for ${f('P')}:
    <p>${f('P = \\frac{U}{71.5} = \\frac{14{,}300}{71.5} = 200')}</p>
  </li>
  <li>Calculate the sum ${f('U + P')}:
    <p>${f('U + P = 14{,}300 + 200 = 14{,}500')}</p>
  </li>
</ol>
<p>Thus, the sum is <strong>14,500</strong>.</p>`,

  // Q14
  '6a9b0f07111ffc76c2e5f937': `<p>To find the value of ${f('t')} such that the system has no solution:</p>
<ol>
  <li>Simplify the first equation:
    <p>${f('16x - 20y = 6y + 8 \\implies 16x - 26y = 8')}</p>
    Divide by 2:
    <p>${f('8x - 13y = 4 \\implies 13y = 8x - 4')}</p>
  </li>
  <li>The second equation is:
    <p>${f('ty = 8x + \\frac{1}{5}')}</p>
  </li>
  <li>A linear system has no solution when the two lines are parallel and distinct (same slope, different y-intercepts).</li>
  <li>Comparing the two equations ${f('13y = 8x - 4')} and ${f('ty = 8x + \\frac{1}{5}')}, the coefficients of ${f('x')} are identical (8), so the coefficients of ${f('y')} must be equal:
    <p>${f('t = 13')}</p>
  </li>
  <li>Since ${f('-\\frac{4}{13} \\ne \\frac{1/5}{13}')}, the lines are distinct, confirming there is no solution.</li>
</ol>
<p>Thus, the value of ${f('t')} is <strong>13</strong>.</p>`,

  // Q15
  '6a9b0fc9111ffc76c2e5fa55': `<p>To find the equation defining ${f('g(x)')}:</p>
<ol>
  <li>The function ${f('f')} is defined by ${f('f(x) = 7(4)^x')}.</li>
  <li>We are given ${f('g(x) = f(x + 3)')}. Substitute ${f('x + 3')} into ${f('f(x)')}:
    <p>${f('g(x) = 7(4)^{x + 3}')}</p>
  </li>
  <li>Using exponent rules ${f('a^{m+n} = a^m \\cdot a^n')}:
    <p>${f('g(x) = 7 \\cdot 4^3 \\cdot 4^x')}</p>
  </li>
  <li>Since ${f('4^3 = 64')}:
    <p>${f('g(x) = 7(64)(4)^x = 448(4)^x')}</p>
  </li>
</ol>
<p>Thus, the equation defining ${f('g')} is <strong>${f('g(x) = 448(4)^x')}</strong>.</p>`,

  // Q16
  '6a9b1069111ffc76c2e5fdcf': `<p>To convert bone mineral density from grams per square centimeter to grams per square millimeter:</p>
<ol>
  <li>We are given that ${f('1\\text{ cm} = 10\\text{ mm}')}.</li>
  <li>Squaring both sides gives the area conversion:
    <p>${f('1\\text{ cm}^2 = (10\\text{ mm})^2 = 100\\text{ mm}^2')}</p>
  </li>
  <li>Convert the density:
    <p>${f('0.812\\text{ g/cm}^2 = \\frac{0.812\\text{ g}}{100\\text{ mm}^2} = 0.00812\\text{ g/mm}^2')}</p>
  </li>
</ol>
<p>Thus, the density in grams per square millimeter is <strong>0.00812</strong>.</p>`,

  // Q17
  '6a9b10ba111ffc76c2e5fe43': `<p>To find a factor of ${f('49p^{19} - 121p^{17}')}:</p>
<ol>
  <li>Factor out the greatest common factor ${f('p^{17}')}:
    <p>${f('49p^{19} - 121p^{17} = p^{17}(49p^2 - 121)')}</p>
  </li>
  <li>Notice that ${f('49p^2 - 121')} is a difference of two squares:
    <p>${f('49p^2 - 121 = (7p)^2 - (11)^2 = (7p - 11)(7p + 11)')}</p>
  </li>
  <li>The completely factored expression is:
    <p>${f('p^{17}(7p - 11)(7p + 11)')}</p>
  </li>
  <li>Among the options, ${f('7p + 11')} is one of the factors.</li>
</ol>
<p>Thus, a factor is <strong>${f('7p + 11')}</strong>.</p>`,

  // Q18
  '6a9b11fc111ffc76c2e5fed3': `<p>To find the value of positive constant ${f('k')}:</p>
<ol>
  <li>Set the factored equation to zero:
    <p>${f('\\frac{5}{9}(5x + 9)(x + \\sqrt{5k + 9})(x - \\sqrt{5k + 9}) = 0')}</p>
  </li>
  <li>Find the three roots:
    <p>${f('5x + 9 = 0 \\implies x_1 = -\\frac{9}{5}')}</p>
    <p>${f('x + \\sqrt{5k + 9} = 0 \\implies x_2 = -\\sqrt{5k + 9}')}</p>
    <p>${f('x - \\sqrt{5k + 9} = 0 \\implies x_3 = \\sqrt{5k + 9}')}</p>
  </li>
  <li>Multiply the three solutions together:
    <p>${f('x_1 \\cdot x_2 \\cdot x_3 = \\left(-\\frac{9}{5}\\right) \\cdot \\left(-\\sqrt{5k + 9}\\right) \\cdot \\left(\\sqrt{5k + 9}\\right) = \\frac{9}{5}(5k + 9)')}</p>
  </li>
  <li>We are given that this product equals 72:
    <p>${f('\\frac{9}{5}(5k + 9) = 72')}</p>
    <p>${f('5k + 9 = 72 \\times \\frac{5}{9} = 40')}</p>
    <p>${f('5k = 31 \\implies k = \\frac{31}{5}')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('k')} is <strong>${f('\\frac{31}{5}')}</strong>.</p>`,

  // Q19
  '6a9b1187111ffc76c2e5feb9': `<p>To find the surface area of the right rectangular prism:</p>
<ol>
  <li>The rectangular base has length ${f('l = \\frac{14}{3}')} and area ${f('56t')}.</li>
  <li>Find the width ${f('w')} of the base:
    <p>${f('l \\cdot w = \\text{Base Area} \\implies \\frac{14}{3}w = 56t')}</p>
    <p>${f('w = 56t \\times \\frac{3}{14} = 12t\\text{ cm}')}</p>
  </li>
  <li>The prism has height ${f('h = 3\\text{ cm}')}.</li>
  <li>The total surface area is:
    <p>${f('\\text{Surface Area} = 2(lw) + 2(lh) + 2(wh)')}</p>
  </li>
  <li>Substitute the known dimensions:
    <p>${f('2(lw) = 2(56t) = 112t')}</p>
    <p>${f('2(lh) = 2\\left(\\frac{14}{3} \\times 3\\right) = 2(14) = 28')}</p>
    <p>${f('2(wh) = 2(12t \\times 3) = 72t')}</p>
  </li>
  <li>Combine like terms:
    <p>${f('\\text{Surface Area} = 112t + 28 + 72t = 184t + 28\\text{ cm}^2')}</p>
  </li>
</ol>
<p>Thus, the surface area is <strong>${f('184t + 28')}</strong>.</p>`,

  // Q20
  '6a9b12d5111ffc76c2e600fa': `<p>To find the value of ${f('\\frac{\\cos p}{\\sin p}')}:</p>
<ol>
  <li>Point ${f('A(1, 0)')} lies on the positive x-axis.</li>
  <li>Point ${f('B\\left(\\frac{5}{\\sqrt{34}}, -\\frac{3}{\\sqrt{34}}\\right)')} lies on the unit circle since:
    <p>${f('\\left(\\frac{5}{\\sqrt{34}}\\right)^2 + \\left(-\\frac{3}{\\sqrt{34}}\\right)^2 = \\frac{25}{34} + \\frac{9}{34} = 1')}</p>
  </li>
  <li>The geometric angle ${f('\\angle AOB = p')} radians has adjacent side length 5 and opposite side length 3 in the reference right triangle formed with the x-axis.</li>
  <li>Therefore, for angle ${f('p')}:
    <p>${f('\\cos p = \\frac{5}{\\sqrt{34}}')} and ${f('\\sin p = \\frac{3}{\\sqrt{34}}')}</p>
  </li>
  <li>Calculate the quotient:
    <p>${f('\\frac{\\cos p}{\\sin p} = \\frac{5/\\sqrt{34}}{3/\\sqrt{34}} = \\frac{5}{3}')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('\\frac{\\cos p}{\\sin p}')} is <strong>${f('\\frac{5}{3}')}</strong>.</p>`,

  // Q21
  '6a9b13a9111ffc76c2e603c4': `<p>To find the greatest possible value of ${f('m')}:</p>
<ol>
  <li>The function is ${f('h(x) = -\\sqrt{x^2 + bx + c}')}.</li>
  <li>The graph contains ${f('(0, -\\sqrt{334})')}:
    <p>${f('h(0) = -\\sqrt{c} = -\\sqrt{334} \\implies c = 334')}</p>
  </li>
  <li>The graph contains ${f('(2, 0)')}:
    <p>${f('h(2) = -\\sqrt{2^2 + 2b + 334} = -\\sqrt{2b + 338} = 0')}</p>
    <p>${f('2b + 338 = 0 \\implies b = -169')}</p>
  </li>
  <li>Now find where ${f('h(m) = 0')}:
    <p>${f('-\\sqrt{m^2 - 169m + 334} = 0 \\implies m^2 - 169m + 334 = 0')}</p>
  </li>
  <li>Factor the quadratic equation:
    <p>Notice that ${f('2 \\times 167 = 334')} and ${f('2 + 167 = 169')}:</p>
    <p>${f('(m - 2)(m - 167) = 0')}</p>
    The solutions are ${f('m = 2')} and ${f('m = 167')}.
  </li>
  <li>The greatest possible value is 167.</li>
</ol>
<p>Thus, the greatest possible value of ${f('m')} is <strong>167</strong>.</p>`,

  // Q22
  '6a9b1469111ffc76c2e604b5': `<p>To find the function ${f('f(x)')} giving the total repair cost for ${f('x \\ge 2')} hours:</p>
<ol>
  <li>The technician charges a flat $160 for the first 2 hours.</li>
  <li>For 6 total hours of repair, there are ${f('6 - 2 = 4')} additional hours.</li>
  <li>The total cost for 6 hours is $360. Subtracting the flat initial fee gives the cost for the 4 additional hours:
    <p>${f('360 - 160 = 200\\text{ dollars}')}</p>
  </li>
  <li>The hourly rate for each additional hour is:
    <p>${f('\\text{Hourly rate} = \\frac{200}{4} = 50\\text{ dollars per hour}')}</p>
  </li>
  <li>For any ${f('x \\ge 2')} hours, the total cost consists of the base 160 plus $50 for each of the ${f('x - 2')} additional hours:
    <p>${f('f(x) = 160 + 50(x - 2)')}</p>
  </li>
  <li>Expand and simplify:
    <p>${f('f(x) = 160 + 50x - 100 = 50x + 60')}</p>
  </li>
</ol>
<p>Thus, the function is <strong>${f('f(x) = 50x + 60')}</strong>.</p>`
};

async function run() {
  console.log('Injecting 22 pedagogical explanations for May 2025 · INT 1 Module 2...\n');

  // Also ensure Q15 stem & answer are updated
  await updateQuestion('6a9b0fc9111ffc76c2e5fa55', {
    question: `<p>The function ${f('f')} is defined by ${f('f(x) = 7(4)^x')}. If ${f('g(x) = f(x + 3)')}, which of the following equations defines the function ${f('g')}?</p>`,
    correctAnswer: `<p>${f('g(x) = 448(4)^x')}</p>`,
    wrongAnswer: [
      `<p>${f('g(x) = 21(4)^x')}</p>`,
      `<p>${f('g(x) = 21(12)^x')}</p>`,
      `<p>${f('g(x) = 343(64)^x')}</p>`
    ]
  });
  console.log('Q15 stem and choices refined: ✅\n');

  let count = 0;
  for (const [id, expl] of Object.entries(explanations)) {
    process.stdout.write(`Updating Q ${id} (${++count}/22)... `);
    await updateQuestion(id, { explanation: expl });
    console.log('✅');
  }
  console.log('\n🎉 Successfully injected all 22 M2 explanations!');
}

run().catch(console.error);
