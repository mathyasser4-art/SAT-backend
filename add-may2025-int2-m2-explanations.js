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
  '6a9b475c111ffc76c2e63e78': `<p>To find the total lease cost when the monthly payment is $300:</p>
<ol>
  <li>The total cost function is given by:
    <p>${f('f(x) = 24x + 1{,}000')}</p>
    where ${f('x')} is the monthly payment.
  </li>
  <li>Substitute ${f('x = 300')} into the function:
    <p>${f('f(300) = 24(300) + 1{,}000')}</p>
  </li>
  <li>Multiply and add:
    <p>${f('f(300) = 7{,}200 + 1{,}000 = 8{,}200')}</p>
  </li>
</ol>
<p>Thus, the total cost to lease the car is <strong>8,200</strong> dollars.</p>`,

  // Q2
  '6a9b47e3111ffc76c2e6401a': `<p>To prove that line ${f('j')} is parallel to line ${f('k')}:</p>
<ol>
  <li>Transversal ${f('l')} intersects parallel lines ${f('j')} and ${f('k')}.</li>
  <li>Angle ${f('w^\\circ')} and the angle measuring ${f('54^\\circ')} occupy the same relative position at each intersection (top-right quadrant), making them <strong>corresponding angles</strong>.</li>
  <li>By the Converse of the Corresponding Angles Postulate, if two lines cut by a transversal have equal corresponding angles, the lines are parallel.</li>
  <li>Therefore, knowing that ${f('w = 54')} is sufficient to prove that lines ${f('j')} and ${f('k')} are parallel.</li>
</ol>
<p>Thus, the sufficient piece of information is <strong>${f('w = 54')}</strong>.</p>`,

  // Q3
  '6a9c03d24471c51d35c18e2d': `<p>To find the value of ${f('r')} for which the equation has no solution:</p>
<ol>
  <li>The given linear equation is:
    <p>${f('5x + 3 = rx + 7')}</p>
  </li>
  <li>A linear equation in one variable has no solution if the variable coefficients on both sides are equal but the constant terms are different.</li>
  <li>Equating the coefficients of ${f('x')}:
    <p>${f('r = 5')}</p>
  </li>
  <li>When ${f('r = 5')}, the equation simplifies to ${f('5x + 3 = 5x + 7 \\implies 3 = 7')}, which is a contradiction with no solution.</li>
</ol>
<p>Thus, the value of ${f('r')} is <strong>5</strong>.</p>`,

  // Q4
  '6a9c042d4471c51d35c18e33': `<p>To find the value of ${f('2x + 9')}:</p>
<ol>
  <li>Let ${f('u = 2x + 9')}.</li>
  <li>Rewrite the equation in terms of ${f('u')}:
    <p>${f('5u = 3u + 74')}</p>
  </li>
  <li>Subtract ${f('3u')} from both sides:
    <p>${f('2u = 74')}</p>
  </li>
  <li>Divide by 2:
    <p>${f('u = 37')}</p>
  </li>
  <li>Since ${f('u = 2x + 9')}, the value of ${f('2x + 9')} is 37.</li>
</ol>
<p>Thus, the value of ${f('2x + 9')} is <strong>37</strong>.</p>`,

  // Q5
  '6a9c04744471c51d35c18e39': `<p>To find the value of ${f('n')}:</p>
<ol>
  <li>Convert 350% to a decimal:
    <p>${f('350\\% = \\frac{350}{100} = 3.5')}</p>
  </li>
  <li>Translate the problem statement into an equation:
    <p>${f('3.5n = 35')}</p>
  </li>
  <li>Solve for ${f('n')}:
    <p>${f('n = \\frac{35}{3.5} = 10')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('n')} is <strong>10</strong>.</p>`,

  // Q6
  '6a9c06284471c51d35c18e41': `<p>To find the equation defining the linear function ${f('h(x)')}:</p>
<ol>
  <li>From the table, the function contains points ${f('(4, 17)')} and ${f('(6, 23)')}.</li>
  <li>Calculate the slope ${f('m')}:
    <p>${f('m = \\frac{23 - 17}{6 - 4} = \\frac{6}{2} = 3')}</p>
  </li>
  <li>Use slope-intercept form ${f('h(x) = mx + b')} with point ${f('(4, 17)')}:
    <p>${f('17 = 3(4) + b \\implies 17 = 12 + b \\implies b = 5')}</p>
  </li>
  <li>Write the equation:
    <p>${f('h(x) = 3x + 5')}</p>
  </li>
</ol>
<p>Thus, the correct equation is <strong>${f('h(x) = 3x + 5')}</strong>.</p>`,

  // Q7
  '6a9c06824471c51d35c18e47': `<p>To find the intersection points of the system:</p>
<ol>
  <li>Set the two equations for ${f('y')} equal to each other:
    <p>${f('x^2 + 17x + 4 = x + 4')}</p>
  </li>
  <li>Subtract ${f('x + 4')} from both sides:
    <p>${f('x^2 + 16x = 0')}</p>
  </li>
  <li>Factor the quadratic equation:
    <p>${f('x(x + 16) = 0')}</p>
    <p>${f('x = 0')} or ${f('x = -16')}</p>
  </li>
  <li>Among the options, -16 is a possible value of ${f('x')}.</li>
</ol>
<p>Thus, a possible value of ${f('x')} is <strong>-16</strong>.</p>`,

  // Q8
  '6a9c06d04471c51d35c18e4d': `<p>To find the value of ${f('x')}:</p>
<ol>
  <li>The total length of the string is 108 inches:
    <p>${f('x + y = 108')}</p>
  </li>
  <li>We are given that ${f('x')} is 8 more than 4 times ${f('y')}:
    <p>${f('x = 4y + 8')}</p>
  </li>
  <li>Substitute this expression for ${f('x')} into the sum equation:
    <p>${f('(4y + 8) + y = 108 \\implies 5y + 8 = 108')}</p>
  </li>
  <li>Solve for ${f('y')}:
    <p>${f('5y = 100 \\implies y = 20')}</p>
  </li>
  <li>Calculate ${f('x')}:
    <p>${f('x = 4(20) + 8 = 80 + 8 = 88')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('x')} is <strong>88</strong>.</p>`,

  // Q9
  '6a9c07544471c51d35c18e53': `<p>To write the system of inequalities for the shrubs:</p>
<ol>
  <li>Let ${f('h')} be the number of hydrangeas and ${f('w')} be the number of winter hazels.</li>
  <li>"No more than 244 total shrubs" means the sum is at most 244:
    <p>${f('h + w \\le 244')}</p>
  </li>
  <li>"The number of hydrangeas will be at most three times the number of winter hazels" translates directly to:
    <p>${f('h \\le 3w')}</p>
  </li>
</ol>
<p>Thus, the correct system of inequalities is <strong>${f('h + w \\le 244')} and ${f('h \\le 3w')}</strong>.</p>`,

  // Q10
  '6a9c07ae4471c51d35c18e59': `<p>To determine which point satisfies the system of inequalities:</p>
<ol>
  <li>The system is:
    <p>${f('y \\le x + 3')}</p>
    <p>${f('y \\ge -3x - 7')}</p>
  </li>
  <li>Test point ${f('(14, 0)')}:
    <ul>
      <li>First inequality: ${f('0 \\le 14 + 3 = 17')} (True)</li>
      <li>Second inequality: ${f('0 \\ge -3(14) - 7 = -42 - 7 = -49')} (True)</li>
    </ul>
    Both inequalities are satisfied.
  </li>
  <li>Test other options:
    <ul>
      <li>${f('(0, -14)')}: ${f('-14 \\ge -7')} is False.</li>
      <li>${f('(0, 14)')}: ${f('14 \\le 3')} is False.</li>
      <li>${f('(-14, 0)')}: ${f('0 \\le -14 + 3 = -11')} is False.</li>
    </ul>
  </li>
</ol>
<p>Thus, the solution point is <strong>(14, 0)</strong>.</p>`,

  // Q11
  '6a9c09234471c51d35c1902d': `<p>To find the greatest solution to ${f('3x^2 - 5x - 5 = 0')}:</p>
<ol>
  <li>Use the quadratic formula ${f('x = \\frac{-b \\pm \\sqrt{b^2 - 4ac}}{2a}')} with ${f('a = 3')}, ${f('b = -5')}, and ${f('c = -5')}:
    <p>${f('x = \\frac{-(-5) \\pm \\sqrt{(-5)^2 - 4(3)(-5)}}{2(3)}')}</p>
  </li>
  <li>Evaluate the discriminant:
    <p>${f('b^2 - 4ac = 25 - (-60) = 25 + 60 = 85')}</p>
  </li>
  <li>The two solutions are:
    <p>${f('x = \\frac{5 \\pm \\sqrt{85}}{6} = \\frac{5}{6} \\pm \\frac{\\sqrt{85}}{6}')}</p>
  </li>
  <li>The greatest solution corresponds to the plus sign:
    <p>${f('x = \\frac{5}{6} + \\frac{\\sqrt{85}}{6}')}</p>
  </li>
</ol>
<p>Thus, the greatest solution is <strong>${f('\\frac{5}{6} + \\frac{\\sqrt{85}}{6}')}</strong>.</p>`,

  // Q12
  '6a9c0a874471c51d35c190cb': `<p>To find the positive difference in average Arctic sea ice area between 1991 and 1992:</p>
<ol>
  <li>The quadratic model is:
    <p>${f('f(x) = -0.0038400x^2 + 15.236x - 15{,}103')}</p>
  </li>
  <li>Compute the difference ${f('f(1992) - f(1991)')}:
    <p>${f('f(1992) - f(1991) = -0.0038400(1992^2 - 1991^2) + 15.236(1992 - 1991)')}</p>
  </li>
  <li>Notice that:
    <p>${f('1992^2 - 1991^2 = (1992 - 1991)(1992 + 1991) = 1 \\times 3{,}983 = 3{,}983')}</p>
  </li>
  <li>Evaluate:
    <p>${f('-0.0038400(3{,}983) + 15.236 = -15.29472 + 15.236 = -0.05872')}</p>
  </li>
  <li>The positive difference is:
    <p>${f('|-0.05872| = 0.05872\\text{ million km}^2')}</p>
    Rounding to the nearest thousandth gives <strong>0.059</strong> (or ${f('\\frac{59}{1000}')}).
  </li>
</ol>
<p>Thus, the positive difference is <strong>0.059</strong> (or <strong>${f('\\frac{59}{1000}')}</strong>).</p>`,

  // Q13
  '6a9c0ace4471c51d35c190d1': `<p>To find the y-intercept of ${f('y = \\left(\\frac{8}{13}\\right)^{x+1}')}:</p>
<ol>
  <li>The y-intercept occurs where ${f('x = 0')}.</li>
  <li>Substitute ${f('x = 0')} into the equation:
    <p>${f('y = \\left(\\frac{8}{13}\\right)^{0 + 1} = \\left(\\frac{8}{13}\\right)^1 = \\frac{8}{13}')}</p>
  </li>
  <li>In coordinate form, this is ${f('\\left(0, \\frac{8}{13}\\right)')}.</li>
</ol>
<p>Thus, the y-intercept is <strong>${f('\\left(0, \\frac{8}{13}\\right)')}</strong>.</p>`,

  // Q14
  '6a9c0b2a4471c51d35c19127': `<p>To identify the form of the equation that displays the minimum value of ${f('f(x)')}:</p>
<ol>
  <li>The quadratic function is ${f('f(x) = x^2 - 4x - 320')}.</li>
  <li>The minimum value of a parabola opening upward is displayed as a constant in <strong>vertex form</strong>:
    <p>${f('f(x) = a(x - h)^2 + k')}</p>
    where ${f('k')} is the minimum value.
  </li>
  <li>Complete the square:
    <p>${f('f(x) = (x^2 - 4x + 4) - 4 - 320')}</p>
    <p>${f('f(x) = (x - 2)^2 - 324 = (x - 2)^2 + (-324)')}</p>
  </li>
  <li>In this form, the minimum value ${f('-324')} appears explicitly as a constant.</li>
</ol>
<p>Thus, the correct form is <strong>${f('f(x) = (x - 2)^2 + (-324)')}</strong>.</p>`,

  // Q15
  '6a9c0b854471c51d35c19156': `<p>To find the value of ${f('k')}:</p>
<ol>
  <li>Find the slope of line ${f('s')}:
    <p>${f('6x + 2y = 0 \\implies 2y = -6x \\implies y = -3x')}</p>
    So ${f('m_s = -3')}.
  </li>
  <li>Line ${f('t')} is perpendicular to line ${f('s')}, so its slope is the negative reciprocal:
    <p>${f('m_t = -\\frac{1}{-3} = \\frac{1}{3}')}</p>
  </li>
  <li>Line ${f('t')} passes through ${f('(7, 0)')} and ${f('\\left(k, \\frac{4}{3}\\right)')}. Use the slope formula:
    <p>${f('m_t = \\frac{\\frac{4}{3} - 0}{k - 7} = \\frac{1}{3}')}</p>
  </li>
  <li>Solve for ${f('k')}:
    <p>${f('\\frac{4/3}{k - 7} = \\frac{1}{3} \\implies \\frac{4}{k - 7} = 1 \\implies k - 7 = 4 \\implies k = 11')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('k')} is <strong>11</strong>.</p>`,

  // Q16
  '6a9c0c054471c51d35c1915c': `<p>To find the value of ${f('a')} in ${f('g(x) = x^3 + ax^2 + bx + c')}:</p>
<ol>
  <li>The zeros of the polynomial are -2, -7, and 6.</li>
  <li>In a monic polynomial ${f('x^3 + ax^2 + bx + c')}, Vieta's formulas state that the coefficient of ${f('x^2')} is the negative sum of its roots:
    <p>${f('a = - (r_1 + r_2 + r_3)')}</p>
  </li>
  <li>Add the given roots:
    <p>${f('r_1 + r_2 + r_3 = (-2) + (-7) + 6 = -3')}</p>
  </li>
  <li>Therefore:
    <p>${f('a = -(-3) = 3')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('a')} is <strong>3</strong>.</p>`,

  // Q17
  '6a9c0c694471c51d35c1918c': `<p>To compare the standard deviations of weight for group A and group B:</p>
<ol>
  <li>Standard deviation measures the degree of dispersion or spread of data values about their mean.</li>
  <li>For Group A, the histogram shows high frequencies at the outer boundaries (6 objects at 0-1 g and 6 objects at 4-5 g) and very few near the mean (2.1 g), creating a wide, U-shaped spread with high variance.</li>
  <li>For Group B, the histogram shows that 10 out of the 20 objects are tightly clustered in the central bin (11-12 g) directly around the mean (11.1 g), with very few objects in the tails.</li>
  <li>Because Group A has its data distributed farther from its center, its standard deviation is strictly greater than that of Group B.</li>
</ol>
<p>Thus, the true statement is: <strong>The standard deviation of weight for the objects in group A is greater than the standard deviation of weight for the objects in group B.</strong></p>`,

  // Q18
  '6a9c0ca34471c51d35c19192': `<p>To write the total charge equation for ${f('x > 3')} hours:</p>
<ol>
  <li>The carpenter charges a flat rate of $216 for the first 3 hours.</li>
  <li>For ${f('x > 3')} hours, the number of additional hours worked beyond the first 3 hours is ${f('x - 3')}.</li>
  <li>Each additional hour costs $60, giving an additional charge of ${f('60(x - 3)')}.</li>
  <li>Total charge ${f('y')} is:
    <p>${f('y = 216 + 60(x - 3)')}</p>
  </li>
  <li>Expand and simplify:
    <p>${f('y = 216 + 60x - 180 = 60x + 36')}</p>
  </li>
</ol>
<p>Thus, the equation is <strong>y = 60x + 36</strong>.</p>`,

  // Q19
  '6a9c0d2f4471c51d35c191c3': `<p>To solve the equation for ${f('q')}:</p>
<ol>
  <li>The given equation is:
    <p>${f('\\frac{46}{p} = \\frac{46}{q} - \\frac{46}{r} - \\frac{46}{s}')}</p>
  </li>
  <li>Divide each term by 46:
    <p>${f('\\frac{1}{p} = \\frac{1}{q} - \\frac{1}{r} - \\frac{1}{s}')}</p>
  </li>
  <li>Isolate ${f('\\frac{1}{q}')}:
    <p>${f('\\frac{1}{q} = \\frac{1}{p} + \\frac{1}{r} + \\frac{1}{s}')}</p>
  </li>
  <li>Find a common denominator ${f('prs')}:
    <p>${f('\\frac{1}{q} = \\frac{rs + ps + pr}{prs}')}</p>
  </li>
  <li>Take the reciprocal of both sides:
    <p>${f('q = \\frac{prs}{pr + ps + rs}')}</p>
  </li>
</ol>
<p>Thus, the expression equivalent to ${f('q')} is <strong>${f('\\frac{prs}{pr + ps + rs}')}</strong>.</p>`,

  // Q20
  '6a9c0e114471c51d35c19250': `<p>To find the value of ${f('\\tan z^\\circ')}:</p>
<ol>
  <li>In right triangle ${f('\\Delta ABC')} with right angle at ${f('A')}, altitude ${f('AD')} is perpendicular to hypotenuse ${f('BC')}.</li>
  <li>In right triangle ${f('\\Delta ABD')}, ${f('\\angle ADB = 90^\\circ')} and ${f('\\angle ABD = w^\\circ')}.</li>
  <li>Because ${f('\\angle BAD + w^\\circ = 90^\\circ')} and ${f('\\angle BAD + z^\\circ = \\angle BAC = 90^\\circ')}, it follows that:
    <p>${f('z^\\circ = w^\\circ')}</p>
  </li>
  <li>We are given ${f('\\cos w^\\circ = \\frac{9}{41}')}. In right triangle ${f('\\Delta ABD')}:
    <p>${f('\\sin w^\\circ = \\sqrt{1 - \\left(\\frac{9}{41}\\right)^2} = \\sqrt{\\frac{1681 - 81}{1681}} = \\sqrt{\\frac{1600}{1681}} = \\frac{40}{41}')}</p>
  </li>
  <li>Calculate ${f('\\tan z^\\circ = \\tan w^\\circ')}:
    <p>${f('\\tan z^\\circ = \\frac{\\sin w^\\circ}{\\cos w^\\circ} = \\frac{40/41}{9/41} = \\frac{40}{9}')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('\\tan z^\\circ')} is <strong>${f('\\frac{40}{9}')}</strong>.</p>`,

  // Q21
  '6a9c0e794471c51d35c192b7': `<p>To find the height of the right square pyramid:</p>
<ol>
  <li>Total surface area = 70,560 and lateral area = 38,160.</li>
  <li>Find the base area ${f('B')}:
    <p>${f('B = \\text{Total Area} - \\text{Lateral Area} = 70{,}560 - 38{,}160 = 32{,}400\\text{ in}^2')}</p>
  </li>
  <li>Since the base is a square, the side length ${f('s')} is:
    <p>${f('s = \\sqrt{32{,}400} = 180\\text{ inches}')}</p>
  </li>
  <li>The 4 congruent triangular lateral faces share the total lateral area:
    <p>${f('\\text{Area of one face} = \\frac{38{,}160}{4} = 9{,}540\\text{ in}^2')}</p>
  </li>
  <li>Use the triangle area formula ${f('\\frac{1}{2} \\times \\text{base} \\times \\text{slant height} = 9{,}540')}:
    <p>${f('\\frac{1}{2}(180)L = 9{,}540 \\implies 90L = 9{,}540 \\implies L = 106\\text{ inches}')}</p>
  </li>
  <li>Use the right triangle relating pyramid height ${f('h')}, half the base ${f('s/2 = 90')}, and slant height ${f('L = 106')}:
    <p>${f('h^2 + 90^2 = 106^2')}</p>
    <p>${f('h^2 = 106^2 - 90^2 = (106 - 90)(106 + 90) = 16 \\times 196 = 3{,}136')}</p>
    <p>${f('h = \\sqrt{3{,}136} = 56\\text{ inches}')}</p>
  </li>
</ol>
<p>Thus, the height of the pyramid is <strong>56</strong> inches.</p>`,

  // Q22
  '6a9c0ea64471c51d35c192ed': `<p>To find the value of constant ${f('c')} such that the equation has exactly one solution:</p>
<ol>
  <li>The given rational equation is:
    <p>${f('\\frac{1}{cx} = \\frac{x}{96} + \\frac{1}{c}')}</p>
  </li>
  <li>Multiply through by ${f('96cx')} (with ${f('x \\ne 0')} and ${f('c \\ne 0')}):
    <p>${f('96 = cx^2 + 96x')}</p>
  </li>
  <li>Rearrange into standard quadratic form:
    <p>${f('cx^2 + 96x - 96 = 0')}</p>
  </li>
  <li>A quadratic equation has exactly one distinct solution when its discriminant equals zero:
    <p>${f('\\Delta = b^2 - 4ac = 96^2 - 4(c)(-96) = 0')}</p>
  </li>
  <li>Factor out 96:
    <p>${f('96(96 + 4c) = 0 \\implies 96 + 4c = 0 \\implies 4c = -96 \\implies c = -24')}</p>
  </li>
  <li>Checking ${f('c = -24')}: ${f('-24x^2 + 96x - 96 = 0 \\implies x^2 - 4x + 4 = (x - 2)^2 = 0 \\implies x = 2')} (valid and non-zero).</li>
</ol>
<p>Thus, the value of ${f('c')} is <strong>-24</strong>.</p>`
};

async function run() {
  console.log('Injecting 22 pedagogical explanations for May 2025 · INT 2 Module 2...\n');
  let count = 0;
  for (const [id, expl] of Object.entries(explanations)) {
    process.stdout.write(`Updating Q ${id} (${++count}/22)... `);
    await updateQuestion(id, { explanation: expl });
    console.log('✅');
  }
  console.log('\n🎉 Successfully injected all 22 M2 explanations!');
}

run().catch(console.error);
