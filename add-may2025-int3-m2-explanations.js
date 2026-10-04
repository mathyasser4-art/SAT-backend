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
  '6aa0e0fddf63ca493d479922': `<p>To find the total cost of leasing the car for a monthly payment of $300:</p>
<ol>
  <li>The lease function is given by:
    <p>${f('f(x) = 24x + 1{,}000')}</p>
  </li>
  <li>Substitute ${f('x = 300')}:
    <p>${f('f(300) = 24(300) + 1{,}000')}</p>
  </li>
  <li>Calculate:
    <p>${f('f(300) = 7{,}200 + 1{,}000 = 8{,}200')}</p>
  </li>
</ol>
<p>Thus, the total cost to lease the car is <strong>8,200</strong> dollars.</p>`,

  // Q2
  '6aa0e15fdf63ca493d479928': `<p>To determine the condition sufficient to prove that lines ${f('j')} and ${f('k')} are parallel:</p>
<ol>
  <li>Line ${f('l')} is a transversal intersecting lines ${f('j')} and ${f('k')}.</li>
  <li>The angle labeled ${f('w^\\circ')} and the angle measuring ${f('54^\\circ')} lie in the same relative position (upper-right) at each intersection, making them <strong>corresponding angles</strong>.</li>
  <li>If two corresponding angles are equal, the two lines are parallel.</li>
  <li>Therefore, knowing that ${f('w = 54')} is sufficient to prove that lines ${f('j')} and ${f('k')} are parallel.</li>
</ol>
<p>Thus, the sufficient information is <strong>${f('w = 54')}</strong>.</p>`,

  // Q3
  '6aa0e1c5df63ca493d479933': `<p>To find the value of ${f('r')} such that the equation has no solution:</p>
<ol>
  <li>The equation is:
    <p>${f('5x + 3 = rx + 7')}</p>
  </li>
  <li>A linear equation has no solution when the coefficients of ${f('x')} on both sides are equal while the constants are unequal.</li>
  <li>Setting the coefficients equal gives:
    <p>${f('r = 5')}</p>
  </li>
  <li>When ${f('r = 5')}, the equation becomes ${f('5x + 3 = 5x + 7 \\implies 3 = 7')}, which is impossible.</li>
</ol>
<p>Thus, the value of ${f('r')} is <strong>5</strong>.</p>`,

  // Q4
  '6aa0e230df63ca493d479939': `<p>To solve for ${f('2x + 9')}:</p>
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
  <li>Since ${f('u = 2x + 9')}, the value is 37.</li>
</ol>
<p>Thus, the value of ${f('2x + 9')} is <strong>37</strong>.</p>`,

  // Q5
  '6aa0e289df63ca493d47993f': `<p>To find the value of ${f('n')}:</p>
<ol>
  <li>Write 350% as a decimal:
    <p>${f('350\\% = 3.5')}</p>
  </li>
  <li>Set up the equation:
    <p>${f('3.5n = 35')}</p>
  </li>
  <li>Divide by 3.5:
    <p>${f('n = \\frac{35}{3.5} = 10')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('n')} is <strong>10</strong>.</p>`,

  // Q6
  '6aa0e2e8df63ca493d479945': `<p>To find the linear equation defining ${f('h(x)')}:</p>
<ol>
  <li>From the table, the function contains ${f('(4, 17)')} and ${f('(6, 23)')}.</li>
  <li>Find the slope:
    <p>${f('m = \\frac{23 - 17}{6 - 4} = \\frac{6}{2} = 3')}</p>
  </li>
  <li>Find the y-intercept using ${f('(4, 17)')}:
    <p>${f('17 = 3(4) + b \\implies 17 = 12 + b \\implies b = 5')}</p>
  </li>
  <li>Write the equation:
    <p>${f('h(x) = 3x + 5')}</p>
  </li>
</ol>
<p>Thus, the equation is <strong>${f('h(x) = 3x + 5')}</strong>.</p>`,

  // Q7
  '6aa0e32fdf63ca493d47994b': `<p>To find a possible value of ${f('x')} where the graphs intersect:</p>
<ol>
  <li>Set the equations equal:
    <p>${f('x^2 + 17x + 4 = x + 4')}</p>
  </li>
  <li>Subtract ${f('x + 4')} from both sides:
    <p>${f('x^2 + 16x = 0')}</p>
  </li>
  <li>Factor:
    <p>${f('x(x + 16) = 0')}</p>
    <p>${f('x = 0')} or ${f('x = -16')}</p>
  </li>
</ol>
<p>Thus, a possible value of ${f('x')} is <strong>-16</strong>.</p>`,

  // Q8
  '6aa0e34cdf63ca493d479951': `<p>To find the value of ${f('x')}:</p>
<ol>
  <li>The total length is 108 inches:
    <p>${f('x + y = 108')}</p>
  </li>
  <li>We are given:
    <p>${f('x = 4y + 8')}</p>
  </li>
  <li>Substitute into the sum:
    <p>${f('(4y + 8) + y = 108 \\implies 5y = 100 \\implies y = 20')}</p>
  </li>
  <li>Solve for ${f('x')}:
    <p>${f('x = 4(20) + 8 = 88')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('x')} is <strong>88</strong>.</p>`,

  // Q9
  '6aa0e3eedf63ca493d479957': `<p>To represent the shrub planting constraints:</p>
<ol>
  <li>"No more than 244 total shrubs" translates to:
    <p>${f('h + w \\le 244')}</p>
  </li>
  <li>"Number of hydrangeas planted will be at most three times the number of winter hazels" translates to:
    <p>${f('h \\le 3w')}</p>
  </li>
</ol>
<p>Thus, the correct system is <strong>${f('h + w \\le 244')} and ${f('h \\le 3w')}</strong>.</p>`,

  // Q10
  '6aa0e4a7df63ca493d479969': `<p>To find the mass of the cube of wood:</p>
<ol>
  <li>The volume of a cube with edge length ${f('s = 0.7\\text{ m}')} is:
    <p>${f('V = s^3 = (0.7)^3 = 0.343\\text{ m}^3')}</p>
  </li>
  <li>Mass equals density times volume:
    <p>${f('\\text{Mass} = 770 \\times 0.343 = 264.11\\text{ kg}')}</p>
  </li>
  <li>Rounding to the nearest whole number gives 264.</li>
</ol>
<p>Thus, the mass is <strong>264</strong> kilograms.</p>`,

  // Q11
  '6aa0e8c7df63ca493d479976': `<p>To find the point that satisfies the system of inequalities:</p>
<ol>
  <li>The inequalities are ${f('y \\le x + 3')} and ${f('y \\ge -3x - 7')}.</li>
  <li>Test point ${f('(14, 0)')}:
    <ul>
      <li>${f('0 \\le 14 + 3 = 17')} (True)</li>
      <li>${f('0 \\ge -3(14) - 7 = -49')} (True)</li>
    </ul>
    Both inequalities hold true.
  </li>
  <li>Testing ${f('(0, -14)')}: ${f('-14 \\ge -7')} is False.</li>
</ol>
<p>Thus, the solution point is <strong>(14, 0)</strong>.</p>`,

  // Q12
  '6aa0e92cdf63ca493d47997c': `<p>To find the greatest solution to ${f('3x^2 - 5x - 5 = 0')}:</p>
<ol>
  <li>Use the quadratic formula:
    <p>${f('x = \\frac{-(-5) \\pm \\sqrt{(-5)^2 - 4(3)(-5)}}{2(3)} = \\frac{5 \\pm \\sqrt{25 + 60}}{6} = \\frac{5 \\pm \\sqrt{85}}{6}')}</p>
  </li>
  <li>The greatest solution is:
    <p>${f('x = \\frac{5}{6} + \\frac{\\sqrt{85}}{6}')}</p>
  </li>
</ol>
<p>Thus, the greatest solution is <strong>${f('\\frac{5}{6} + \\frac{\\sqrt{85}}{6}')}</strong>.</p>`,

  // Q13
  '6aa0e988df63ca493d479982': `<p>To find the positive difference in sea ice area between 1991 and 1992:</p>
<ol>
  <li>The model is:
    <p>${f('f(x) = -0.00384x^2 + 15.236x - 15{,}103')}</p>
  </li>
  <li>Compute ${f('f(1992) - f(1991)')}:
    <p>${f('f(1992) - f(1991) = -0.00384(1992^2 - 1991^2) + 15.236(1)')}</p>
  </li>
  <li>Notice that ${f('1992^2 - 1991^2 = 1992 + 1991 = 3{,}983')}:
    <p>${f('-0.00384(3{,}983) + 15.236 = -15.29472 + 15.236 = -0.05872')}</p>
  </li>
  <li>The positive difference is:
    <p>${f('|-0.05872| = 0.05872\\text{ million km}^2')}</p>
    Rounding to the nearest thousandth gives <strong>0.059</strong>.
  </li>
</ol>
<p>Thus, the positive difference is <strong>0.059</strong>.</p>`,

  // Q14
  '6aa0e9c8df63ca493d479988': `<p>To find the y-intercept of ${f('y = \\left(\\frac{8}{13}\\right)^{x+1}')}:</p>
<ol>
  <li>Set ${f('x = 0')}:
    <p>${f('y = \\left(\\frac{8}{13}\\right)^{0+1} = \\frac{8}{13}')}</p>
  </li>
  <li>The coordinates are ${f('\\left(0, \\frac{8}{13}\\right)')}.</li>
</ol>
<p>Thus, the y-intercept is <strong>${f('\\left(0, \\frac{8}{13}\\right)')}</strong>.</p>`,

  // Q15
  '6aa0ea09df63ca493d47998e': `<p>To write the quadratic function in a form displaying its minimum value:</p>
<ol>
  <li>The quadratic function is ${f('f(x) = x^2 - 4x - 320')}.</li>
  <li>Complete the square to find vertex form:
    <p>${f('f(x) = (x^2 - 4x + 4) - 4 - 320 = (x - 2)^2 - 324 = (x - 2)^2 + (-324)')}</p>
  </li>
  <li>In vertex form, the minimum value -324 is displayed directly as a constant term.</li>
</ol>
<p>Thus, the correct form is <strong>${f('f(x) = (x - 2)^2 + (-324)')}</strong>.</p>`,

  // Q16
  '6aa0ea61df63ca493d479994': `<p>To find the value of ${f('k')}:</p>
<ol>
  <li>Line ${f('s')} is ${f('6x + 2y = 0 \\implies y = -3x')}, so its slope is ${f('m_s = -3')}.</li>
  <li>The perpendicular line ${f('t')} has slope:
    <p>${f('m_t = -\\frac{1}{-3} = \\frac{1}{3}')}</p>
  </li>
  <li>Using points ${f('(7, 0)')} and ${f('\\left(k, \\frac{4}{3}\\right)')}:
    <p>${f('\\frac{\\frac{4}{3} - 0}{k - 7} = \\frac{1}{3} \\implies \\frac{4}{k - 7} = 1 \\implies k - 7 = 4 \\implies k = 11')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('k')} is <strong>11</strong>.</p>`,

  // Q17
  '6aa0eaa8df63ca493d47999a': `<p>To find the value of ${f('a')} in ${f('g(x) = x^3 + ax^2 + bx + c')}:</p>
<ol>
  <li>The zeros are -2, -7, and 6.</li>
  <li>By Vieta's formulas, the coefficient of ${f('x^2')} is the negative sum of all zeros:
    <p>${f('a = - ((-2) + (-7) + 6) = -(-3) = 3')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('a')} is <strong>3</strong>.</p>`,

  // Q18
  '6aa0ead3df63ca493d4799a0': `<p>To find the total charge for ${f('x > 3')} hours:</p>
<ol>
  <li>The base rate for the first 3 hours is $216.</li>
  <li>The number of additional hours is ${f('x - 3')}, each costing $60:
    <p>${f('y = 216 + 60(x - 3)')}</p>
  </li>
  <li>Simplify:
    <p>${f('y = 216 + 60x - 180 = 60x + 36')}</p>
  </li>
</ol>
<p>Thus, the equation is <strong>y = 60x + 36</strong>.</p>`,

  // Q19
  '6aa0eb0bdf63ca493d4799a6': `<p>To solve for ${f('q')}:</p>
<ol>
  <li>The equation is:
    <p>${f('\\frac{46}{p} = \\frac{46}{q} - \\frac{46}{r} - \\frac{46}{s}')}</p>
  </li>
  <li>Divide by 46:
    <p>${f('\\frac{1}{p} = \\frac{1}{q} - \\frac{1}{r} - \\frac{1}{s}')}</p>
  </li>
  <li>Isolate ${f('\\frac{1}{q}')}:
    <p>${f('\\frac{1}{q} = \\frac{1}{p} + \\frac{1}{r} + \\frac{1}{s} = \\frac{rs + ps + pr}{prs}')}</p>
  </li>
  <li>Take the reciprocal:
    <p>${f('q = \\frac{prs}{pr + ps + rs}')}</p>
  </li>
</ol>
<p>Thus, the expression equivalent to ${f('q')} is <strong>${f('\\frac{prs}{pr + ps + rs}')}</strong>.</p>`,

  // Q20
  '6aa0ebcedf63ca493d4799ac': `<p>To find the value of ${f('\\tan z')}:</p>
<ol>
  <li>We are given ${f('\\cos z = \\frac{9}{41}')}.</li>
  <li>Use the Pythagorean identity ${f('\\sin^2 z + \\cos^2 z = 1')}:
    <p>${f('\\sin z = \\sqrt{1 - \\left(\\frac{9}{41}\\right)^2} = \\sqrt{\\frac{1681 - 81}{1681}} = \\sqrt{\\frac{1600}{1681}} = \\frac{40}{41}')}</p>
  </li>
  <li>Calculate ${f('\\tan z')}:
    <p>${f('\\tan z = \\frac{\\sin z}{\\cos z} = \\frac{40/41}{9/41} = \\frac{40}{9}')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('\\tan z')} is <strong>${f('\\frac{40}{9}')}</strong>.</p>`,

  // Q21
  '6aa0ebeadf63ca493d4799b2': `<p>To find the height of the right square pyramid:</p>
<ol>
  <li>Total surface area = 70,560 and lateral area = 38,160.</li>
  <li>Base area:
    <p>${f('B = 70{,}560 - 38{,}160 = 32{,}400\\text{ in}^2')}</p>
  </li>
  <li>Base edge length:
    <p>${f('s = \\sqrt{32{,}400} = 180\\text{ inches}')}</p>
  </li>
  <li>Area of each of the 4 lateral triangles:
    <p>${f('\\frac{38{,}160}{4} = 9{,}540\\text{ in}^2')}</p>
    <p>${f('\\frac{1}{2}(180)L = 9{,}540 \\implies 90L = 9{,}540 \\implies L = 106\\text{ inches}')}</p>
  </li>
  <li>Find height ${f('h')}:
    <p>${f('h = \\sqrt{L^2 - (s/2)^2} = \\sqrt{106^2 - 90^2} = \\sqrt{11{,}236 - 8{,}100} = \\sqrt{3{,}136} = 56\\text{ inches}')}</p>
  </li>
</ol>
<p>Thus, the height of the pyramid is <strong>56</strong> inches.</p>`,

  // Q22
  '6aa0ec05df63ca493d4799b8': `<p>To find the value of ${f('A')}:</p>
<ol>
  <li>684 is ${f('A\\%')} greater than 9.</li>
  <li>Calculate the absolute increase:
    <p>${f('684 - 9 = 675')}</p>
  </li>
  <li>Find the percentage increase relative to 9:
    <p>${f('A\\% = \\frac{675}{9} = 75 = 7{,}500\\%')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('A')} is <strong>7500</strong>.</p>`
};

async function run() {
  console.log('Injecting 22 pedagogical explanations for May 2025 · INT 3 Module 2...\n');
  let count = 0;
  for (const [id, expl] of Object.entries(explanations)) {
    process.stdout.write(`Updating Q ${id} (${++count}/22)... `);
    await updateQuestion(id, { explanation: expl });
    console.log('✅');
  }
  console.log('\n🎉 Successfully injected all 22 M2 explanations!');
}

run().catch(console.error);
