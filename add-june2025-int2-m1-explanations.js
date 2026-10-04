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
  '6a6d4cc114cab24f9785a82f':
    `<p>Lines ${f('r')} and ${f('s')} are parallel lines intersected by transversal line ${f('n')}.</p>` +
    `<p>The angle measuring ${f('164^\\circ')} and the angle measuring ${f('x^\\circ')} are corresponding angles lying in the same relative position at each intersection.</p>` +
    `<p>Since corresponding angles are equal when two parallel lines are cut by a transversal, ${f('x = 164')}.</p>`,

  // Q2
  '6a6d4d8214cab24f9785a841':
    `<p>The airplane's cruising speed ${f('s')} varied between 175 miles per hour and 195 miles per hour (inclusive).</p>` +
    `<p>This range is represented by the compound inequality:</p>` +
    `<p>${f('175 \\le s \\le 195')}</p>`,

  // Q3
  '6a6d4dd614cab24f9785a847':
    `<p>We are given that ${f('5x = 9')}.</p>` +
    `<p>Notice that ${f('20x = 4(5x)')}.</p>` +
    `<p>Substitute ${f('5x = 9')}:</p>` +
    `<p>${f('20x = 4(9) = 36')}</p>`,

  // Q4
  '6a6d4e0214cab24f9785a84b':
    `<p>Given expression: ${f('(x^3 + 9x^2 - 8x) + 5(x^2 + 8)')}.</p>` +
    `<p>Distribute 5 through the second term:</p>` +
    `<p>${f('5(x^2 + 8) = 5x^2 + 40')}</p>` +
    `<p>Combine with the first polynomial:</p>` +
    `<p>${f('(x^3 + 9x^2 - 8x) + (5x^2 + 40) = x^3 + (9x^2 + 5x^2) - 8x + 40')}</p>` +
    `<p>${f('= x^3 + 14x^2 - 8x + 40')}</p>`,

  // Q5
  '6a6d56bb14cab24f9785a89a':
    `<p>The function is defined as ${f('f(x) = x^3 + 9')}.</p>` +
    `<p>Substitute ${f('x = 2')}:</p>` +
    `<p>${f('f(2) = 2^3 + 9 = 8 + 9 = 17')}</p>`,

  // Q6
  '6a6d570014cab24f9785a89e':
    `<p>The function is defined by ${f('g(x) = \\frac{x}{2}')}.</p>` +
    `<p>Set ${f('g(x) = 620')}:</p>` +
    `<p>${f('\\frac{x}{2} = 620 \\implies x = 620 \\times 2 = 1240')}</p>`,

  // Q7
  '6a6d573014cab24f9785a8a2':
    `<p>Examining the scatterplot:</p>` +
    `<p>The data points show a downward linear trend (negative slope) starting with a y-intercept around ${f('(0, 8.7)')}.</p>` +
    `<p>As ${f('x')} increases from 0 to 10, ${f('y')} decreases from around 8.7 down to roughly 0.7, giving a slope of approximately ${f('\\frac{0.7 - 8.7}{10 - 0} = -0.8')}.</p>` +
    `<p>Therefore, the most appropriate linear model is ${f('y = 8.7 - 0.8x')}.</p>`,

  // Q8
  '6a6d577914cab24f9785a8a8':
    `<p>The given equation is ${f('3x - 2y = -18')}.</p>` +
    `<p>Solve for ${f('y')} in terms of ${f('x')}:</p>` +
    `<p>${f('-2y = -3x - 18 \\implies y = 1.5x + 9')}</p>` +
    `<p>Now evaluate for the values of ${f('x')}:</p>` +
    `<ul>` +
    `<li>For ${f('x = 0')}: ${f('y = 1.5(0) + 9 = 9')}</li>` +
    `<li>For ${f('x = 2')}: ${f('y = 1.5(2) + 9 = 12')}</li>` +
    `<li>For ${f('x = 4')}: ${f('y = 1.5(4) + 9 = 15')}</li>` +
    `</ul>` +
    `<p>This matches the table with pairs ${f('(0, 9)')}, ${f('(2, 12)')}, and ${f('(4, 15)')}.</p>`,

  // Q9
  '6a6d579014cab24f9785a8ac':
    `<p>The total volume of the mixture is 41 mL, which is the sum of the volumes of water and isopropanol:</p>` +
    `<p>${f('\\text{Volume of water} + \\text{Volume of isopropanol} = 41')}</p>` +
    `<p>Given that the volume of isopropanol is 10 mL:</p>` +
    `<p>${f('\\text{Volume of water} + 10 = 41 \\implies \\text{Volume of water} = 41 - 10 = 31\\text{ mL}')}.</p>`,

  // Q10
  '6a6d57b014cab24f9785a8b0':
    `<p>Wholesale price = $4.00.</p>` +
    `<p>The retail price is 280% of the wholesale price:</p>` +
    `<p>${f('\\text{Retail price} = 4.00 \\times 2.80 = 11.20\\text{ dollars}')}</p>` +
    `<p>The discounted price is 80% off the retail price, meaning the customer pays ${f('100\\% - 80\\% = 20\\%')} of the retail price:</p>` +
    `<p>${f('\\text{Discounted price} = 11.20 \\times 0.20 = 2.24\\text{ dollars}')} (or ${f('\\frac{56}{25}')}).</p>`,

  // Q11
  '6a6d57ef14cab24f9785a8b6':
    `<p>We are given the system:</p>` +
    `<p>${f('y = -\\frac{1}{4}x')} and ${f('y = \\frac{1}{6}x')}</p>` +
    `<p>Equating the two expressions for ${f('y')}:</p>` +
    `<p>${f('-\\frac{1}{4}x = \\frac{1}{6}x')}</p>` +
    `<p>${f('\\frac{1}{6}x + \\frac{1}{4}x = 0 \\implies \\frac{5}{12}x = 0 \\implies x = 0')}.</p>`,

  // Q12
  '6a6d581714cab24f9785a8ba':
    `<p>Given the equation: ${f('PC = N(18 - C)')}.</p>` +
    `<p>Distribute ${f('N')} on the right side:</p>` +
    `<p>${f('PC = 18N - NC')}</p>` +
    `<p>Add ${f('NC')} to both sides to group terms containing ${f('C')}:</p>` +
    `<p>${f('PC + NC = 18N')}</p>` +
    `<p>Factor out ${f('C')}:</p>` +
    `<p>${f('C(P + N) = 18N')}</p>` +
    `<p>Divide both sides by ${f('N + P')}:</p>` +
    `<p>${f('C = \\frac{18N}{N + P}')}.</p>`,

  // Q13
  '6a6d584e14cab24f9785a8be':
    `<p>In January 2018 (${f('m = 0')}), the number of customers enrolled was 200.</p>` +
    `<p>Each month, the number of customers increases by 4%, which corresponds to a growth factor of ${f('1 + 0.04 = 1.04')}.</p>` +
    `<p>Therefore, after ${f('m')} months, the total number of customers enrolled is given by:</p>` +
    `<p>${f('c = 200(1.04)^m')}.</p>`,

  // Q14
  '6a6d5f2f14cab24f9785a8c4':
    `<p>The bacteria population function is ${f('f(t) = 8{,}000(2)^{\\frac{t}{300}')}.</p>` +
    `<p>The initial population is ${f('f(0) = 8{,}000')}.</p>` +
    `<p>For the population to double, the factor ${f('2^{\\frac{t}{300}}')} must equal ${f('2^1')}:</p>` +
    `<p>${f('\\frac{t}{300} = 1 \\implies t = 300\\text{ minutes}')}.</p>`,

  // Q15
  '6a6d5f5d14cab24f9785a8c8':
    `<p>A system of linear equations in two variables has infinitely many solutions if and only if both equations represent the same identical line.</p>` +
    `<p>The first equation is ${f('y = \\frac{2}{9}x + 8')}, which is in slope-intercept form with slope ${f('m = \\frac{2}{9}')}.</p>` +
    `<p>Therefore, the second equation must also have a slope of ${f('\\frac{2}{9}')}.</p>`,

  // Q16
  '6a6d5f8b14cab24f9785a8cc':
    `<p>Given equation: ${f('3x^2 - 6x - 30 = 0')}.</p>` +
    `<p>Add 30 to both sides:</p>` +
    `<p>${f('3x^2 - 6x = 30')}</p>` +
    `<p>Factor out 3 from the left side:</p>` +
    `<p>${f('3(x^2 - 2x) = 30')}</p>` +
    `<p>Divide both sides by 3:</p>` +
    `<p>${f('x^2 - 2x = 10')}.</p>`,

  // Q17
  '6a6d5fd714cab24f9785a8d0':
    `<p>The function is ${f('f(x) = (x - 4)(x - 11)(x + k)')}.</p>` +
    `<p>Since the graph passes through ${f('(-2, 0)')}, we have ${f('f(-2) = 0')}:</p>` +
    `<p>${f('(-2 - 4)(-2 - 11)(-2 + k) = 0')}</p>` +
    `<p>${f('(-6)(-13)(-2 + k) = 0 \\implies 78(-2 + k) = 0 \\implies k = 2')}.</p>` +
    `<p>Now find ${f('f(0)')}:</p>` +
    `<p>${f('f(0) = (0 - 4)(0 - 11)(0 + 2) = (-4)(-11)(2) = 88')}.</p>`,

  // Q18
  '6a6d603714cab24f9785a8d6':
    `<p>Line ${f('k')} passes through the points ${f('(0, 3)')} and ${f('(4, 0)')}.</p>` +
    `<p>The slope of line ${f('k')} is:</p>` +
    `<p>${f('m_k = \\frac{0 - 3}{4 - 0} = -\\frac{3}{4}')}</p>` +
    `<p>Since line ${f('j')} is perpendicular to line ${f('k')}, its slope is the negative reciprocal:</p>` +
    `<p>${f('m_j = -\\frac{1}{m_k} = \\frac{4}{3}')}</p>` +
    `<p>Using the point-slope form with ${f('(-15, -28)')}:</p>` +
    `<p>${f('y - (-28) = \\frac{4}{3}(x - (-15))')}</p>` +
    `<p>${f('y + 28 = \\frac{4}{3}x + 20 \\implies y = \\frac{4}{3}x - 8')}.</p>`,

  // Q19
  '6a6d609114cab24f9785a8da':
    `<p>In right triangle ${f('ABC')} with acute angles ${f('A')} and ${f('B')}, the tangent of angle ${f('B')} is the ratio of the opposite side to the adjacent side:</p>` +
    `<p>${f('\\tan B = \\frac{AC}{BC}')}</p>` +
    `<p>We are given ${f('\\tan B = \\frac{1}{7}')} and ${f('AC = 23.2')}:</p>` +
    `<p>${f('\\frac{1}{7} = \\frac{23.2}{BC} \\implies BC = 7 \\times 23.2 = 162.4')}.</p>`,

  // Q20
  '6a6d60ae14cab24f9785a8de':
    `<p>Let the original banner have length ${f('L')} and width ${f('W')}. The original area is:</p>` +
    `<p>${f('A = LW = 3{,}500\\text{ sq in}')}</p>` +
    `<p>When both the length and width are increased by 40%, the new dimensions are ${f('1.40L')} and ${f('1.40W')}.</p>` +
    `<p>The area of the copy is:</p>` +
    `<p>${f('A_{\\text{new}} = (1.40L)(1.40W) = 1.40^2(LW) = 1.96 \\times 3{,}500 = 6{,}860\\text{ sq in}')}.</p>`,

  // Q21
  '6a6d60ce14cab24f9785a8e2':
    `<p>The given function is in vertex form: ${f('f(x) = (x - 1)^2 + 7')}.</p>` +
    `<p>For all real numbers ${f('x')}, the squared term ${f('(x - 1)^2 \\ge 0')}.</p>` +
    `<p>The minimum value of ${f('(x - 1)^2')} is 0, which occurs when ${f('x = 1')}.</p>` +
    `<p>Therefore, the minimum value of ${f('f(x)')} is ${f('0 + 7 = 7')}.</p>`,

  // Q22
  '6a6d611914cab24f9785a8e6':
    `<p>Point ${f('G(0, 0)')} is the center of the unit circle, and point ${f('F(1, 0)')} lies on the positive x-axis (corresponding to standard angle 0 radians).</p>` +
    `<p>Point ${f('H(-1, y)')} lies on the unit circle ${f('x^2 + y^2 = 1')}. Substituting ${f('x = -1')}:</p>` +
    `<p>${f('(-1)^2 + y^2 = 1 \\implies 1 + y^2 = 1 \\implies y = 0')}.</p>` +
    `<p>Thus, ${f('H')} is located at ${f('(-1, 0)')}, which lies on the negative x-axis.</p>` +
    `<p>Any ray from the origin to ${f('(-1, 0)')} forms an angle with the positive x-axis that is an odd integer multiple of ${f('\\pi')} radians, such as ${f('\\pi, 3\\pi, 5\\pi, 7\\pi, 9\\pi, 11\\pi, \\dots')}.</p>` +
    `<p>Among the given choices, ${f('11\\pi')} is an odd multiple of ${f('\\pi')}, so it is the correct answer.</p>`
};

async function main() {
  console.log('Injecting June 2025 · INT 2 M1 Explanations...');
  for (const [id, expl] of Object.entries(explanations)) {
    const res = await updateQuestion(id, { explanation: expl });
    console.log(`Updated ${id}:`, res.message || res);
  }
  console.log('Finished June 2025 · INT 2 M1!');
}

main().catch(console.error);
