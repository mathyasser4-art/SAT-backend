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
  '6a6ce567709cb26e3aea323d':
    `<p>Parallel lines ${f('r')} and ${f('s')} are intersected by transversal line ${f('t')}.</p>` +
    `<p>The angle measuring ${f('21^\\circ')} at line ${f('s')} and the angle measuring ${f('x^\\circ')} at line ${f('r')} are corresponding angles lying in the same relative position at each intersection.</p>` +
    `<p>Because corresponding angles formed by parallel lines and a transversal are congruent, ${f('x = 21')}.</p>`,

  // Q2
  '6a6ce76d709cb26e3aea3243':
    `<p>Factor the right side of the second equation:</p>` +
    `<p>${f('y = 11x - 66 = 11(x - 6)')}</p>` +
    `<p>Equate the two expressions for ${f('y')}:</p>` +
    `<p>${f('(x - 6)(x + 5) = 11(x - 6)')}</p>` +
    `<p>Subtract ${f('11(x - 6)')} from both sides and factor out ${f('(x - 6)')}:</p>` +
    `<p>${f('(x - 6)[(x + 5) - 11] = 0')}</p>` +
    `<p>${f('(x - 6)(x - 6) = (x - 6)^2 = 0 \\implies x = 6')}</p>` +
    `<p>Substitute ${f('x = 6')} to find ${f('y')}:</p>` +
    `<p>${f('y = 11(6) - 66 = 0')}</p>` +
    `<p>Thus, the solution is ${f('(6, 0)')}.</p>`,

  // Q3
  '6a6d167064c8e41fac128f61':
    `<p>Find the constant ratio ${f('\\frac{y}{x}')} from the given table:</p>` +
    `<p>${f('\\frac{7}{217} = \\frac{1}{31}')}</p>` +
    `<p>${f('\\frac{8}{248} = \\frac{1}{31}')}</p>` +
    `<p>${f('\\frac{9}{279} = \\frac{1}{31}')}</p>` +
    `<p>Because this ratio is constant, the linear equation relating ${f('y')} and ${f('x')} is:</p>` +
    `<p>${f('y = \\frac{1}{31}x')}</p>`,

  // Q4
  '6a6d16b164c8e41fac128f65':
    `<p>Evaluate ${f('m(6)')}:</p>` +
    `<p>${f('m(6) = 3(6) + 6 = 18 + 6 = 24')}</p>` +
    `<p>Evaluate ${f('p(6)')}:</p>` +
    `<p>${f('p(6) = 6 - 6 = 0')}</p>` +
    `<p>Now calculate ${f('2m(6) - p(6)')}:</p>` +
    `<p>${f('2(24) - 0 = 48')}</p>`,

  // Q5
  '6a6d16f564c8e41fac128f69':
    `<p>Using the given circumference ${f('x = 2.75')} inches and breaking strength ${f('y = 9,528.75')} pounds, substitute into ${f('y = 900ax^2')}:</p>` +
    `<p>${f('9,528.75 = 900a(2.75)^2 = 900a(7.5625) = 6,806.25a')}</p>` +
    `<p>Solve for ${f('a')}:</p>` +
    `<p>${f('a = \\frac{9,528.75}{6,806.25} = 1.4')}</p>` +
    `<p>Now estimate the breaking strength for a circumference of ${f('x = 8.50')} inches:</p>` +
    `<p>${f('y = 900(1.4)(8.50)^2 = 1,260(72.25) = 91,035\\text{ pounds}')}</p>`,

  // Q6
  '6a6d174a64c8e41fac128f6d':
    `<p>Each costume requires 4 yards of fabric, so ${f('x')} costumes require a total of ${f('4x')} yards of fabric.</p>` +
    `<p>The equation ${f('y - 4x = 5')} can be rewritten as ${f('y = 4x + 5')}, where ${f('y')} is the total yards of fabric purchased.</p>` +
    `<p>This indicates that the total amount of fabric purchased is 5 yards greater than the amount of fabric used to make the costumes.</p>`,

  // Q7
  '6a6d17a364c8e41fac128f73':
    `<p>Since the point ${f('(k, 2k)')} lies on the graph of ${f('y = f(x)')}, substitute ${f('x = k')} and ${f('y = 2k')} into the function equation:</p>` +
    `<p>${f('2k = 7k - 165')}</p>` +
    `<p>Subtract ${f('7k')} from both sides:</p>` +
    `<p>${f('-5k = -165 \\implies k = 33')}</p>`,

  // Q8
  '6a6d17d664c8e41fac128f77':
    `<p>Subtract 31 from both sides of the given equation:</p>` +
    `<p>${f('(x + k)^2 = 0')}</p>` +
    `<p>Take the square root of both sides:</p>` +
    `<p>${f('x + k = 0 \\implies x = -k')}</p>` +
    `<p>Since there is only one value of ${f('x')} that satisfies this equation, it has exactly one distinct real solution.</p>`,

  // Q9
  '6a6d186464c8e41fac128f7b':
    `<p>Quadrilateral ${f('KLMN')} is a kite with ${f('KL = LM = 3')} and ${f('KN = MN = 27')}.</p>` +
    `<p>The diagonals of a kite are perpendicular, intersecting at point ${f('G')}, and diagonal ${f('LN')} bisects diagonal ${f('KM')} into two equal segments ${f('GK = GM = 1')}.</p>` +
    `<p>In right triangle ${f('\\triangle KGL')}:</p>` +
    `<p>${f('GL = \\sqrt{KL^2 - GK^2} = \\sqrt{3^2 - 1^2} = \\sqrt{8}')}</p>` +
    `<p>In right triangle ${f('\\triangle KGN')}:</p>` +
    `<p>${f('GN = \\sqrt{KN^2 - GK^2} = \\sqrt{27^2 - 1^2} = \\sqrt{729 - 1} = \\sqrt{728}')}</p>` +
    `<p>The total length of diagonal ${f('LN')} is:</p>` +
    `<p>${f('LN = GL + GN = \\sqrt{8} + \\sqrt{728}')}</p>` +
    `<p>Matching with ${f('\\sqrt{p} + \\sqrt{w}')}, we have ${f('p = 8')} and ${f('w = 728')} (or vice versa), so:</p>` +
    `<p>${f('p + w = 8 + 728 = 736')}</p>`,

  // Q10
  '6a6d188864c8e41fac128f7f':
    `<p>When estimating a population proportion with a fixed confidence level, the margin of error is inversely proportional to the square root of the sample size ${f('n')} (${f('\\text{MOE} \\propto \\frac{1}{\\sqrt{n}}')}).</p>` +
    `<p>Therefore, a smaller margin of error corresponds to a larger sample size.</p>` +
    `<p>Group 3 reported the smallest margin of error (8%), which means Group 3 had the largest sample size.</p>`,

  // Q11
  '6a6d196364c8e41fac128f91':
    `<p>Expand both sides of the given equation:</p>` +
    `<p>${f('cx - 6c = -7x - 7k')}</p>` +
    `<p>Collect the ${f('x')} terms on one side:</p>` +
    `<p>${f('(c + 7)x = 6c - 7k')}</p>` +
    `<p>A linear equation ${f('Ax = B')} has exactly one solution if and only if the coefficient of ${f('x')} is nonzero (${f('A \\neq 0')}):</p>` +
    `<p>${f('c + 7 \\neq 0 \\implies c \\neq -7')}</p>` +
    `<p>Therefore, the value of ${f('c')} cannot be ${f('-7')}.</p>`,

  // Q12
  '6a6d19b964c8e41fac128f95':
    `<p>Find the average rate of change of speed during the first 8.00 seconds:</p>` +
    `<p>${f('\\text{Rate}_1 = \\frac{11.0 - 0}{8.00 - 0} = 1.375\\text{ m/s}^2')}</p>` +
    `<p>Find the average rate of change of speed from 8.00 seconds to 14.0 seconds:</p>` +
    `<p>${f('\\text{Rate}_2 = \\frac{23.0 - 11.0}{14.0 - 8.00} = \\frac{12.0}{6.00} = 2.00\\text{ m/s}^2')}</p>` +
    `<p>Find the positive difference between the two average rates of change:</p>` +
    `<p>${f('2.00 - 1.375 = 0.625')}</p>` +
    `<p>Rounded to the nearest hundredth, the positive difference is 0.63.</p>`,

  // Q13
  '6a6d1a3164c8e41fac128f99':
    `<p>Since the graph of ${f('y = f(x) = a^x - b')} passes through ${f('(c, 4)')} and ${f('(2c, 114)')}:</p>` +
    `<p>1. ${f('a^c - b = 4 \\implies a^c = b + 4')}</p>` +
    `<p>2. ${f('a^{2c} - b = 114 \\implies (a^c)^2 = b + 114')}</p>` +
    `<p>Substitute ${f('a^c = b + 4')} into the second equation:</p>` +
    `<p>${f('(b + 4)^2 = b + 114')}</p>` +
    `<p>${f('b^2 + 8b + 16 = b + 114')}</p>` +
    `<p>${f('b^2 + 7b - 98 = 0')}</p>` +
    `<p>Factor the quadratic equation:</p>` +
    `<p>${f('(b - 7)(b + 14) = 0')}</p>` +
    `<p>Since ${f('a > 0')}, ${f('a^c = b + 4')} must be positive. If ${f('b = -14')}, ${f('a^c = -10')}, which is impossible. Thus, ${f('b = 7')} (giving ${f('a^c = 11 > 0')}).</p>`,

  // Q14
  '6a6d1afa14cab24f9785a495':
    `<p>The function ${f('g(x) = f(x + 6)')} represents a horizontal translation of ${f('f(x)')} by 6 units to the left.</p>` +
    `<p>Horizontal shifts alter the location of the vertex but do not change the minimum value of the quadratic function.</p>` +
    `<p>Find the minimum value of ${f('f(x) = 4x^2 + 56x + 197')}. The vertex occurs at:</p>` +
    `<p>${f('x = -\\frac{b}{2a} = -\\frac{56}{2(4)} = -7')}</p>` +
    `<p>Substitute ${f('x = -7')} into ${f('f(x)')}:</p>` +
    `<p>${f('f(-7) = 4(-7)^2 + 56(-7) + 197 = 4(49) - 392 + 197 = 196 - 392 + 197 = 1')}</p>` +
    `<p>Therefore, the minimum value of ${f('g(x)')} is also 1.</p>`,

  // Q15
  '6a6d1b4414cab24f9785a4c4':
    `<p>The center of the circle is ${f('C(-4, -7)')} and the point of tangency is ${f('P(-7, -8)')}.</p>` +
    `<p>Find the slope of the radius connecting the center to the point of tangency:</p>` +
    `<p>${f('m_{\\text{radius}} = \\frac{-8 - (-7)}{-7 - (-4)} = \\frac{-1}{-3} = \\frac{1}{3}')}</p>` +
    `<p>A tangent line to a circle is perpendicular to the radius at the point of tangency. Therefore, the slope of line ${f('k')} is the negative reciprocal of ${f('\\frac{1}{3}')}:</p>` +
    `<p>${f('m_k = -\\frac{1}{1/3} = -3')}</p>`,

  // Q16
  '6a6d1b9b14cab24f9785a4f9':
    `<p>Rearrange the equation by moving all terms to one side:</p>` +
    `<p>${f('(x - k)^2 - (k - 4a)(x - k) = 0')}</p>` +
    `<p>Factor out the common term ${f('(x - k)')}:</p>` +
    `<p>${f('(x - k)[(x - k) - (k - 4a)] = 0')}</p>` +
    `<p>${f('(x - k)(x - 2k + 4a) = 0')}</p>` +
    `<p>The two solutions are ${f('x_1 = k')} and ${f('x_2 = 2k - 4a')}.</p>` +
    `<p>The sum of the solutions is:</p>` +
    `<p>${f('x_1 + x_2 = k + (2k - 4a) = 3k - 4a')}</p>` +
    `<p>We are given that the sum of the solutions is ${f('3k + 37')}:</p>` +
    `<p>${f('3k - 4a = 3k + 37 \\implies -4a = 37 \\implies a = -\\frac{37}{4} = -9.25')}</p>`,

  // Q17
  '6a6d1bc014cab24f9785a519':
    `<p>At the beginning of the year, the savings account had $900.</p>` +
    `<p>Javier deposits $45 at the end of each week. By the end of the 4th week, he makes 4 deposits:</p>` +
    `<p>${f('\\text{Total} = 900 + 4(45) = 900 + 180 = 1,080\\text{ dollars}')}</p>`,

  // Q18
  '6a6d1c2514cab24f9785a56a':
    `<p>Given ${f('y = f(x) = a^x - b')} passes through ${f('(c, 5)')} and ${f('(2c, 137)')}:</p>` +
    `<p>1. ${f('a^c - b = 5 \\implies a^c = b + 5')}</p>` +
    `<p>2. ${f('a^{2c} - b = 137 \\implies (a^c)^2 = b + 137')}</p>` +
    `<p>Substitute ${f('a^c = b + 5')}:</p>` +
    `<p>${f('(b + 5)^2 = b + 137')}</p>` +
    `<p>${f('b^2 + 10b + 25 = b + 137')}</p>` +
    `<p>${f('b^2 + 9b - 112 = 0')}</p>` +
    `<p>Factor the quadratic equation:</p>` +
    `<p>${f('(b - 7)(b + 16) = 0')}</p>` +
    `<p>Since ${f('a > 0')}, ${f('a^c = b + 5')} must be strictly positive. If ${f('b = -16')}, ${f('a^c = -11')}, which has no real solution. Thus, ${f('b = 7')}.</p>`,

  // Q19
  '6a6d1c5214cab24f9785a5aa':
    `<p>An increase of 438% means the mass increased by ${f('4.38k')}.</p>` +
    `<p>Adding this increase to the original mass ${f('k')}:</p>` +
    `<p>${f('k + 4.38k = (1 + 4.38)k = 5.38k\\text{ grams}')}</p>`,

  // Q20
  '6a6d1d2114cab24f9785a68c':
    `<p>The initial balance in the savings account was $900.</p>` +
    `<p>Javier deposits $55 at the end of each week. By the end of the 4th week, 4 deposits have been made:</p>` +
    `<p>${f('\\text{Total} = 900 + 4(55) = 900 + 220 = 1,120\\text{ dollars}')}</p>`,

  // Q21
  '6a6d1d8414cab24f9785a69e':
    `<p>Factor the right-hand side of the second equation:</p>` +
    `<p>${f('y = 12x - 96 = 12(x - 8)')}</p>` +
    `<p>Equate the expressions for ${f('y')}:</p>` +
    `<p>${f('(x - 8)(x + 4) = 12(x - 8)')}</p>` +
    `<p>Subtract ${f('12(x - 8)')} and factor out ${f('(x - 8)')}:</p>` +
    `<p>${f('(x - 8)[(x + 4) - 12] = 0')}</p>` +
    `<p>${f('(x - 8)^2 = 0 \\implies x = 8')}</p>` +
    `<p>Substitute ${f('x = 8')} to find ${f('y')}:</p>` +
    `<p>${f('y = 12(8) - 96 = 0')}</p>` +
    `<p>Thus, the ordered pair is ${f('(8, 0)')}.</p>`,

  // Q22
  '6a6d1dbd14cab24f9785a6a2':
    `<p>Multiply the equation by ${f('-1')} to write it in standard form:</p>` +
    `<p>${f('x^2 - bx + 49 = 0')}</p>` +
    `<p>For this quadratic equation to have no real solutions, the discriminant ${f('\\Delta = b^2 - 4ac')} must be strictly negative:</p>` +
    `<p>${f('(-b)^2 - 4(1)(49) < 0')}</p>` +
    `<p>${f('b^2 - 196 < 0')}</p>` +
    `<p>${f('b^2 < 196 \\implies -14 < b < 14')}</p>` +
    `<p>Since ${f('b')} is an integer, the least possible value is ${f('b = -13')}.</p>`
};

async function run() {
  console.log('Injecting explanations for August 2025 · INT 2 (M2)...');

  const ids = Object.keys(explanations);
  let count = 0;
  for (const id of ids) {
    const res = await updateQuestion(id, { explanation: explanations[id] });
    count++;
    console.log(`[${count}/${ids.length}] Updated explanation for ${id}: ${res.message === 'success' ? '✅' : JSON.stringify(res)}`);
  }

  console.log('\n🎉 Finished updating all 22 explanations for August 2025 · INT 2 (M2)!');
}

run().catch(console.error);
