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
  '6a6d3f5514cab24f9785a78a':
    `<p>A decreasing exponential function has the form ${f('f(x) = a \\cdot b^x')} where ${f('a > 0')} and ${f('0 < b < 1')}.</p>` +
    `<p>Its graph decreases from left to right at a diminishing rate and approaches a horizontal asymptote (the ${f('x')}-axis) as ${f('x \\to \\infty')}, creating a characteristic upward curve (convex).</p>` +
    `<p>Graph A correctly displays this decreasing exponential behavior.</p>`,

  // Q2
  '6a6d3f7d14cab24f9785a78e':
    `<p>The ${f('y')}-intercept of a graph is found by setting ${f('x = 0')}:</p>` +
    `<p>${f('y = 6(0)^2 + 4(0) + 3 = 3')}</p>` +
    `<p>Therefore, the ${f('y')}-intercept is ${f('(0, 3)')}.</p>`,

  // Q3
  '6a6d3fab14cab24f9785a792':
    `<p>Set up the equation according to the problem description:</p>` +
    `<p>${f('x(x - 7) = 18')}</p>` +
    `<p>${f('x^2 - 7x - 18 = 0')}</p>` +
    `<p>Factor the quadratic equation:</p>` +
    `<p>${f('(x - 9)(x + 2) = 0')}</p>` +
    `<p>Since ${f('x')} must be positive, ${f('x = 9')}.</p>`,

  // Q4
  '6a6d3ff214cab24f9785a798':
    `<p>A cylinder with a diameter of 6 inches has a radius of ${f('r = \\frac{6}{2} = 3')} inches.</p>` +
    `<p>The volume of a cylinder is given by ${f('V = \\pi r^2 h')}:</p>` +
    `<p>${f('V = \\pi (3^2)(21) = \\pi(9)(21) = 189\\pi\\text{ cubic inches}')}</p>`,

  // Q5
  '6a6d407414cab24f9785a7a0':
    `<p>In triangle ${f('PQR')}, the side ${f('\\overline{QR}')} is extended to point ${f('S')}, forming the exterior angle ${f('\\angle PRS = 166^\\circ')}.</p>` +
    `<p>By the exterior angle theorem, the measure of an exterior angle of a triangle is equal to the sum of the measures of its two remote interior angles:</p>` +
    `<p>${f('\\angle PRS = \\angle QPR + \\angle PQR')}</p>` +
    `<p>${f('166^\\circ = \\angle QPR + 132^\\circ')}</p>` +
    `<p>${f('\\angle QPR = 166^\\circ - 132^\\circ = 34^\\circ')}</p>`,

  // Q6
  '6a6d40f014cab24f9785a7ac':
    `<p>The ${f('y')}-intercept of the function ${f('f(x) = -9x + 54')} occurs at ${f('x = 0')}:</p>` +
    `<p>${f('f(0) = -9(0) + 54 = 54')}</p>` +
    `<p>In this context, ${f('x = 0')} represents the state before any candles were made. Therefore, the ${f('y')}-intercept indicates that Eli had approximately 54 ounces of wax when he began making candles.</p>`,

  // Q7
  '6a6d413514cab24f9785a7b0':
    `<p>From the graph, the line intersects the axes at ${f('(80, 0)')} on the ${f('x')}-axis (Company A) and ${f('(0, 45)')} on the ${f('y')}-axis (Company B).</p>` +
    `<p>Test the intercepts in ${f('9x + 16y = 720')}:</p>` +
    `<p>1. At ${f('(80, 0)')}: ${f('9(80) + 16(0) = 720 + 0 = 720')} (True)</p>` +
    `<p>2. At ${f('(0, 45)')}: ${f('9(0) + 16(45) = 0 + 720 = 720')} (True)</p>` +
    `<p>Thus, ${f('9x + 16y = 720')} correctly represents the relationship.</p>`,

  // Q8
  '6a6d419414cab24f9785a7b4':
    `<p>Start with the given equation:</p>` +
    `<p>${f('ak = \\frac{b}{12}(8 + m)')}</p>` +
    `<p>Multiply both sides by 12:</p>` +
    `<p>${f('12ak = b(8 + m)')}</p>` +
    `<p>Divide both sides by ${f('b')}:</p>` +
    `<p>${f('\\frac{12ak}{b} = 8 + m')}</p>` +
    `<p>Subtract 8 from both sides:</p>` +
    `<p>${f('m = \\frac{12ak}{b} - 8')}</p>`,

  // Q9
  '6a6d41cd14cab24f9785a7ba':
    `<p>Set ${f('g(x) = 10,000')} and express 10,000 as a power of 10:</p>` +
    `<p>${f('10^{4x - 2} = 10^4')}</p>` +
    `<p>Since the bases are identical, equate the exponents:</p>` +
    `<p>${f('4x - 2 = 4')}</p>` +
    `<p>${f('4x = 6 \\implies x = \\frac{6}{4} = \\frac{3}{2}')}</p>`,

  // Q10
  '6a6d438714cab24f9785a7c6':
    `<p>Rewrite the second equation by factoring out ${f('\\frac{x}{y}')}:</p>` +
    `<p>${f('\\frac{2x}{ty} = \\frac{2}{t} \\left(\\frac{x}{y}\\right) = 18')}</p>` +
    `<p>Substitute ${f('\\frac{x}{y} = 3')}:</p>` +
    `<p>${f('\\frac{2}{t}(3) = 18')}</p>` +
    `<p>${f('\\frac{6}{t} = 18 \\implies 18t = 6 \\implies t = \\frac{6}{18} = \\frac{1}{3}')}</p>`,

  // Q11
  '6a6d43ce14cab24f9785a7ca':
    `<p>The total length of the two parts is 53 inches:</p>` +
    `<p>${f('x + y = 53')}</p>` +
    `<p>We are given that ${f('x = 2y + 8')}, which gives ${f('y = \\frac{x - 8}{2}')}.</p>` +
    `<p>Substitute this expression for ${f('y')} into the total length equation:</p>` +
    `<p>${f('x + \\frac{x - 8}{2} = 53')}</p>` +
    `<p>Multiply by 2:</p>` +
    `<p>${f('2x + x - 8 = 106')}</p>` +
    `<p>${f('3x = 114 \\implies x = 38')}</p>`,

  // Q12
  '6a6d474714cab24f9785a7d0':
    `<p>A linear equation has no solution if the variable terms cancel out while leaving an untrue statement.</p>` +
    `<p>In ${f('-13x - \\frac{1}{9} = -13x + \\frac{1}{9}')}, adding ${f('13x')} to both sides yields:</p>` +
    `<p>${f('-\\frac{1}{9} = \\frac{1}{9}')}</p>` +
    `<p>Since this statement is false for all values of ${f('x')}, the equation has no solution.</p>`,

  // Q13
  '6a6d478a14cab24f9785a7d4':
    `<p>The formula relating Fahrenheit and Kelvin is ${f('F(x) = \\frac{9}{5}(x - 273.15) + 32')}.</p>` +
    `<p>This is a linear function with slope ${f('\\frac{\\Delta F}{\\Delta x} = \\frac{9}{5} = 1.8')}.</p>` +
    `<p>When the temperature increases by ${f('\\Delta x = 13.30')} kelvins, the corresponding increase in degrees Fahrenheit is:</p>` +
    `<p>${f('\\Delta F = \\frac{9}{5}(13.30) = 1.8 \\times 13.30 = 23.94^\\circ\\text{F}')}</p>`,

  // Q14
  '6a6d47a414cab24f9785a7d8':
    `<p>The sum of the boiling points of all 175 organic compounds is:</p>` +
    `<p>${f('175 \\times 167 = 29,225^\\circ\\text{C}')}</p>` +
    `<p>The sum of the boiling points of the 50 semivolatile compounds is:</p>` +
    `<p>${f('50 \\times 322 = 16,100^\\circ\\text{C}')}</p>` +
    `<p>The sum of the boiling points of the remaining 125 volatile compounds is:</p>` +
    `<p>${f('29,225 - 16,100 = 13,125^\\circ\\text{C}')}</p>` +
    `<p>The mean boiling point of the volatile compounds is:</p>` +
    `<p>${f('\\frac{13,125}{125} = 105^\\circ\\text{C}')}</p>`,

  // Q15
  '6a6d480f14cab24f9785a7de':
    `<p>In the exponential function ${f('f(x) = 26(1.20)^{\\frac{x}{3}}')}, when ${f('x')} increases by 6, the exponent increases by ${f('\\frac{6}{3} = 2')}.</p>` +
    `<p>Thus, the function value is multiplied by:</p>` +
    `<p>${f('(1.20)^2 = 1.44')}</p>` +
    `<p>A factor of 1.44 corresponds to an increase of ${f('1.44 - 1 = 0.44 = 44\\%')}.</p>` +
    `<p>Therefore, ${f('p = 44')}.</p>`,

  // Q16
  '6a6d484b14cab24f9785a7e2':
    `<p>The carpenter charges a flat rate of $228 for the first 2 hours.</p>` +
    `<p>For ${f('x > 2')} total hours, the remaining time beyond the first 2 hours is ${f('x - 2')} hours, charged at $95 per hour.</p>` +
    `<p>Total charge:</p>` +
    `<p>${f('y = 228 + 95(x - 2) = 228 + 95x - 190 = 95x + 38')}</p>`,

  // Q17
  '6a6d487714cab24f9785a7e6':
    `<p>Equate the two equations to find the intersection points:</p>` +
    `<p>${f('x^2 + 8x + a = -6.5 \\implies x^2 + 8x + (a + 6.5) = 0')}</p>` +
    `<p>The system has no real solutions when the discriminant is strictly negative (${f('\\Delta < 0')}):</p>` +
    `<p>${f('8^2 - 4(1)(a + 6.5) < 0')}</p>` +
    `<p>${f('64 - 4a - 26 < 0')}</p>` +
    `<p>${f('38 - 4a < 0 \\implies 4a > 38 \\implies a > 9.5')}</p>` +
    `<p>Since ${f('a')} is an integer, the least possible value is ${f('a = 10')}.</p>`,

  // Q18
  '6a6d48bc14cab24f9785a7ea':
    `<p>Rewrite the radicals using fractional exponents with base ${f('272n')}:</p>` +
    `<p>${f('\\sqrt[5]{272n} = (272n)^{\\frac{1}{5}}')}</p>` +
    `<p>${f('(\\sqrt[6]{272n})^2 = \\left((272n)^{\\frac{1}{6}}\\right)^2 = (272n)^{\\frac{2}{6}} = (272n)^{\\frac{1}{3}}')}</p>` +
    `<p>Multiply using the product rule of exponents:</p>` +
    `<p>${f('(272n)^{\\frac{1}{5}} \\times (272n)^{\\frac{1}{3}} = (272n)^{\\frac{1}{5} + \\frac{1}{3}} = (272n)^{\\frac{8}{15}}')}</p>` +
    `<p>Equate the exponent to ${f('30x')}:</p>` +
    `<p>${f('30x = \\frac{8}{15} \\implies x = \\frac{8}{15 \\times 30} = \\frac{8}{450} = \\frac{4}{225}')}</p>`,

  // Q19
  '6a6d493c14cab24f9785a7ee':
    `<p>We are looking for the conditional probability ${f('P(\\text{Group A} \\mid \\text{age } \\ge 10)')}.</p>` +
    `<p>The total number of participants who are at least 10 years of age is:</p>` +
    `<p>${f('35 \\text{ (10–19 years)} + 35 \\text{ (20+ years)} = 70')}</p>` +
    `<p>Among these 70 participants, the number in Group A is:</p>` +
    `<p>${f('17 + 8 = 25')}</p>` +
    `<p>Therefore, the probability is:</p>` +
    `<p>${f('\\frac{25}{70} = \\frac{5}{14}')}</p>`,

  // Q20
  '6a6d49c914cab24f9785a7f2':
    `<p>Since ${f('g(x) = \\frac{f(x)}{x + 4}')}, we have ${f('f(x) = (x + 4)g(x)')}.</p>` +
    `<p>Use the values from the table to determine ${f('f(x)')}:</p>` +
    `<p>1. At ${f('x = -9')}: ${f('f(-9) = (-9 + 4)(0) = 0')}</p>` +
    `<p>2. At ${f('x = 16')}: ${f('f(16) = (16 + 4)(5) = 20 \\times 5 = 100')}</p>` +
    `<p>Because ${f('f(x)')} is a linear function, its slope is:</p>` +
    `<p>${f('m = \\frac{100 - 0}{16 - (-9)} = \\frac{100}{25} = 4')}</p>` +
    `<p>Using the point ${f('(-9, 0)')}, the linear equation is:</p>` +
    `<p>${f('f(x) = 4(x + 9) = 4x + 36')}</p>` +
    `<p>The ${f('y')}-intercept is ${f('(0, 36)')}.</p>`,

  // Q21
  '6a6d4a7014cab24f9785a7f6':
    `<p>Express the given relationships mathematically:</p>` +
    `<p>1. ${f('A = 4.38B')}</p>` +
    `<p>2. ${f('A = 0.00073C \\implies C = \\frac{A}{0.00073}')}</p>` +
    `<p>Substitute ${f('A = 4.38B')} into the second equation:</p>` +
    `<p>${f('C = \\frac{4.38B}{0.00073} = 6,000B')}</p>` +
    `<p>Since ${f('C')} is ${f('p\\%')} of ${f('B')}, ${f('C = \\frac{p}{100}B')}:</p>` +
    `<p>${f('\\frac{p}{100} = 6,000 \\implies p = 600,000')}</p>` +
    `<p>Now find ${f('\\frac{p}{1000}')}:</p>` +
    `<p>${f('\\frac{p}{1,000} = \\frac{600,000}{1,000} = 600')}</p>`,

  // Q22
  '6a6d4ac414cab24f9785a7fa':
    `<p>Multiply the given equation by ${f('72cx')} (assuming ${f('x \\neq 0')} and ${f('c \\neq 0')}):</p>` +
    `<p>${f('72 = cx^2 + 72x \\implies cx^2 + 72x - 72 = 0')}</p>` +
    `<p>For this quadratic equation to have exactly one distinct real solution, its discriminant must equal 0:</p>` +
    `<p>${f('\\Delta = (72)^2 - 4(c)(-72) = 0')}</p>` +
    `<p>${f('5,184 + 288c = 0')}</p>` +
    `<p>${f('288c = -5,184 \\implies c = -\\frac{5,184}{288} = -18')}</p>` +
    `<p>(With ${f('c = -18')}, the equation is ${f('-18(x - 2)^2 = 0')}, giving the single solution ${f('x = 2 \\neq 0')}).</p>`
};

async function run() {
  console.log('Injecting explanations for June 2025 · INT 1 (M2)...');

  const ids = Object.keys(explanations);
  let count = 0;
  for (const id of ids) {
    const res = await updateQuestion(id, { explanation: explanations[id] });
    count++;
    console.log(`[${count}/${ids.length}] Updated explanation for ${id}: ${res.message === 'success' ? '✅' : JSON.stringify(res)}`);
  }

  console.log('\n🎉 Finished updating all 22 explanations for June 2025 · INT 1 (M2)!');
}

run().catch(console.error);
