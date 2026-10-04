const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';

function updateQuestionExplanation(questionId, explanationHtml) {
    return new Promise((resolve, reject) => {
        const payload = JSON.stringify({ explanation: explanationHtml });
        const req = https.request(`${API_BASE}/question/updateQuestion/${questionId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload)
            }
        }, (res) => {
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

function f(formula) {
  return `<span class="ql-formula" data-value="${formula}"></span>`;
}

const explanations = {
  // Q1
  '6a624c93c3d08d90637d3631': `<p><strong>The correct answer is 40.</strong></p>
<p>The function is defined as ${f('h(x) = 8|x|')}.</p>
<p>To find ${f('h(-5)')}, substitute ${f('x = -5')}:</p>
<p>${f('h(-5) = 8|-5| = 8(5) = 40')}</p>`,

  // Q2
  '6a624cc7c3d08d90637d3637': `<p><strong>The correct answer is 4.</strong></p>
<p>The area of a rectangle is given by the formula:</p>
<p>${f('\\text{Area} = \\text{length} \\times \\text{width}')}</p>
<p>We are given that the area is 60 square inches and the length of the longest side is 15 inches:</p>
<p>${f('60 = 15 \\times \\text{width}')}</p>
<p>Divide both sides by 15:</p>
<p>${f('\\text{width} = \\frac{60}{15} = 4\\text{ inches}')}</p>
<p>Thus, the length of the shortest side is <strong>4</strong> inches.</p>`,

  // Q3
  '6a624d49c3d08d90637d3643': `<p><strong>The correct answer is 29.</strong></p>
<p>Locate the row in the table where the air temperature is ${f('38^\\circ\\text{F}')}:</p>
<p>In this row, under the column <em>"Wind chill temperature at wind speed 15 mph"</em>, the corresponding temperature is <strong>${f('29^\\circ\\text{F}')}</strong>.</p>`,

  // Q4
  '6a624df8c3d08d90637d365b': `<p><strong>The correct answer is 174.</strong></p>
<p>Charles saves ${f('\\frac{2}{5}')} of the $145 he earns each week:</p>
<p>${f('\\text{Weekly Savings} = \\frac{2}{5} \\times 145 = 2 \\times 29 = 58\\text{ dollars}')}</p>
<p>In 3 weeks, he will save:</p>
<p>${f('\\text{Total Savings} = 3 \\times 58 = 174\\text{ dollars}')}</p>`,

  // Q5
  '6a624e6ac3d08d90637d365f': `<p><strong>The correct answer is ${f('\\frac{10}{80}')}.</strong></p>
<p>The probability of selecting an igneous rock is the number of igneous rocks divided by the total number of rocks:</p>
<p>${f('P(\\text{igneous}) = \\frac{\\text{Frequency of igneous rocks}}{\\text{Total rocks}} = \\frac{10}{80}')}</p>`,

  // Q6
  '6a624ec6c3d08d90637d3663': `<p><strong>The correct answer is ${f('j = 7(k + 15m)')}.</strong></p>
<p>Given the equation:</p>
<p>${f('\\frac{j}{7} = k + 15m')}</p>
<p>Multiply both sides of the equation by 7 to isolate ${f('j')}:</p>
<p>${f('j = 7(k + 15m)')}</p>`,

  // Q7
  '6a624efbc3d08d90637d3667': `<p><strong>The correct answer is (3, 4).</strong></p>
<p>The solution to a system of linear equations graphed in the ${f('xy')}-plane corresponds to the coordinates of the point of intersection of the lines.</p>
<p>From the graph, one line is horizontal at ${f('y = 4')}, and the other line passes through ${f('(0, -4)')} and ${f('(3, 4)')}.</p>
<p>Both lines intersect precisely at the point <strong>${f('(3, 4)')}</strong>.</p>`,

  // Q8
  '6a624f74c3d08d90637d366b': `<p><strong>The correct answer is 202.</strong></p>
<p>Set the profit function ${f('p(x) = 5x - 210')} equal to 800:</p>
<p>${f('5x - 210 = 800')}</p>
<p>Add 210 to both sides:</p>
<p>${f('5x = 1{,}010')}</p>
<p>Divide by 5:</p>
<p>${f('x = \\frac{1{,}010}{5} = 202')}</p>
<p>Thus, they must sell <strong>202</strong> car stickers.</p>`,

  // Q9
  '6a624fc5c3d08d90637d366f': `<p><strong>The correct answer is 4.</strong></p>
<p>We are given that ${f('\\frac{x}{y} = 76')} and ${f('\\frac{cx}{4y} = 76')}.</p>
<p>Rewrite the second equation as:</p>
<p>${f('\\frac{c}{4} \\left(\\frac{x}{y}\\right) = 76')}</p>
<p>Substitute ${f('\\frac{x}{y} = 76')}:</p>
<p>${f('\\frac{c}{4} (76) = 76')}</p>
<p>Divide both sides by 76:</p>
<p>${f('\\frac{c}{4} = 1 \\implies c = 4')}</p>`,

  // Q10
  '6a663c25c3d08d90637d38d3': `<p><strong>The correct answer is ${f('42^\\circ')}.</strong></p>
<p>When two geometric figures are similar, their corresponding side lengths are proportional, and their corresponding angle measures are <strong>equal</strong>.</p>
<p>Since trapezoid ${f('CDEF')} is similar to trapezoid ${f('JKLM')}, angle ${f('C')} corresponds to angle ${f('J')}.</p>
<p>Therefore:</p>
<p>${f('m\\angle J = m\\angle C = 42^\\circ')}</p>`,

  // Q11
  '6a663c8ac3d08d90637d38d7': `<p><strong>The correct answer is ${f('t = 25d')}.</strong></p>
<p>Calculate the constant of proportionality ${f('k = \\frac{t}{d}')} for each row of the table:</p>
<p>• For ${f('d = 0.32')}, ${f('t = 8')}: ${f('\\frac{8}{0.32} = 25')}</p>
<p>• For ${f('d = 0.48')}, ${f('t = 12')}: ${f('\\frac{12}{0.48} = 25')}</p>
<p>• For ${f('d = 0.76')}, ${f('t = 19')}: ${f('\\frac{19}{0.76} = 25')}</p>
<p>Since the ratio is constant at 25, the equation defining this linear relationship is ${f('t = 25d')}.</p>`,

  // Q12
  '6a663e59c3d08d90637d3904': `<p><strong>The correct answer is 21.</strong></p>
<p>In right triangle ${f('JKL')}, with right angle at ${f('K')}:</p>
<p>${f('\\tan(\\angle L) = \\frac{\\text{opposite}}{\\text{adjacent}} = \\frac{JK}{KL} = \\frac{3}{4}')}</p>
<p>This means the legs ${f('JK')} and ${f('KL')} are in the ratio ${f('3 : 4')}. Let ${f('JK = 3x')} and ${f('KL = 4x')} for some positive constant ${f('x')}.</p>
<p>By the Pythagorean theorem, the hypotenuse ${f('JL')} is:</p>
<p>${f('JL = \\sqrt{(3x)^2 + (4x)^2} = \\sqrt{9x^2 + 16x^2} = \\sqrt{25x^2} = 5x')}</p>
<p>From the figure, the length of hypotenuse ${f('JL = 35')}:</p>
<p>${f('5x = 35 \\implies x = 7')}</p>
<p>Therefore, the length of ${f('JK')} is:</p>
<p>${f('JK = 3x = 3(7) = 21')}</p>`,

  // Q13
  '6a664039c3d08d90637d3908': `<p><strong>The correct answer is -24.</strong></p>
<p>The given quadratic function is ${f('f(x) = x^2 - 12x + 12')}.</p>
<p>Because the coefficient of ${f('x^2')} is positive (1 > 0), the parabola opens upward, and its minimum occurs at the vertex.</p>
<p>The ${f('x')}-coordinate of the vertex is:</p>
<p>${f('x = -\\frac{b}{2a} = -\\frac{-12}{2(1)} = 6')}</p>
<p>Substitute ${f('x = 6')} into the function to find the minimum value:</p>
<p>${f('f(6) = (6)^2 - 12(6) + 12 = 36 - 72 + 12 = -24')}</p>`,

  // Q14
  '6a664096c3d08d90637d390c': `<p><strong>The correct answer is ${f('g(x) = 2x - 7')}.</strong></p>
<p>For any linear function ${f('g(x) = mx + b')}, the difference ${f('g(x + 1) - g(x)')} represents the rate of change (slope) per unit increase in ${f('x')}:</p>
<p>${f('m = g(x + 1) - g(x) = 2')}</p>
<p>Using point-slope form with ${f('m = 2')} and the given point ${f('(9, 11)')}:</p>
<p>${f('g(x) - 11 = 2(x - 9)')}</p>
<p>${f('g(x) - 11 = 2x - 18')}</p>
<p>Add 11 to both sides:</p>
<p>${f('g(x) = 2x - 7')}</p>`,

  // Q15
  '6a664137c3d08d90637d3912': `<p><strong>The correct answer is 507.</strong></p>
<p>The linear function is defined by ${f('f(x) = rx + s')}. The slope ${f('r')} can be calculated from the two points ${f('(-9, 78)')} and ${f('(9, -156)')}:</p>
<p>${f('r = \\frac{-156 - 78}{9 - (-9)} = \\frac{-234}{18} = -13')}</p>
<p>Now find the ${f('y')}-intercept ${f('s')} using ${f('f(9) = -156')}:</p>
<p>${f('-13(9) + s = -156')}</p>
<p>${f('-117 + s = -156 \\implies s = -156 + 117 = -39')}</p>
<p>Now compute the product ${f('rs')}:</p>
<p>${f('rs = (-13) \\times (-39) = 507')}</p>`,

  // Q16
  '6a664166c3d08d90637d3916': `<p><strong>The correct answer is ${f('x = \\frac{-11 \\pm \\sqrt{181}}{2}')}.</strong></p>
<p>Expand and rewrite the equation in standard quadratic form ${f('ax^2 + bx + c = 0')}:</p>
<p>${f('x(x + 11) - 15 = 0')}</p>
<p>${f('x^2 + 11x - 15 = 0')}</p>
<p>Apply the quadratic formula with ${f('a = 1')}, ${f('b = 11')}, and ${f('c = -15')}:</p>
<p>${f('x = \\frac{-11 \\pm \\sqrt{11^2 - 4(1)(-15)}}{2(1)}')}</p>
<p>${f('x = \\frac{-11 \\pm \\sqrt{121 + 60}}{2} = \\frac{-11 \\pm \\sqrt{181}}{2}')}</p>`,

  // Q17
  '6a66418fc3d08d90637d391a': `<p><strong>The correct answer is 1.</strong></p>
<p>Given the equation:</p>
<p>${f('2|4x - 2| = 5')}</p>
<p>Divide both sides by 2:</p>
<p>${f('|4x - 2| = 2.5')}</p>
<p>This yields two linear equations:</p>
<p><strong>Case 1:</strong> ${f('4x - 2 = 2.5 \\implies 4x = 4.5 \\implies x = 1.125')}</p>
<p><strong>Case 2:</strong> ${f('4x - 2 = -2.5 \\implies 4x = -0.5 \\implies x = -0.125')}</p>
<p>The sum of the two solutions is:</p>
<p>${f('1.125 + (-0.125) = 1')}</p>`,

  // Q18
  '6a66420ec3d08d90637d3920': `<p><strong>The correct answer is 314.</strong></p>
<p>We are given two relationships for ${f('a')}:</p>
<p>1) ${f('a = 2.20b')}</p>
<p>2) ${f('a = 0.70c')}</p>
<p>Equating the two expressions for ${f('a')}:</p>
<p>${f('0.70c = 2.20b')}</p>
<p>Solve for ${f('c')} in terms of ${f('b')}:</p>
<p>${f('c = \\frac{2.20}{0.70}b = \\frac{22}{7}b \\approx 3.142857b')}</p>
<p>If ${f('c')} is ${f('p\\%')} of ${f('b')}, then ${f('c = \\frac{p}{100}b')}:</p>
<p>${f('\\frac{p}{100} = \\frac{22}{7} \\implies p = \\frac{2{,}200}{7} \\approx 314.2857')}</p>
<p>The closest value among the options is <strong>314</strong>.</p>`,

  // Q19
  '6a66427fc3d08d90637d3924': `<p><strong>The correct answer is ${f('A = 53.12(2.28)^{(x/6)}')}.</strong></p>
<p>• At the end of every 6-hour period, the total mass increases by 128%, which corresponds to a growth factor of:</p>
<p>${f('1 + 1.28 = 2.28')}</p>
<p>• Since the growth occurs every 6 hours, the exponent for the number of periods after ${f('x')} hours is ${f('\\frac{x}{6}')}.</p>
<p>• The general model is ${f('A = A_0 (2.28)^{(x/6)}')}.</p>
<p>• We are given that after 18 hours (${f('x = 18')}), the mass is 629.60 grams:</p>
<p>${f('629.60 = A_0 (2.28)^{18/6} = A_0 (2.28)^3 = A_0 (11.852352)')}</p>
<p>${f('A_0 = \\frac{629.60}{11.852352} \\approx 53.12')}</p>
<p>Therefore, the model is ${f('A = 53.12(2.28)^{(x/6)}')}.</p>`,

  // Q20
  '6a6642c2c3d08d90637d3930': `<p><strong>The correct answer is (0, 3).</strong></p>
<p>Given the system of equations:</p>
<p>1) ${f('y = 7x + 3')}</p>
<p>2) ${f('y = 7x^2 + 3')}</p>
<p>Equating the expressions for ${f('y')}:</p>
<p>${f('7x^2 + 3 = 7x + 3')}</p>
<p>${f('7x^2 - 7x = 0')}</p>
<p>${f('7x(x - 1) = 0')}</p>
<p>This yields two solutions for ${f('x')}:</p>
<p>• If ${f('x = 0')}, ${f('y = 7(0) + 3 = 3')}, giving the ordered pair <strong>${f('(0, 3)')}</strong>.</p>
<p>• If ${f('x = 1')}, ${f('y = 7(1) + 3 = 10')}, giving the ordered pair ${f('(1, 10)')}.</p>
<p>Among the given choices, ${f('(0, 3)')} is the correct answer.</p>`,

  // Q21
  '6a6642fcc3d08d90637d3934': `<p><strong>The correct answer is (13, 0).</strong></p>
<p>The ${f('x')}-intercepts of a graph in the ${f('xy')}-plane occur where ${f('y = 0')}:</p>
<p>${f('x^2 - 169 = 0')}</p>
<p>${f('x^2 = 169 \\implies x = \\pm 13')}</p>
<p>Thus, the ${f('x')}-intercepts are ${f('(13, 0)')} and ${f('(-13, 0)')}.</p>
<p>Among the choices, <strong>(13, 0)</strong> is listed.</p>`,

  // Q22
  '6a664327c3d08d90637d3938': `<p><strong>The correct answer is 20.</strong></p>
<p>The volume of a pyramid is given by:</p>
<p>${f('V = \\frac{1}{3} B h')}</p>
<p>where ${f('B')} is the area of the base and ${f('h')} is the height.</p>
<p>Given ${f('V = 125')} and ${f('h = 15')}:</p>
<p>${f('125 = \\frac{1}{3} B (15) = 5B')}</p>
<p>${f('B = \\frac{125}{5} = 25\\text{ square inches}')}</p>
<p>Since the base is a square, the side length ${f('s')} is:</p>
<p>${f('s = \\sqrt{25} = 5\\text{ inches}')}</p>
<p>The perimeter of the square base is:</p>
<p>${f('\\text{Perimeter} = 4s = 4(5) = 20\\text{ inches}')}</p>`
};

async function run() {
  console.log('🚀 Injecting 22 explanations for October 2025 · INT 1 Module 1...\n');
  const ids = Object.keys(explanations);
  let successCount = 0;

  for (let i = 0; i < ids.length; i++) {
    const id = ids[i];
    process.stdout.write(`Updating M1 Q${i + 1} (${id})... `);
    try {
      const res = await updateQuestionExplanation(id, explanations[id]);
      if (res.message === 'success') {
        console.log('✅');
        successCount++;
      } else {
        console.log('⚠️ ' + JSON.stringify(res));
      }
    } catch (err) {
      console.log('❌ Error: ' + err.message);
    }
  }

  console.log(`\n🎉 Finished Module 1: ${successCount}/${ids.length} explanations injected successfully!`);
}

run().catch(console.error);
