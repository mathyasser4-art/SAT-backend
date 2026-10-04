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
  '6a626509c3d08d90637d369b': `<p><strong>The correct answer is 22.</strong></p>
<p>In a rectangle with side lengths ${f('a')} and ${f('b')} and diagonal ${f('d')}, by the Pythagorean theorem:</p>
<p>${f('a^2 + b^2 = d^2')}</p>
<p>Given ${f('d = \\sqrt{65}')} and ${f('a = 4')}:</p>
<p>${f('4^2 + b^2 = (\\sqrt{65})^2')}</p>
<p>${f('16 + b^2 = 65')}</p>
<p>${f('b^2 = 65 - 16 = 49 \\implies b = 7')}</p>
<p>The perimeter of the rectangle is:</p>
<p>${f('P = 2(a + b) = 2(4 + 7) = 2(11) = 22')}</p>`,

  // Q2
  '6a626672c3d08d90637d36a9': `<p><strong>The correct answer is 42.</strong></p>
<p>The function is defined as ${f('h(x) = 7|x|')}.</p>
<p>To evaluate ${f('h(-6)')}, substitute ${f('x = -6')}:</p>
<p>${f('h(-6) = 7|-6| = 7(6) = 42')}</p>`,

  // Q3
  '6a626750c3d08d90637d36ce': `<p><strong>The correct answer is 4.</strong></p>
<p>We are given that ${f('\\frac{x}{y} = 52')} and ${f('\\frac{cx}{4y} = 52')}.</p>
<p>Rewrite the second equation by factoring out the constant coefficient:</p>
<p>${f('\\frac{c}{4} \\left(\\frac{x}{y}\\right) = 52')}</p>
<p>Substitute ${f('\\frac{x}{y} = 52')}:</p>
<p>${f('\\frac{c}{4} (52) = 52')}</p>
<p>Divide both sides by 52:</p>
<p>${f('\\frac{c}{4} = 1 \\implies c = 4')}</p>`,

  // Q4
  '6a6267efc3d08d90637d36d8': `<p><strong>The correct answer is 16.</strong></p>
<p>Notice the repeated expression ${f('8 - 4x')} on both sides of the equation:</p>
<p>${f('5(8 - 4x) + 2 = 4(8 - 4x) + 18')}</p>
<p>Let ${f('u = 8 - 4x')}. The equation becomes:</p>
<p>${f('5u + 2 = 4u + 18')}</p>
<p>Subtract ${f('4u')} from both sides:</p>
<p>${f('u + 2 = 18')}</p>
<p>Subtract 2 from both sides:</p>
<p>${f('u = 16')}</p>
<p>Therefore, the value of ${f('8 - 4x')} is <strong>16</strong>.</p>`,

  // Q5
  '6a62714dc3d08d90637d36dc': `<p><strong>The correct answer is 0.25 (or 1/4).</strong></p>
<p>Set the function ${f('g(x) = 16x + 25')} equal to 29:</p>
<p>${f('16x + 25 = 29')}</p>
<p>Subtract 25 from both sides:</p>
<p>${f('16x = 4')}</p>
<p>Divide by 16:</p>
<p>${f('x = \\frac{4}{16} = \\frac{1}{4} = 0.25')}</p>`,

  // Q6
  '6a62733ac3d08d90637d36e4': `<p><strong>The correct answer is 343.</strong></p>
<p>Translate the given statements into algebraic equations:</p>
<p>1) ${f('a')} is 240% of ${f('b')} ${f('\\implies a = 2.40b')}</p>
<p>2) ${f('a')} is 70% of ${f('c')} ${f('\\implies a = 0.70c')}</p>
<p>Equating the expressions for ${f('a')}:</p>
<p>${f('0.70c = 2.40b')}</p>
<p>Solve for ${f('c')}:</p>
<p>${f('c = \\frac{2.40}{0.70}b = \\frac{24}{7}b \\approx 3.42857b')}</p>
<p>If ${f('c')} is ${f('p\\%')} of ${f('b')}, then:</p>
<p>${f('p = \\frac{24}{7} \\times 100 = \\frac{2{,}400}{7} \\approx 342.86')}</p>
<p>The closest value among the choices is <strong>343</strong>.</p>`,

  // Q7
  '6a6273d6c3d08d90637d36e8': `<p><strong>The correct answer is 30.</strong></p>
<p>The equation is given by ${f('x + y = 48')}, where ${f('x')} is the number of marble queen pothos stems and ${f('y')} is the number of snow queen pothos stems.</p>
<p>Substitute ${f('y = 18')}:</p>
<p>${f('x + 18 = 48')}</p>
<p>Subtract 18 from both sides:</p>
<p>${f('x = 48 - 18 = 30')}</p>`,

  // Q8
  '6a627489c3d08d90637d36ee': `<p><strong>The correct answer is -10.</strong></p>
<p>We are given that ${f('7 + x = 5')}.</p>
<p>Notice that the expression ${f('-14 - 2x')} can be factored by ${f('-2')}:</p>
<p>${f('-14 - 2x = -2(7 + x)')}</p>
<p>Substitute ${f('7 + x = 5')}:</p>
<p>${f('-14 - 2x = -2(5) = -10')}</p>`,

  // Q9
  '6a627516c3d08d90637d36f2': `<p><strong>The correct answer is 28.</strong></p>
<p>The function is defined by ${f('k(x) = x^3 + 20')}.</p>
<p>To find the value when ${f('x = 2')}, substitute 2 for ${f('x')}:</p>
<p>${f('k(2) = 2^3 + 20 = 8 + 20 = 28')}</p>`,

  // Q10
  '6a6275afc3d08d90637d36f6': `<p><strong>The correct answer is ${f('x^2 + 7a + 8')}.</strong></p>
<p>Group the first three terms of the given expression:</p>
<p>${f('(x^4 + 14ax^2 + 49a^2) - 64')}</p>
<p>Notice that ${f('x^4 + 14ax^2 + 49a^2 = (x^2 + 7a)^2')}.</p>
<p>The entire expression is a difference of two squares:</p>
<p>${f('(x^2 + 7a)^2 - 8^2 = (x^2 + 7a + 8)(x^2 + 7a - 8)')}</p>
<p>Thus, ${f('x^2 + 7a + 8')} is a factor of the expression.</p>`,

  // Q11
  '6a627684c3d08d90637d3702': `<p><strong>The correct answer is ${f('g(x) = 2x - 7')}.</strong></p>
<p>For a linear function, the slope ${f('m')} is the rate of change per unit increase in ${f('x')}:</p>
<p>${f('m = g(x + 1) - g(x) = 2')}</p>
<p>Using point-slope form with ${f('m = 2')} and the point ${f('(9, 11)')}:</p>
<p>${f('g(x) - 11 = 2(x - 9)')}</p>
<p>${f('g(x) - 11 = 2x - 18 \\implies g(x) = 2x - 7')}</p>`,

  // Q12
  '6a627762c3d08d90637d370c': `<p><strong>The correct answer is 15,389.</strong></p>
<p>The volume of the wall of the hollow cylindrical pipe is the difference between the volume of the outer cylinder and the inner cylinder:</p>
<p>${f('V = \\pi R^2 h - \\pi r^2 h = \\pi h (R^2 - r^2)')}</p>
<p>From the problem statement:</p>
<p>• Outside diameter = 60 inches ${f('\\implies R = \\frac{60}{2} = 30\\text{ inches}')}</p>
<p>• Wall thickness = ${f('\\frac{5}{8} = 0.625\\text{ inches}')}</p>
<p>• Inside radius ${f('r = 30 - 0.625 = 29.375\\text{ inches}')}</p>
<p>• Height ${f('h = 132\\text{ inches}')}</p>
<p>Calculate ${f('R^2 - r^2')}:</p>
<p>${f('R^2 - r^2 = (R - r)(R + r) = (0.625)(30 + 29.375) = (0.625)(59.375) = 37.109375')}</p>
<p>Now calculate the volume:</p>
<p>${f('V = \\pi \\times 132 \\times 37.109375 \\approx 4{,}898.4375\\pi \\approx 15{,}388.9\\text{ cubic inches}')}</p>
<p>Rounding to the nearest integer gives <strong>15,389</strong>.</p>`,

  // Q13
  '6a627802c3d08d90637d371a': `<p><strong>The correct answer is 28.</strong></p>
<p>The function is defined as ${f('h(x) = 7|x|')}.</p>
<p>Substitute ${f('x = -4')}:</p>
<p>${f('h(-4) = 7|-4| = 7(4) = 28')}</p>`,

  // Q14
  '6a627941c3d08d90637d3720': `<p><strong>The correct answer is 18.</strong></p>
<p>In triangle ${f('ABC')}, segment ${f('DE')} is parallel to ${f('AC')}, with ${f('D')} on ${f('AB')} and ${f('E')} on ${f('BC')}.</p>
<p>Since ${f('DE \\parallel AC')}, triangles ${f('\\triangle BDE')} and ${f('\\triangle BAC')} are similar (${f('\\triangle BDE \\sim \\triangle BAC')}).</p>
<p>We are given that ${f('BD = AD')}, which means ${f('D')} is the midpoint of ${f('AB')}, and therefore:</p>
<p>${f('\\frac{BD}{BA} = \\frac{BD}{BD + AD} = \\frac{1}{2}')}</p>
<p>By the properties of similar triangles, the ratio of corresponding sides is equal:</p>
<p>${f('\\frac{BE}{BC} = \\frac{BD}{BA} = \\frac{1}{2} \\implies BC = 2 \\times BE')}</p>
<p>Given ${f('BE = 9')}:</p>
<p>${f('BC = 2(9) = 18')}</p>`,

  // Q15
  '6a6279b9c3d08d90637d3724': `<p><strong>The correct answer is 12.</strong></p>
<p>Notice the repeated expression ${f('8 - 2x')} on both sides of the equation:</p>
<p>${f('5(8 - 2x) + 3 = 4(8 - 2x) + 15')}</p>
<p>Let ${f('u = 8 - 2x')}. The equation simplifies to:</p>
<p>${f('5u + 3 = 4u + 15')}</p>
<p>Subtract ${f('4u')} from both sides:</p>
<p>${f('u + 3 = 15')}</p>
<p>Subtract 3 from both sides:</p>
<p>${f('u = 12')}</p>
<p>Therefore, the value of ${f('8 - 2x')} is <strong>12</strong>.</p>`,

  // Q16
  '6a627aa7c3d08d90637d3728': `<p><strong>The correct answer is 338.</strong></p>
<p>Translate the given percentage relationships into equations:</p>
<p>1) ${f('a = 2.70b')}</p>
<p>2) ${f('a = 0.80c')}</p>
<p>Equating the two expressions for ${f('a')}:</p>
<p>${f('0.80c = 2.70b')}</p>
<p>Solve for ${f('c')} in terms of ${f('b')}:</p>
<p>${f('c = \\frac{2.70}{0.80}b = \\frac{27}{8}b = 3.375b')}</p>
<p>If ${f('c')} is ${f('p\\%')} of ${f('b')}, then:</p>
<p>${f('p = 3.375 \\times 100 = 337.5')}</p>
<p>The closest value among the choices is <strong>338</strong>.</p>`,

  // Q17
  '6a627b5fc3d08d90637d3732': `<p><strong>The correct answer is 40.</strong></p>
<p>Given the equation ${f('x + y = 53')}, substitute ${f('y = 13')}:</p>
<p>${f('x + 13 = 53 \\implies x = 53 - 13 = 40')}</p>`,

  // Q18
  '6a627c21c3d08d90637d373e': `<p><strong>The correct answer is -15.</strong></p>
<p>Start with the given equation ${f('7 + x = 5')}.</p>
<p>Notice that ${f('-21 - 3x')} can be rewritten by factoring out ${f('-3')}:</p>
<p>${f('-21 - 3x = -3(7 + x)')}</p>
<p>Substitute ${f('7 + x = 5')}:</p>
<p>${f('-3(5) = -15')}</p>`,

  // Q19
  '6a627d56c3d08d90637d3742': `<p><strong>The correct answer is 58.</strong></p>
<p>The function is defined by ${f('k(x) = x^3 + 50')}.</p>
<p>Substitute ${f('x = 2')}:</p>
<p>${f('k(2) = 2^3 + 50 = 8 + 50 = 58')}</p>`,

  // Q20
  '6a6283efc3d08d90637d3746': `<p><strong>The correct answer is 0.</strong></p>
<p>Set each factor of the product ${f('2x(x - 1)(x + 7) = 0')} equal to zero:</p>
<p>• ${f('2x = 0 \\implies x = 0')}</p>
<p>• ${f('x - 1 = 0 \\implies x = 1')}</p>
<p>• ${f('x + 7 = 0 \\implies x = -7')}</p>
<p>Among the given choices (-1, 0, 2, 7), <strong>0</strong> is one of the solutions.</p>`,

  // Q21
  '6a6285b1c3d08d90637d374e': `<p><strong>The correct answer is 5.</strong></p>
<p>A data point has its actual ${f('y')}-value greater than the ${f('y')}-value predicted by the line of best fit if and only if the point lies vertically <strong>above</strong> the line.</p>
<p>Counting the points that lie strictly above the line of best fit in the scatterplot gives exactly <strong>5</strong> points.</p>`,

  // Q22
  '6a62888fc3d08d90637d3776': `<p><strong>The correct answer is 66.</strong></p>
<p>Multiply both sides of ${f('\\frac{\\sin X}{\\cos Y} = 1')} by ${f('\\cos Y')}:</p>
<p>${f('\\sin X = \\cos Y')}</p>
<p>By the complementary angle trigonometric identity, for acute angles ${f('X')} and ${f('Y')}, ${f('\\sin X = \\cos Y')} if and only if ${f('X')} and ${f('Y')} are complementary:</p>
<p>${f('X + Y = 90^\\circ')}</p>
<p>Given that ${f('m\\angle Y = 24^\\circ')}:</p>
<p>${f('m\\angle X = 90^\\circ - 24^\\circ = 66^\\circ')}</p>`
};

async function run() {
  console.log('🚀 Injecting 22 explanations for October 2025 · INT 2 Module 1...\n');
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
