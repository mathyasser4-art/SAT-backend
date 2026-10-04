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
  '6a6e0f88f37fd34c9d2ad0f5':
    `<p>The florist has a total of 700 flowers in stock.</p>` +
    `<p>Calculate ${f('\\frac{2}{5}')} of the total stock:</p>` +
    `<p>${f('\\frac{2}{5} \\times 700 = 2 \\times 140 = 280')}</p>` +
    `<p>From the bar graph, the flower counts are:</p>` +
    `<ul>` +
    `<li>Daisy: 60</li>` +
    `<li>Orchid: 100</li>` +
    `<li>Tulip: 190</li>` +
    `<li>Lily: 180</li>` +
    `<li>Sunflower: 170</li>` +
    `</ul>` +
    `<p>The sum of Orchid and Lily is ${f('100 + 180 = 280')}, which is exactly ${f('\\frac{2}{5}')} of the florist's stock.</p>`,

  // Q2
  '6a6e101bf37fd34c9d2ad105':
    `<p>From the scatterplot, the line of best fit for data set A crosses the y-axis at approximately ${f('y \\approx 53.75')}.</p>` +
    `<p>Data set B is created by subtracting 11 units from each y-value of data set A.</p>` +
    `<p>Subtracting a constant 11 from each y-coordinate translates the entire data set and its line of best fit downward by 11 units:</p>` +
    `<p>${f('\\text{New y-intercept} = 53.75 - 11 = 42.75')}.</p>`,

  // Q3
  '6a6e1082f37fd34c9d2ad111':
    `<p>Given equation: ${f('4(2x + 11) - 2(2x - 5) = -9 + 13x')}.</p>` +
    `<p>Distribute on the left side:</p>` +
    `<p>${f('(8x + 44) - (4x - 10) = -9 + 13x')}</p>` +
    `<p>${f('4x + 54 = -9 + 13x')}</p>` +
    `<p>Subtract ${f('4x')} and add 9 to both sides:</p>` +
    `<p>${f('9x = 63 \\implies x = 7')}.</p>` +
    `<p>Now find ${f('12x')}:</p>` +
    `<p>${f('12x = 12(7) = 84')}.</p>`,

  // Q4
  '6a6e10adf37fd34c9d2ad115':
    `<p>Density is defined as mass divided by volume:</p>` +
    `<p>${f('\\text{Density} = \\frac{\\text{Mass}}{\\text{Volume}}')}</p>` +
    `<p>Given ${f('\\text{Mass} = 3{,}080\\text{ grams}')} and ${f('\\text{Volume} = 280\\text{ cm}^3')}:</p>` +
    `<p>${f('\\text{Density} = \\frac{3{,}080}{280} = 11\\text{ grams per cubic centimeter}')}.</p>`,

  // Q5
  '6a6e10f1f37fd34c9d2ad119':
    `<p>Solve the inequality for ${f('y')}:</p>` +
    `<p>${f('3x - 7y > 21 \\implies -7y > -3x + 21 \\implies y < \\frac{3}{7}x - 3')}</p>` +
    `<p>Now examine the region ${f('x < 0')} and ${f('y > 0')} (Quadrant II):</p>` +
    `<p>If ${f('x < 0')}, then ${f('\\frac{3}{7}x < 0')}, which means ${f('\\frac{3}{7}x - 3 < -3')}.</p>` +
    `<p>Any solution must satisfy ${f('y < \\frac{3}{7}x - 3 < -3')}.</p>` +
    `<p>However, all points in this region have ${f('y > 0')}, which can never be less than ${f('-3')}.</p>` +
    `<p>Therefore, the region ${f('x < 0')} and ${f('y > 0')} does NOT contain any points that are part of the solution set.</p>`,

  // Q6
  '6a6e1127f37fd34c9d2ad11d':
    `<p>The graph shows the linear equation ${f('y = f(x) - 9')}.</p>` +
    `<p>From the graph, the line passes through ${f('(0, -1)')} and ${f('(1, -6)')}:</p>` +
    `<ul>` +
    `<li>Slope: ${f('m = \\frac{-6 - (-1)}{1 - 0} = -5')}</li>` +
    `<li>Y-intercept: ${f('b = -1')}</li>` +
    `</ul>` +
    `<p>Thus, the equation of the line shown is ${f('y = -5x - 1')}.</p>` +
    `<p>Since this graph represents ${f('y = f(x) - 9')}:</p>` +
    `<p>${f('f(x) - 9 = -5x - 1 \\implies f(x) = -5x + 8')}.</p>`,

  // Q7
  '6a6e123cf37fd34c9d2ad123':
    `<p>In ${f('\\triangle FGH')} and ${f('\\triangle KLM')}, we are given:</p>` +
    `<ul>` +
    `<li>${f('\\angle G = \\angle L = 30^\\circ')}</li>` +
    `<li>${f('GH = LM = 34\\text{ cm}')}</li>` +
    `<li>${f('\\frac{GH}{GF} = \\frac{LM}{LK} \\implies \\frac{34}{GF} = \\frac{34}{LK} \\implies GF = LK')}</li>` +
    `</ul>` +
    `<p>Since two pairs of corresponding sides are equal (${f('GH = LM')} and ${f('GF = LK')}) and their included angles are equal (${f('\\angle G = \\angle L')}), the triangles are congruent by the Side-Angle-Side (SAS) congruence postulate.</p>` +
    `<p>Therefore, no additional information is necessary.</p>`,

  // Q8
  '6a6e12d5f37fd34c9d2ad127':
    `<p>We are given the system of equations:</p>` +
    `<p>${f('y = 3x + 9')} and ${f('3y = 8x - 6')}</p>` +
    `<p>Substitute ${f('y = 3x + 9')} into the second equation:</p>` +
    `<p>${f('3(3x + 9) = 8x - 6 \\implies 9x + 27 = 8x - 6')}</p>` +
    `<p>${f('x = -6 - 27 = -33')}</p>` +
    `<p>Find ${f('y')}:</p>` +
    `<p>${f('y = 3(-33) + 9 = -99 + 9 = -90')}</p>` +
    `<p>Now calculate ${f('x - y')}:</p>` +
    `<p>${f('x - y = -33 - (-90) = -33 + 90 = 57')}.</p>`,

  // Q9
  '6a6e1310f37fd34c9d2ad12b':
    `<p>The exponential function is ${f('f(x) = c^x')}.</p>` +
    `<p>Substitute into the given equation ${f('f(6) = 9 \\cdot f(4)')}:</p>` +
    `<p>${f('c^6 = 9 \\cdot c^4')}</p>` +
    `<p>Since ${f('c > 1')}, divide both sides by ${f('c^4')}:</p>` +
    `<p>${f('c^2 = 9 \\implies c = 3')}.</p>`,

  // Q10
  '6a6e13fd808167941fdca6dd':
    `<p>In the right triangle shown:</p>` +
    `<ul>` +
    `<li>The side opposite to angle ${f('x^\\circ')} has length 63.</li>` +
    `<li>The hypotenuse has length 73.</li>` +
    `</ul>` +
    `<p>By definition of the sine function:</p>` +
    `<p>${f('\\sin x^\\circ = \\frac{\\text{Opposite}}{\\text{Hypotenuse}} = \\frac{63}{73}')}.</p>`,

  // Q11
  '6a6e17e7808167941fdca799':
    `<p>The system is:</p>` +
    `<p>(1) ${f('-x - wy = -337')}</p>` +
    `<p>(2) ${f('2x - wy = 47')}</p>` +
    `<p>Subtract equation (1) from equation (2) to eliminate the ${f('wy')} term:</p>` +
    `<p>${f('(2x - wy) - (-x - wy) = 47 - (-337)')}</p>` +
    `<p>${f('3x = 384 \\implies x = 128')}</p>` +
    `<p>Since the intersection point is ${f('(q, 19)')}, we have ${f('q = 128')} and ${f('y = 19')}.</p>` +
    `<p>Substitute into equation (2):</p>` +
    `<p>${f('2(128) - 19w = 47 \\implies 256 - 19w = 47 \\implies 19w = 209 \\implies w = 11')}.</p>`,

  // Q12
  '6a6e1898808167941fdca79d':
    `<p>This is a conditional probability problem: ${f('P(\\text{Site A} \\mid \\text{Red maple})')}.</p>` +
    `<p>The condition limits our sample space to all red maple trees:</p>` +
    `<p>${f('\\text{Total red maples} = 35 + 15 = 50')}</p>` +
    `<p>Among these 50 red maple trees, 35 are located at Site A.</p>` +
    `<p>Therefore, the probability is:</p>` +
    `<p>${f('P(\\text{Site A} \\mid \\text{Red maple}) = \\frac{35}{50}')}.</p>`,

  // Q13
  '6a6e19e5808167941fdca7a3':
    `<p>The temperature function is ${f('g(t) = 295 + (361 - 295)(2.72)^{-0.104t}')}.</p>` +
    `<p>When the beaker was first placed on the table, ${f('t = 0')}:</p>` +
    `<p>${f('g(0) = 295 + (361 - 295)(2.72)^0 = 295 + (361 - 295)(1) = 361\\text{ kelvins}')}.</p>`,

  // Q14
  '6a6e1aa8808167941fdca7a9':
    `<p>We are given that ${f('f(1) = k')} and need to find the equivalent form that displays ${f('k')} as either the coefficient or the base.</p>` +
    `<p>Consider the function form ${f('f(x) = 144.5(1.7)^{x-1}')}:</p>` +
    `<p>Evaluating at ${f('x = 1')}:</p>` +
    `<p>${f('f(1) = 144.5(1.7)^{1 - 1} = 144.5(1.7)^0 = 144.5')}</p>` +
    `<p>In this form, the value ${f('k = 144.5')} appears directly as the coefficient.</p>`,

  // Q15
  '6a6e1af8808167941fdca7ad':
    `<p>The graph crosses the x-axis where ${f('y = 0')}:</p>` +
    `<p>${f('9\\left(\\frac{a}{6}\\right)^{x+c} - b = 0 \\implies \\left(\\frac{a}{6}\\right)^{x+c} = \\frac{b}{9}')}</p>` +
    `<p>We are given that ${f('a > 6')} (so base ${f('\\frac{a}{6} > 1')}) and ${f('b > 0')} (so ${f('\\frac{b}{9} > 0')}).</p>` +
    `<p>An exponential function with a base greater than 1 is strictly increasing across all real numbers and takes on every positive real value exactly once.</p>` +
    `<p>Taking the logarithm:</p>` +
    `<p>${f('x + c = \\log_{a/6}\\left(\\frac{b}{9}\\right) \\implies x = \\log_{a/6}\\left(\\frac{b}{9}\\right) - c')}</p>` +
    `<p>This yields exactly one unique real solution for ${f('x')}, so the graph crosses the x-axis One time.</p>`,

  // Q16
  '6a6e1b80808167941fdca7b1':
    `<p>Since the graph of ${f('y = f(x)')} contains the points ${f('(-6, 0)')}, ${f('(7, 0)')}, ${f('(0, 0)')}, and ${f('(4, 0)')}, the values ${f('x = -6, 7, 0, 4')} are roots of ${f('f(x)')}.</p>` +
    `<p>By the factor theorem, ${f('(x + 6)')}, ${f('(x - 7)')}, ${f('x')}, and ${f('(x - 4)')} are factors of ${f('f(x)')}.</p>` +
    `<p>Multiplying the factors ${f('x')} and ${f('(x - 7)')}:</p>` +
    `<p>${f('x(x - 7) = x^2 - 7x')}</p>` +
    `<p>Therefore, ${f('x^2 - 7x')} must be a factor of ${f('f(x)')}.</p>`,

  // Q17
  '6a6e1d73808167941fdca7b5':
    `<p>Point ${f('P')} is the midpoint of ${f('NQ')}, so ${f('NP = PQ = 52\\text{ ft}')}.</p>` +
    `<p>The full width of rectangle ${f('SNQR')} is ${f('NQ = 52 + 52 = 104\\text{ ft}')}, and its height is ${f('NS = 18\\text{ ft}')}:</p>` +
    `<p>${f('\\text{Area of rectangle} = 104 \\times 18 = 1{,}872\\text{ sq ft}')}</p>` +
    `<p>Semicircle ${f('O')} has diameter ${f('NP = 52\\text{ ft}')}, so its radius is ${f('r = 26\\text{ ft}')}:</p>` +
    `<p>${f('\\text{Area of semicircle} = \\frac{1}{2}\\pi r^2 = \\frac{1}{2}\\pi(26^2) = 338\\pi\\text{ sq ft}')}</p>` +
    `<p>The total area of the figure is ${f('338\\pi + 1{,}872')}.</p>` +
    `<p>Matching ${f('a\\pi + b')}: ${f('a = 338')} and ${f('b = 1{,}872')}.</p>` +
    `<p>Now find ${f('a - b')}:</p>` +
    `<p>${f('a - b = 338 - 1{,}872 = -1534')}.</p>`,

  // Q18
  '6a6e1dee808167941fdca7bb':
    `<p>Given equation: ${f('\\frac{1}{5xy} + xyz = \\frac{1}{4yz}')}.</p>` +
    `<p>Subtract ${f('\\frac{1}{5xy}')} from both sides:</p>` +
    `<p>${f('xyz = \\frac{1}{4yz} - \\frac{1}{5xy}')}</p>` +
    `<p>Find a common denominator for the right side (${f('20xyz')}):</p>` +
    `<p>${f('xyz = \\frac{5x - 4z}{20xyz}')}</p>` +
    `<p>Multiply both sides by ${f('y')}:</p>` +
    `<p>${f('xy^2z = \\frac{5x - 4z}{20xz}')}</p>` +
    `<p>Divide both sides by ${f('xz')}:</p>` +
    `<p>${f('y^2 = \\frac{5x - 4z}{20x^2z^2}')}</p>` +
    `<p>Since ${f('y > 0')}, take the positive square root:</p>` +
    `<p>${f('y = \\sqrt{\\frac{5x - 4z}{20x^2z^2}}')}.</p>`,

  // Q19
  '6a6e1f345db514110caca794':
    `<p>Given equation: ${f('2|x - 5| = k \\implies |x - 5| = \\frac{k}{2}')}.</p>` +
    `<p>The absolute value of any real expression is non-negative (${f('|u| \\ge 0')}):</p>` +
    `<ul>` +
    `<li>If ${f('\\frac{k}{2} > 0')}, there are two solutions (${f('x - 5 = \\pm \\frac{k}{2}')}).</li>` +
    `<li>If ${f('\\frac{k}{2} < 0')}, there are zero solutions.</li>` +
    `<li>If ${f('\\frac{k}{2} = 0')}, there is exactly one solution (${f('x - 5 = 0 \\implies x = 5')}).</li>` +
    `</ul>` +
    `<p>For the equation to have exactly one solution, we must have ${f('\\frac{k}{2} = 0')}. Thus, 0 only is correct.</p>`,

  // Q20
  '6a6e1f8e5db514110caca798':
    `<p>The initial mass of the kangaroo at 80 days old was ${f('k')} grams.</p>` +
    `<p>A percent increase of 676% corresponds to adding ${f('676\\% = 6.76')} times the initial mass:</p>` +
    `<p>${f('\\text{New mass} = k + 6.76k = (1 + 6.76)k = 7.76k')}.</p>`,

  // Q21
  '6a6e22c75db514110caca79c':
    `<p>We are given that ${f('g(x) = \\frac{f(x)}{x + 3}')}, which means ${f('f(x) = (x + 3)g(x)')}.</p>` +
    `<p>Using the table, evaluate ${f('f(x)')} at the given points:</p>` +
    `<ul>` +
    `<li>At ${f('x = -21')}: ${f('f(-21) = (-21 + 3)(2) = (-18)(2) = -36')}</li>` +
    `<li>At ${f('x = -9')}: ${f('f(-9) = (-9 + 3)(0) = 0')}</li>` +
    `<li>At ${f('x = 15')}: ${f('f(15) = (15 + 3)(4) = (18)(4) = 72')}</li>` +
    `</ul>` +
    `<p>Since ${f('f')} is linear, its slope is:</p>` +
    `<p>${f('m = \\frac{0 - (-36)}{-9 - (-21)} = \\frac{36}{12} = 3')}</p>` +
    `<p>Using point-slope form with ${f('(-9, 0)')}:</p>` +
    `<p>${f('f(x) = 3(x + 9) = 3x + 27')}</p>` +
    `<p>The y-intercept occurs at ${f('x = 0')}, giving ${f('(0, 27)')}.</p>`,

  // Q22
  '6a6e23015db514110caca7a0':
    `<p>For tour groups with ${f('n \\ge 25')} people:</p>` +
    `<ul>` +
    `<li>The first 25 people cost 28 USD each: ${f('25 \\times 28 = 700\\text{ USD}')}.</li>` +
    `<li>The remaining ${f('(n - 25)')} people cost 17 USD each: ${f('17(n - 25)\\text{ USD}')}.</li>` +
    `</ul>` +
    `<p>The total charge function is:</p>` +
    `<p>${f('f(n) = 700 + 17(n - 25) = 700 + 17n - 425 = 17n + 275')}.</p>`
};

async function main() {
  console.log('Injecting June 2025 · US 1 M2 Explanations...');
  for (const [id, expl] of Object.entries(explanations)) {
    const res = await updateQuestion(id, { explanation: expl });
    console.log(`Updated ${id}:`, res.message || res);
  }
  console.log('Finished June 2025 · US 1 M2!');
}

main().catch(console.error);
