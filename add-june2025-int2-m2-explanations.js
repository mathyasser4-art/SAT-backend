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
  '6a6d615d14cab24f9785a8f6':
    `<p>Average acceleration is defined as the change in speed divided by the time elapsed:</p>` +
    `<p>${f('\\text{Average acceleration} = \\frac{\\Delta v}{\\Delta t}')}</p>` +
    `<p>Given ${f('\\Delta v = 45\\text{ m/s}')} and ${f('\\Delta t = 6\\text{ s}')}:</p>` +
    `<p>${f('\\text{Average acceleration} = \\frac{45}{6} = 7.5\\text{ m/s}^2')}.</p>`,

  // Q2
  '6a6d619314cab24f9785a8fc':
    `<p>The given system of equations is:</p>` +
    `<p>${f('x + 26 = y')} and ${f('(x + 26)^2 = y')}</p>` +
    `<p>Substitute ${f('y = x + 26')} into the second equation:</p>` +
    `<p>${f('(x + 26)^2 = x + 26')}</p>` +
    `<p>Subtract ${f('(x + 26)')} from both sides:</p>` +
    `<p>${f('(x + 26)^2 - (x + 26) = 0 \\implies (x + 26)(x + 26 - 1) = 0 \\implies (x + 26)(x + 25) = 0')}</p>` +
    `<p>Thus, ${f('x = -26')} or ${f('x = -25')}.</p>` +
    `<p>Among the given choices, ${f('-25')} is a possible value of ${f('x')}.</p>`,

  // Q3
  '6a6d61c214cab24f9785a900':
    `<p>Total distance is equal to speed multiplied by time for each activity:</p>` +
    `<ul>` +
    `<li>Walking distance: ${f('2 \\text{ mph} \\times w \\text{ hours} = 2w \\text{ miles}')}</li>` +
    `<li>Running distance: ${f('6 \\text{ mph} \\times r \\text{ hours} = 6r \\text{ miles}')}</li>` +
    `</ul>` +
    `<p>The combined total distance is 10 miles, so:</p>` +
    `<p>${f('2w + 6r = 10')}.</p>`,

  // Q4
  '6a6d61fb14cab24f9785a906':
    `<p>The function ${f('f(x) = 50x + 12')} gives the distance traveled from the station in kilometers, where ${f('x')} is the number of hours after crossing the city border.</p>` +
    `<p>At the instant the train crosses the city border, ${f('x = 0')}:</p>` +
    `<p>${f('f(0) = 50(0) + 12 = 12\\text{ km}')}</p>` +
    `<p>Therefore, 12 represents the estimated total distance the train traveled between the station and the city border.</p>`,

  // Q5
  '6a6d624c14cab24f9785a90a':
    `<p>The given equation is ${f('\\frac{1}{3}(x + 7) - \\frac{1}{2}(x + 7) = -8')}.</p>` +
    `<p>Factor out ${f('(x + 7)')} on the left side:</p>` +
    `<p>${f('\\left(\\frac{1}{3} - \\frac{1}{2}\\right)(x + 7) = -8')}</p>` +
    `<p>${f('\\left(\\frac{2}{6} - \\frac{3}{6}\\right)(x + 7) = -\\frac{1}{6}(x + 7) = -8')}</p>` +
    `<p>Multiply both sides by ${f('-6')}:</p>` +
    `<p>${f('x + 7 = 48 \\implies x = 41')}.</p>`,

  // Q6
  '6a6d627507c5da645a88ca5c':
    `<p>The x-intercept occurs where ${f('g(x) = 0')}:</p>` +
    `<p>${f('\\frac{4}{9}x - 24 = 0')}</p>` +
    `<p>Add 24 to both sides:</p>` +
    `<p>${f('\\frac{4}{9}x = 24')}</p>` +
    `<p>Multiply both sides by ${f('\\frac{9}{4}')}:</p>` +
    `<p>${f('x = 24 \\times \\frac{9}{4} = 6 \\times 9 = 54')}.</p>`,

  // Q7
  '6a6d630a07c5da645a88ca60':
    `<p>In the given graph and context, ${f('x')} represents the points earned by Player 1, and ${f('y')} represents the points earned by Player 2.</p>` +
    `<p>The coordinate pair ${f('(49, 0)')} has ${f('x = 49')} and ${f('y = 0')}.</p>` +
    `<p>Therefore, when Player 1 earns 49 points, Player 2 will earn 0 points.</p>`,

  // Q8
  '6a6d634307c5da645a88ca66':
    `<p>Given expression: ${f('3x^2 - 5x + 6x - 10')}.</p>` +
    `<p>Factor by grouping:</p>` +
    `<p>${f('(3x^2 - 5x) + (6x - 10) = x(3x - 5) + 2(3x - 5)')}</p>` +
    `<p>${f('= (3x - 5)(x + 2)')}</p>` +
    `<p>Thus, ${f('3x - 5')} is a factor of the expression.</p>`,

  // Q9
  '6a6d638807c5da645a88ca7f':
    `<p>The average rate of change between ${f('x = 2')} and ${f('x = 6')} is given by:</p>` +
    `<p>${f('\\frac{y(6) - y(2)}{6 - 2}')}</p>` +
    `<p>From the graph, at ${f('x = 2')}, ${f('y = 3')}$, and at ${f('x = 6')}, ${f('y = 8')}:</p>` +
    `<p>${f('\\text{Average rate of change} = \\frac{8 - 3}{6 - 2} = \\frac{5}{4} = 1.25')}.</p>`,

  // Q10
  '6a6d63c107c5da645a88ca8e':
    `<p>The given equation is ${f('(x + 64)^2 = -100')}.</p>` +
    `<p>For any real number ${f('x')}, the quantity ${f('(x + 64)^2')} must be greater than or equal to 0.</p>` +
    `<p>Since a non-negative real value can never equal the negative value ${f('-100')}, there are no real solutions to this equation.</p>` +
    `<p>Therefore, the number of distinct real solutions is Zero.</p>`,

  // Q11
  '6a6d63e307c5da645a88ca92':
    `<p>The given absolute value equation is ${f('|x - 8| = 11')}.</p>` +
    `<p>This splits into two linear cases:</p>` +
    `<ul>` +
    `<li>Case 1: ${f('x - 8 = 11 \\implies x = 19')}</li>` +
    `<li>Case 2: ${f('x - 8 = -11 \\implies x = -3')}</li>` +
    `</ul>` +
    `<p>The sum of the solutions is:</p>` +
    `<p>${f('19 + (-3) = 16')}.</p>`,

  // Q12
  '6a6d640807c5da645a88ca96':
    `<p>The margin of error in a random sample is inversely proportional to the square root of the sample size ${f('n')}:</p>` +
    `<p>${f('\\text{Margin of Error} \\propto \\frac{1}{\\sqrt{n}}')}</p>` +
    `<p>When the sample size increases from 159 to 318, the larger sample size provides greater precision, which causes the margin of error to be lower.</p>`,

  // Q13
  '6a6d644707c5da645a88ca9a':
    `<p>The original data set contains 11 maximum temperatures.</p>` +
    `<p>The temperature ${f('76.2^\\circ\\text{F}')} lies in the highest bin of the histogram, which is strictly greater than the mean of the 11 temperatures.</p>` +
    `<p>Removing a value that is greater than the mean always decreases the mean of the remaining data set. Thus, Statement I must be true.</p>` +
    `<p>For the median: in the original 11 values, the median is the 6th ordered value. In the new 10 values, the median is the average of the 5th and 6th ordered values. Since both values lie within the same middle frequency bin, the median does not necessarily decrease.</p>` +
    `<p>Therefore, statement I only must be true.</p>`,

  // Q14
  '6a6d64b007c5da645a88ca9e':
    `<p>We are given that:</p>` +
    `<p>${f('0.44h = 0.62j')} and ${f('j = 0.22k')}</p>` +
    `<p>Solve for ${f('h')} in terms of ${f('j')}:</p>` +
    `<p>${f('h = \\frac{0.62}{0.44}j = \\frac{31}{22}j')}</p>` +
    `<p>Substitute ${f('j = 0.22k')}:</p>` +
    `<p>${f('h = \\frac{31}{22}(0.22k) = 31(0.01k) = 0.31k')}</p>` +
    `<p>Since ${f('h = 0.31k')}, ${f('h')} is 31% of ${f('k')}.</p>`,

  // Q15
  '6a6d64ee07c5da645a88caa2':
    `<p>Looking at the graph, the line has an x-intercept at ${f('(90, 0)')} and a y-intercept at ${f('(0, 50)')}.</p>` +
    `<p>Test the equation ${f('10x + 18y = 900')}:</p>` +
    `<ul>` +
    `<li>If ${f('y = 0')}: ${f('10x = 900 \\implies x = 90')}</li>` +
    `<li>If ${f('x = 0')}: ${f('18y = 900 \\implies y = 50')}</li>` +
    `</ul>` +
    `<p>Both intercepts match the graph precisely, so this equation represents the relationship.</p>`,

  // Q16
  '6a6d655607c5da645a88caa6':
    `<p>We are given that ${f('f(1) = k')} and need to find the equivalent form that displays ${f('k')} as either the coefficient or the base.</p>` +
    `<p>Consider the function form ${f('f(x) = 50.4(1.2)^{x-1}')}:</p>` +
    `<p>Evaluating at ${f('x = 1')}:</p>` +
    `<p>${f('f(1) = 50.4(1.2)^{1 - 1} = 50.4(1.2)^0 = 50.4')}</p>` +
    `<p>In this form, the value ${f('f(1) = 50.4')} appears directly as the leading coefficient.</p>`,

  // Q17
  '6a6d65d007c5da645a88caaa':
    `<p>In ${f('\\triangle PQR')}, the interior angles are ${f('\\angle P = (4x + 9)^\\circ')}, ${f('\\angle Q = (5x + 4)^\\circ')}, and ${f('\\angle R = (5y + 4)^\\circ')}.</p>` +
    `<p>Side ${f('QR')} is extended to point ${f('S')}, making ${f('\\angle PRS')} an exterior angle at vertex ${f('R')}.</p>` +
    `<p>By the exterior angle theorem, the exterior angle equals the sum of the two remote interior angles:</p>` +
    `<p>${f('\\angle PRS = \\angle P + \\angle Q')}</p>` +
    `<p>${f('x + y = (4x + 9) + (5x + 4) = 9x + 13 \\implies y = 8x + 13')}</p>` +
    `<p>Since ${f('\\angle PRQ')} and ${f('\\angle PRS')} form a linear pair on line ${f('QRS')}:</p>` +
    `<p>${f('(5y + 4) + (x + y) = 180 \\implies x + 6y + 4 = 180 \\implies x + 6y = 176')}</p>` +
    `<p>Substitute ${f('y = 8x + 13')}:</p>` +
    `<p>${f('x + 6(8x + 13) = 176 \\implies x + 48x + 78 = 176 \\implies 49x = 98 \\implies x = 2')}</p>` +
    `<p>Now find ${f('y')}:</p>` +
    `<p>${f('y = 8(2) + 13 = 16 + 13 = 29')}</p>` +
    `<p>Therefore, ${f('x + y = 2 + 29 = 31')}.</p>`,

  // Q18
  '6a6d662f07c5da645a88cab0':
    `<p>According to the triangle inequality theorem, the third side ${f('x')} must be strictly greater than the difference and strictly less than the sum of the other two sides:</p>` +
    `<p>${f('|9 - 5| < x < 9 + 5')}</p>` +
    `<p>${f('4 < x < 14')}.</p>`,

  // Q19
  '6a6d666f07c5da645a88cab4':
    `<p>The area of the base of the cone is given by ${f('B = \\pi r^2 = 3{,}136\\pi')}.</p>` +
    `<p>${f('r^2 = 3{,}136 \\implies r = \\sqrt{3{,}136} = 56\\text{ cm}')}</p>` +
    `<p>The volume of a cone is ${f('V = \\frac{1}{3}Bh')}:</p>` +
    `<p>${f('34{,}496\\pi = \\frac{1}{3}(3{,}136\\pi)h \\implies h = \\frac{3 \\times 34{,}496}{3{,}136} = 33\\text{ cm}')}</p>` +
    `<p>The slant height ${f('l')} is the hypotenuse of the right triangle formed by the radius and height:</p>` +
    `<p>${f('l = \\sqrt{r^2 + h^2} = \\sqrt{56^2 + 33^2} = \\sqrt{3{,}136 + 1{,}089} = \\sqrt{4{,}225} = 65\\text{ cm}')}.</p>`,

  // Q20
  '6a6d668d07c5da645a88caba':
    `<p>The quadratic model reaches its maximum height of 400 feet at ${f('t = 5')} seconds, so its vertex is at ${f('(5, 400)')}.</p>` +
    `<p>In vertex form, the height is given by:</p>` +
    `<p>${f('h(t) = a(t - 5)^2 + 400')}</p>` +
    `<p>Since the object launched from ground level (${f('h(0) = 0')}):</p>` +
    `<p>${f('a(0 - 5)^2 + 400 = 0 \\implies 25a = -400 \\implies a = -16')}</p>` +
    `<p>Thus, the height equation is ${f('h(t) = -16(t - 5)^2 + 400')}.</p>` +
    `<p>At ${f('t = 9')} seconds:</p>` +
    `<p>${f('h(9) = -16(9 - 5)^2 + 400 = -16(4^2) + 400 = -16(16) + 400 = -256 + 400 = 144\\text{ feet}')}.</p>`,

  // Q21
  '6a6d66fc07c5da645a88cabe':
    `<p>The rental cost consists of a 56 USD base charge for the first day, plus 28 USD for each of the remaining ${f('(d - 1)')} days:</p>` +
    `<p>${f('C(d) = 56 + 28(d - 1)')}</p>` +
    `<p>Distribute and simplify:</p>` +
    `<p>${f('C(d) = 56 + 28d - 28 = 28d + 28')}.</p>`,

  // Q22
  '6a6d676a07c5da645a88cac2':
    `<p>The quadratic function ${f('f(x) = ax^2 + bx + c')} has x-intercepts at ${f('(8, 0)')} and ${f('(-5, 0)')}.</p>` +
    `<p>Therefore, its factored form is:</p>` +
    `<p>${f('f(x) = a(x - 8)(x + 5) = a(x^2 - 3x - 40) = ax^2 - 3ax - 40a')}</p>` +
    `<p>Comparing coefficients with ${f('ax^2 + bx + c')}:</p>` +
    `<p>${f('b = -3a')}</p>` +
    `<p>We are asked to find the value of ${f('a + b')}:</p>` +
    `<p>${f('a + b = a + (-3a) = -2a')}</p>` +
    `<p>We are given that ${f('a')} is an integer greater than 1 (${f('a \\in \\{2, 3, 4, \\dots\\}')}).</p>` +
    `<ul>` +
    `<li>If ${f('a = 2')}, ${f('a + b = -2(2) = -4')}</li>` +
    `<li>If ${f('a = 3')}, ${f('a + b = -2(3) = -6')}</li>` +
    `</ul>` +
    `<p>Among the given answer choices, ${f('-4')} is the only possible value.</p>`
};

async function main() {
  console.log('Injecting June 2025 · INT 2 M2 Explanations...');
  for (const [id, expl] of Object.entries(explanations)) {
    const res = await updateQuestion(id, { explanation: expl });
    console.log(`Updated ${id}:`, res.message || res);
  }
  console.log('Finished June 2025 · INT 2 M2!');
}

main().catch(console.error);
