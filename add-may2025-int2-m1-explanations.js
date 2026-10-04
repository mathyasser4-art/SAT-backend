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
  '6a9b35b0111ffc76c2e61f50': `<p>To find the measure of angle ${f('\\angle C')} in ${f('\\Delta ABC')}:</p>
<ol>
  <li>The sum of interior angles in any triangle is ${f('180^\\circ')}:
    <p>${f('\\angle A + \\angle B + \\angle C = 180^\\circ')}</p>
  </li>
  <li>Substitute the given angle measures ${f('\\angle A = 34^\\circ')} and ${f('\\angle B = 90^\\circ')}:
    <p>${f('34^\\circ + 90^\\circ + \\angle C = 180^\\circ')}</p>
  </li>
  <li>Combine the known angles and solve for ${f('\\angle C')}:
    <p>${f('124^\\circ + \\angle C = 180^\\circ \\implies \\angle C = 180^\\circ - 124^\\circ = 56^\\circ')}</p>
  </li>
</ol>
<p>Thus, the measure of angle ${f('\\angle C')} is <strong>56</strong> degrees.</p>`,

  // Q2
  '6a9b3616111ffc76c2e62025': `<p>To find the equivalent expression for ${f('3xy(2x^2 + 7y)')}:</p>
<ol>
  <li>Apply the distributive property by multiplying ${f('3xy')} by each term inside the parentheses:
    <p>${f('3xy(2x^2 + 7y) = (3xy)(2x^2) + (3xy)(7y)')}</p>
  </li>
  <li>Multiply the coefficients and combine powers of ${f('x')} and ${f('y')}:
    <ul>
      <li>First term: ${f('(3 \\times 2)(x \\cdot x^2)(y) = 6x^3y')}</li>
      <li>Second term: ${f('(3 \\times 7)(x)(y \\cdot y) = 21xy^2')}</li>
    </ul>
  </li>
  <li>Add the resulting terms:
    <p>${f('6x^3y + 21xy^2')}</p>
  </li>
</ol>
<p>Thus, the equivalent expression is <strong>${f('6x^3y + 21xy^2')}</strong>.</p>`,

  // Q3
  '6a9b365b111ffc76c2e62104': `<p>To find the equivalent factored form of ${f('30x^2 + 6x + 6')}:</p>
<ol>
  <li>Identify the greatest common factor (GCF) of the coefficients 30, 6, and 6.</li>
  <li>The greatest common divisor of 30, 6, and 6 is 6.</li>
  <li>Factor out 6 from each term:
    <p>${f('30x^2 + 6x + 6 = 6(5x^2 + x + 1)')}</p>
  </li>
</ol>
<p>Thus, the equivalent expression is <strong>${f('6(5x^2 + x + 1)')}</strong>.</p>`,

  // Q4
  '6a9b36a6111ffc76c2e62121': `<p>To calculate the maximum number of trees that can be planted:</p>
<ol>
  <li>The recommended maximum planting density is 92 trees per acre.</li>
  <li>We have 2 acres of land available.</li>
  <li>Multiply the rate per acre by the number of acres:
    <p>${f('\\text{Total Trees} = 92 \\times 2 = 184')}</p>
  </li>
</ol>
<p>Thus, the maximum number of trees that can be planted is <strong>184</strong>.</p>`,

  // Q5
  '6a9b381d111ffc76c2e622a8': `<p>To find the number of months until total charges equal $178:</p>
<ol>
  <li>Let ${f('m')} be the number of months.</li>
  <li>The total cost consists of a one-time $34 enrollment fee plus $16 per month:
    <p>${f('34 + 16m = 178')}</p>
  </li>
  <li>Subtract 34 from both sides:
    <p>${f('16m = 178 - 34 = 144')}</p>
  </li>
  <li>Divide by 16:
    <p>${f('m = \\frac{144}{16} = 9')}</p>
  </li>
</ol>
<p>Thus, the member will have been charged $178 after <strong>9</strong> months.</p>`,

  // Q6
  '6a9b39c7111ffc76c2e62593': `<p>To interpret the constant 9 in ${f('f(t) = 14t + 9')}:</p>
<ol>
  <li>In a linear model ${f('f(t) = mt + b')}, the constant ${f('b')} is the y-intercept, which represents the value of the function when ${f('t = 0')}.</li>
  <li>Here, ${f('t = 0')} corresponds to the moment Shruti purchased the pothos plant.</li>
  <li>Evaluating ${f('f(0) = 14(0) + 9 = 9')} inches gives the initial length of the plant.</li>
</ol>
<p>Thus, the best interpretation is: <strong>The estimated length of the pothos plant was 9 inches when Shruti purchased it.</strong></p>`,

  // Q7
  '6a9b3a64111ffc76c2e6260c': `<p>To find the number of visitors located in room C:</p>
<ol>
  <li>The total number of visitors is 375.</li>
  <li>Since every visitor is in either room A, room B, or room C, the sum of probabilities must equal 1:
    <p>${f('P(A) + P(B) + P(C) = 1')}</p>
  </li>
  <li>Substitute the known probabilities:
    <p>${f('0.48 + 0.24 + P(C) = 1 \\implies 0.72 + P(C) = 1 \\implies P(C) = 0.28')}</p>
  </li>
  <li>Calculate the number of visitors in room C:
    <p>${f('\\text{Number in room C} = 0.28 \\times 375 = 105')}</p>
  </li>
</ol>
<p>Thus, there are <strong>105</strong> visitors in room C.</p>`,

  // Q8
  '6a9b3af6111ffc76c2e62787': `<p>To solve the quadratic equation ${f('x^2 - 28x = 0')}:</p>
<ol>
  <li>Factor out the common term ${f('x')}:
    <p>${f('x(x - 28) = 0')}</p>
  </li>
  <li>Set each factor equal to zero:
    <p>${f('x = 0')} or ${f('x - 28 = 0 \\implies x = 28')}</p>
  </li>
  <li>Among the given options (56, 28, 14, and ${f('\\sqrt{28}')}), 28 is a solution.</li>
</ol>
<p>Thus, a solution to the equation is <strong>28</strong>.</p>`,

  // Q9
  '6a9b3b40111ffc76c2e627c7': `<p>To find the perimeter of the base of the right square pyramid:</p>
<ol>
  <li>The volume formula for a pyramid is:
    <p>${f('V = \\frac{1}{3}Bh')}</p>
    where ${f('B')} is the base area and ${f('h = 12\\text{ inches}')}.
  </li>
  <li>Substitute ${f('V = 196')} and ${f('h = 12')}:
    <p>${f('196 = \\frac{1}{3}B(12) = 4B \\implies B = \\frac{196}{4} = 49\\text{ square inches}')}</p>
  </li>
  <li>Since the base is a square, the side length ${f('s')} is:
    <p>${f('s = \\sqrt{49} = 7\\text{ inches}')}</p>
  </li>
  <li>Calculate the perimeter of the square base:
    <p>${f('\\text{Perimeter} = 4s = 4(7) = 28\\text{ inches}')}</p>
  </li>
</ol>
<p>Thus, the perimeter of the base is <strong>28</strong> inches.</p>`,

  // Q10
  '6a9b3db7111ffc76c2e62d51': `<p>To find the function giving the value of the share of stock:</p>
<ol>
  <li>The initial value at ${f('t = 0')} is $240.</li>
  <li>Each year, the value increases by 1% of its value the previous year, which represents exponential growth with growth factor:
    <p>${f('1 + r = 1 + 0.01 = 1.01')}</p>
  </li>
  <li>After ${f('t')} years, the value is given by:
    <p>${f('V(t) = 240(1.01)^t')}</p>
  </li>
</ol>
<p>Thus, the correct function is <strong>${f('V(t) = 240(1.01)^t')}</strong>.</p>`,

  // Q11
  '6a9b3e2c111ffc76c2e62d57': `<p>To evaluate ${f('6f(3) - g(3)')}:</p>
<ol>
  <li>Given ${f('f(x) = x + 3')}, find ${f('f(3)')}:
    <p>${f('f(3) = 3 + 3 = 6')}</p>
  </li>
  <li>Given ${f('g(x) = 3x')}, find ${f('g(3)')}:
    <p>${f('g(3) = 3(3) = 9')}</p>
  </li>
  <li>Substitute into the given expression:
    <p>${f('6f(3) - g(3) = 6(6) - 9 = 36 - 9 = 27')}</p>
  </li>
</ol>
<p>Thus, the value of the expression is <strong>27</strong>.</p>`,

  // Q12
  '6a9b3e81111ffc76c2e62d5d': `<p>To find the value of ${f('r')} for infinitely many solutions:</p>
<ol>
  <li>A system of two linear equations has infinitely many solutions if one equation is a non-zero constant multiple of the other.</li>
  <li>Multiply the first equation ${f('3x + 9y = 10')} by 2:
    <p>${f('2(3x + 9y) = 2(10) \\implies 6x + 18y = 20')}</p>
  </li>
  <li>Comparing this with the second equation ${f('rx + 18y = 20')}, the y-coefficients (18) and constant terms (20) match, so the x-coefficients must also be equal:
    <p>${f('r = 6')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('r')} is <strong>6</strong>.</p>`,

  // Q13
  '6a9b3eb5111ffc76c2e62d63': `<p>To find the estimated revenue when tote bags are priced at $12 each:</p>
<ol>
  <li>At the baseline price of $9, the club expects to sell 80 bags.</li>
  <li>The price increases from $9 to $12, which is an increase of:
    <p>${f('12 - 9 = 3\\text{ dollars}')}</p>
  </li>
  <li>For each $1 price increase, 8 fewer bags are sold. For a $3 increase:
    <p>${f('3 \\times 8 = 24\\text{ fewer bags sold}')}</p>
  </li>
  <li>The number of bags sold at $12 is:
    <p>${f('80 - 24 = 56\\text{ bags}')}</p>
  </li>
  <li>Calculate total revenue:
    <p>${f('\\text{Revenue} = \\text{Price} \\times \\text{Quantity} = 12 \\times 56 = 672\\text{ dollars}')}</p>
  </li>
</ol>
<p>Thus, the estimated revenue is <strong>672</strong> dollars.</p>`,

  // Q14
  '6a9b3f09111ffc76c2e62d69': `<p>To find the value of ${f('2y')} from the system of equations:</p>
<ol>
  <li>We have:
    <p>${f('3x + 6y = 17')}</p>
    <p>${f('-3x - 4y = 5')}</p>
  </li>
  <li>Add the two equations directly to eliminate ${f('x')}:
    <p>${f('(3x - 3x) + (6y - 4y) = 17 + 5')}</p>
    <p>${f('2y = 22')}</p>
  </li>
  <li>Notice that the question asks directly for the value of ${f('2y')}.</li>
</ol>
<p>Thus, the value of ${f('2y')} is <strong>22</strong>.</p>`,

  // Q15
  '6a9b3f5a111ffc76c2e62d72': `<p>To solve the equation ${f('0.7w - 0.57 = 7(w - 0.001)')}:</p>
<ol>
  <li>Distribute 7 on the right side:
    <p>${f('0.7w - 0.57 = 7w - 0.007')}</p>
  </li>
  <li>Rearrange terms by gathering all ${f('w')} terms on the right side and constants on the left side:
    <p>${f('-0.57 + 0.007 = 7w - 0.7w')}</p>
    <p>${f('-0.563 = 6.3w')}</p>
  </li>
  <li>Solve for ${f('w')}:
    <p>${f('w = -\\frac{0.563}{6.3} = -\\frac{563}{6300}')}</p>
  </li>
</ol>
<p>Thus, the solution is <strong>${f('-\\frac{563}{6300}')}</strong>.</p>`,

  // Q16
  '6a9b4019111ffc76c2e62f16': `<p>To find the quadratic equation that has exactly one distinct real solution:</p>
<ol>
  <li>A quadratic equation ${f('ax^2 + bx + c = 0')} has exactly one distinct real solution when its discriminant is zero:
    <p>${f('\\Delta = b^2 - 4ac = 0')}</p>
    This occurs when the quadratic is a perfect square trinomial.
  </li>
  <li>Test each option:
    <ul>
      <li>${f('x^2 - 16 = 0 \\implies x = \\pm 4')} (two solutions)</li>
      <li>${f('x^2 + 16 = 0 \\implies x = \\pm 4i')} (no real solutions)</li>
      <li>${f('x^2 - 16x + 56 = 0 \\implies \\Delta = (-16)^2 - 4(1)(56) = 256 - 224 = 32 > 0')} (two solutions)</li>
      <li>${f('x^2 - 16x + 64 = 0 \\implies (x - 8)^2 = 0 \\implies x = 8')} (exactly one distinct real solution)</li>
    </ul>
  </li>
</ol>
<p>Thus, the correct equation is <strong>${f('x^2 - 16x + 64 = 0')}</strong>.</p>`,

  // Q17
  '6a9b4165111ffc76c2e6315b': `<p>To find the value of ${f('b')} in ${f('f(x) = 7x + b')}:</p>
<ol>
  <li>We are given ${f('f(8) = 56')}.</li>
  <li>Substitute ${f('x = 8')} into the function:
    <p>${f('f(8) = 7(8) + b = 56')}</p>
  </li>
  <li>Simplify and solve for ${f('b')}:
    <p>${f('56 + b = 56 \\implies b = 56 - 56 = 0')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('b')} is <strong>0</strong>.</p>`,

  // Q18
  '6a9b41c1111ffc76c2e63219': `<p>To interpret the distance-time graph:</p>
<ol>
  <li>From ${f('t = 0')} to ${f('t = 1')}: The graph is a line segment rising from ${f('0')} to ${f('60')} miles at a constant slope of 60 mph, meaning Quinidra drove away from home at a constant speed for 1 hour.</li>
  <li>From ${f('t = 1')} to ${f('t = 5')}: The graph is a flat horizontal line at distance 60 miles for 4 hours, meaning she remained stationary at the location.</li>
  <li>From ${f('t = 5')} to ${f('t = 6')}: The graph is a line segment descending from ${f('60')} back to ${f('0')} miles at a constant slope of -60 mph, meaning she drove back to her home at a constant speed for 1 hour.</li>
</ol>
<p>Thus, the model describes: <strong>Quinidra drove away from her home at a constant speed for 1 hour; spent 4 hours at the location, then drove back to her home at a constant speed for 1 hour.</strong></p>`,

  // Q19
  '6a9b4300111ffc76c2e634a8': `<p>To find the mean mass of the 35 objects:</p>
<ol>
  <li>Multiply each mass by its corresponding frequency to find the total mass for each group:
    <ul>
      <li>${f('10 \\times 12 = 120\\text{ grams}')}</li>
      <li>${f('20 \\times 6 = 120\\text{ grams}')}</li>
      <li>${f('30 \\times 8 = 240\\text{ grams}')}</li>
      <li>${f('40 \\times 9 = 360\\text{ grams}')}</li>
    </ul>
  </li>
  <li>Sum the products to obtain the total mass of all objects:
    <p>${f('\\text{Total Mass} = 120 + 120 + 240 + 360 = 840\\text{ grams}')}</p>
  </li>
  <li>Divide by the total number of objects (35):
    <p>${f('\\text{Mean} = \\frac{840}{35} = 24\\text{ grams}')}</p>
  </li>
</ol>
<p>Thus, the mean mass is <strong>24</strong> grams.</p>`,

  // Q20
  '6a9b441f111ffc76c2e638ac': `<p>To find the y-intercept of ${f('y = -(4)^x - 39')}:</p>
<ol>
  <li>The y-intercept occurs where ${f('x = 0')}.</li>
  <li>Substitute ${f('x = 0')} into the equation:
    <p>${f('y = -(4)^0 - 39')}</p>
  </li>
  <li>Recall that ${f('4^0 = 1')}:
    <p>${f('y = -(1) - 39 = -40')}</p>
  </li>
  <li>The coordinates are ${f('(0, -40)')}.</li>
</ol>
<p>Thus, the y-intercept is <strong>(0, -40)</strong>.</p>`,

  // Q21
  '6a9b4462111ffc76c2e639f7': `<p>To find the area of the enlarged poster copy:</p>
<ol>
  <li>The original area of the poster is ${f('A = 330\\text{ in}^2')}.</li>
  <li>The length and width are each increased by 50%, which scales every linear dimension by a factor of:
    <p>${f('1 + 0.50 = 1.5')}</p>
  </li>
  <li>Area scales by the square of the linear scale factor:
    <p>${f('A_{\\text{copy}} = A \\times (1.5)^2 = 330 \\times 2.25 = 742.5\\text{ in}^2')}</p>
  </li>
  <li>Expressed as a simplified fraction:
    <p>${f('742.5 = \\frac{1485}{2}')}</p>
  </li>
</ol>
<p>Thus, the area of the copy is <strong>${f('\\frac{1485}{2}')}</strong> (or <strong>742.5</strong>) square inches.</p>`,

  // Q22
  '6a9b4498111ffc76c2e63a62': `<p>To find the radius of the circle:</p>
<ol>
  <li>The circle has center ${f('(h, k) = (28, 5)')} and passes through y-intercepts ${f('(0, -16)')} and ${f('(0, 26)')}.</li>
  <li>The radius ${f('r')} is the Euclidean distance from the center to any point on the circle.</li>
  <li>Using point ${f('(0, 26)')}:
    <p>${f('r^2 = (28 - 0)^2 + (5 - 26)^2')}</p>
    <p>${f('r^2 = 28^2 + (-21)^2 = 784 + 441 = 1{,}225')}</p>
  </li>
  <li>Take the square root:
    <p>${f('r = \\sqrt{1{,}225} = 35')}</p>
  </li>
</ol>
<p>Thus, the radius of the circle is <strong>35</strong>.</p>`
};

async function run() {
  console.log('Injecting 22 pedagogical explanations for May 2025 · INT 2 Module 1...\n');
  let count = 0;
  for (const [id, expl] of Object.entries(explanations)) {
    process.stdout.write(`Updating Q ${id} (${++count}/22)... `);
    await updateQuestion(id, { explanation: expl });
    console.log('✅');
  }
  console.log('\n🎉 Successfully injected all 22 M1 explanations!');
}

run().catch(console.error);
