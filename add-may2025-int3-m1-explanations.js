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
  '6a9c1aad4471c51d35c19de1': `<p>To find the measure of angle ${f('\\angle C')} in ${f('\\Delta ABC')}:</p>
<ol>
  <li>The sum of interior angles in any triangle is ${f('180^\\circ')}:
    <p>${f('\\angle A + \\angle B + \\angle C = 180^\\circ')}</p>
  </li>
  <li>Substitute ${f('\\angle A = 34^\\circ')} and ${f('\\angle B = 90^\\circ')}:
    <p>${f('34^\\circ + 90^\\circ + \\angle C = 180^\\circ')}</p>
  </li>
  <li>Combine and solve for ${f('\\angle C')}:
    <p>${f('124^\\circ + \\angle C = 180^\\circ \\implies \\angle C = 180^\\circ - 124^\\circ = 56^\\circ')}</p>
  </li>
</ol>
<p>Thus, the measure of angle ${f('\\angle C')} is <strong>${f('56^\\circ')}</strong>.</p>`,

  // Q2
  '6a9c1aef4471c51d35c19de7': `<p>To expand the algebraic expression ${f('3xy(2x^2 + 7y)')}:</p>
<ol>
  <li>Distribute ${f('3xy')} to both terms inside the parentheses:
    <p>${f('3xy(2x^2 + 7y) = (3xy)(2x^2) + (3xy)(7y)')}</p>
  </li>
  <li>Multiply coefficients and apply the product rule for exponents:
    <ul>
      <li>${f('(3 \\times 2)(x \\cdot x^2)(y) = 6x^3y')}</li>
      <li>${f('(3 \\times 7)(x)(y \\cdot y) = 21xy^2')}</li>
    </ul>
  </li>
  <li>Combine the terms:
    <p>${f('6x^3y + 21xy^2')}</p>
  </li>
</ol>
<p>Thus, the equivalent expression is <strong>${f('6x^3y + 21xy^2')}</strong>.</p>`,

  // Q3
  '6a9c1b294471c51d35c19ded': `<p>To factor the expression ${f('30x^2 + 6x + 6')}:</p>
<ol>
  <li>Determine the greatest common factor (GCF) of the terms 30, 6, and 6.</li>
  <li>The greatest common divisor is 6.</li>
  <li>Factor out 6 from the expression:
    <p>${f('30x^2 + 6x + 6 = 6(5x^2 + x + 1)')}</p>
  </li>
</ol>
<p>Thus, the equivalent expression is <strong>${f('6(5x^2 + x + 1)')}</strong>.</p>`,

  // Q4
  '6a9c1b5d4471c51d35c19df3': `<p>To find the maximum number of trees that can be planted:</p>
<ol>
  <li>The recommended planting density is at most 92 trees per acre.</li>
  <li>For an area of 2 acres:
    <p>${f('\\text{Maximum Trees} = 92 \\times 2 = 184')}</p>
  </li>
</ol>
<p>Thus, the maximum number of trees that can be planted is <strong>184</strong>.</p>`,

  // Q5
  '6a9c1b744471c51d35c19df9': `<p>To calculate the number of months of gym membership:</p>
<ol>
  <li>Let ${f('m')} represent the number of months.</li>
  <li>The total cost equation is:
    <p>${f('34 + 16m = 178')}</p>
  </li>
  <li>Subtract the enrollment fee:
    <p>${f('16m = 178 - 34 = 144')}</p>
  </li>
  <li>Divide by the monthly fee:
    <p>${f('m = \\frac{144}{16} = 9')}</p>
  </li>
</ol>
<p>Thus, the member has been charged for <strong>9</strong> months.</p>`,

  // Q6
  '6a9c1bb24471c51d35c19dff': `<p>To find the value of ${f('b')} in ${f('f(x) = 7x + b')}:</p>
<ol>
  <li>We are given that ${f('f(8) = 56')}.</li>
  <li>Substitute ${f('x = 8')} into the function:
    <p>${f('f(8) = 7(8) + b = 56')}</p>
  </li>
  <li>Simplify:
    <p>${f('56 + b = 56 \\implies b = 0')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('b')} is <strong>0</strong>.</p>`,

  // Q7
  '6a9c1c014471c51d35c19e05': `<p>To interpret the constant 9 in the linear function ${f('f(t) = 14t + 9')}:</p>
<ol>
  <li>In the context of the problem, ${f('t')} is the time in months since purchase, and ${f('f(t)')} is the estimated plant length in inches.</li>
  <li>When ${f('t = 0')} (at the time of purchase):
    <p>${f('f(0) = 14(0) + 9 = 9\\text{ inches}')}</p>
  </li>
  <li>Therefore, 9 represents the initial length of the plant.</li>
</ol>
<p>Thus, the best interpretation is: <strong>The estimated length of the pothos plant was 9 inches when Shruti purchased it.</strong></p>`,

  // Q8
  '6a9c1c2c4471c51d35c19e0b': `<p>To find the number of visitors in room C:</p>
<ol>
  <li>The total number of visitors is 375.</li>
  <li>The total probability across all three mutually exclusive rooms is 1:
    <p>${f('P(A) + P(B) + P(C) = 1')}</p>
  </li>
  <li>Substitute the known probabilities:
    <p>${f('0.48 + 0.24 + P(C) = 1 \\implies 0.72 + P(C) = 1 \\implies P(C) = 0.28')}</p>
  </li>
  <li>Multiply the probability by the total number of visitors:
    <p>${f('\\text{Visitors in room C} = 0.28 \\times 375 = 105')}</p>
  </li>
</ol>
<p>Thus, there are <strong>105</strong> visitors in room C.</p>`,

  // Q9
  '6a9c1c694471c51d35c19e11': `<p>To solve the quadratic equation ${f('x^2 - 28x = 0')}:</p>
<ol>
  <li>Factor out ${f('x')}:
    <p>${f('x(x - 28) = 0')}</p>
  </li>
  <li>Set each factor to zero:
    <p>${f('x = 0')} or ${f('x = 28')}</p>
  </li>
  <li>Among the options, 28 is a solution.</li>
</ol>
<p>Thus, a solution to the equation is <strong>28</strong>.</p>`,

  // Q10
  '6a9c1c854471c51d35c19e17': `<p>To find the perimeter of the base of the right square pyramid:</p>
<ol>
  <li>The volume of a pyramid is ${f('V = \\frac{1}{3}Bh')}, with ${f('h = 12')} and ${f('V = 196')}.</li>
  <li>Calculate the base area ${f('B')}:
    <p>${f('196 = \\frac{1}{3}B(12) = 4B \\implies B = 49\\text{ in}^2')}</p>
  </li>
  <li>The base is a square, so its edge length is:
    <p>${f('s = \\sqrt{49} = 7\\text{ inches}')}</p>
  </li>
  <li>Find the perimeter:
    <p>${f('\\text{Perimeter} = 4s = 4(7) = 28\\text{ inches}')}</p>
  </li>
</ol>
<p>Thus, the perimeter of the base is <strong>28</strong> inches.</p>`,

  // Q11
  '6a9c1e6a4471c51d35c19f68': `<p>To evaluate ${f('6f(3) - g(3)')}:</p>
<ol>
  <li>Given ${f('f(x) = x + 3')}:
    <p>${f('f(3) = 3 + 3 = 6')}</p>
  </li>
  <li>Given ${f('g(x) = 3x')}:
    <p>${f('g(3) = 3(3) = 9')}</p>
  </li>
  <li>Compute:
    <p>${f('6f(3) - g(3) = 6(6) - 9 = 36 - 9 = 27')}</p>
  </li>
</ol>
<p>Thus, the value of the expression is <strong>27</strong>.</p>`,

  // Q12
  '6a9c1ebc4471c51d35c19fa8': `<p>To find the value of ${f('r')} for infinitely many solutions:</p>
<ol>
  <li>The system has infinitely many solutions when the two equations represent identical lines.</li>
  <li>Multiply the first equation ${f('3x + 9y = 10')} by 2:
    <p>${f('6x + 18y = 20')}</p>
  </li>
  <li>Compare this to the second equation ${f('rx + 18y = 20')}:
    <p>${f('r = 6')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('r')} is <strong>6</strong>.</p>`,

  // Q13
  '6a9c1ee54471c51d35c19fae': `<p>To find the revenue when tote bags are sold for $12 each:</p>
<ol>
  <li>The baseline price is $9 with 80 bags sold.</li>
  <li>The price increases by ${f('12 - 9 = 3')} dollars.</li>
  <li>Sales drop by 8 bags per dollar increase:
    <p>${f('3 \\times 8 = 24\\text{ fewer bags sold}')}</p>
  </li>
  <li>Number of bags sold at $12:
    <p>${f('80 - 24 = 56\\text{ bags}')}</p>
  </li>
  <li>Total revenue:
    <p>${f('\\text{Revenue} = 12 \\times 56 = 672\\text{ dollars}')}</p>
  </li>
</ol>
<p>Thus, the estimated revenue is <strong>672</strong> dollars.</p>`,

  // Q14
  '6a9c1f3a4471c51d35c19fb4': `<p>To solve for ${f('2y')}:</p>
<ol>
  <li>Given the system:
    <p>${f('3x + 6y = 17')}</p>
    <p>${f('-3x - 4y = 5')}</p>
  </li>
  <li>Add both equations to eliminate ${f('x')}:
    <p>${f('(3x - 3x) + (6y - 4y) = 17 + 5')}</p>
    <p>${f('2y = 22')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('2y')} is <strong>22</strong>.</p>`,

  // Q15
  '6a9c1f714471c51d35c19fba': `<p>To solve ${f('0.7w - 0.57 = 7(w - 0.001)')}:</p>
<ol>
  <li>Expand the right side:
    <p>${f('0.7w - 0.57 = 7w - 0.007')}</p>
  </li>
  <li>Rearrange terms:
    <p>${f('-0.57 + 0.007 = 7w - 0.7w')}</p>
    <p>${f('-0.563 = 6.3w')}</p>
  </li>
  <li>Solve for ${f('w')}:
    <p>${f('w = -\\frac{0.563}{6.3} = -\\frac{563}{6300}')}</p>
  </li>
</ol>
<p>Thus, the solution is <strong>${f('-\\frac{563}{6300}')}</strong>.</p>`,

  // Q16
  '6a9c1fc34471c51d35c19fc0': `<p>To identify the quadratic equation with exactly one distinct real solution:</p>
<ol>
  <li>A quadratic equation has exactly one distinct real solution if and only if its discriminant is zero:
    <p>${f('\\Delta = b^2 - 4ac = 0')}</p>
    which means the equation is a perfect square.
  </li>
  <li>For ${f('x^2 - 16x + 64 = 0')}:
    <p>${f('(x - 8)^2 = 0 \\implies x = 8')}</p>
    This has exactly one distinct real solution.
  </li>
</ol>
<p>Thus, the correct equation is <strong>${f('x^2 - 16x + 64 = 0')}</strong>.</p>`,

  // Q17
  '6a9c201f4471c51d35c19fc6': `<p>To interpret the graph of distance versus time:</p>
<ol>
  <li>From ${f('t = 0')} to ${f('t = 1')}, the distance increases steadily from 0 to 60 miles.</li>
  <li>From ${f('t = 1')} to ${f('t = 5')}, the distance remains constant at 60 miles, indicating Quinidra stayed at that location.</li>
  <li>From ${f('t = 5')} to ${f('t = 6')}, the distance drops steadily from 60 miles back down to 0 miles, indicating she returned home.</li>
</ol>
<p>Thus, the model describes: <strong>Quinidra drove 60 miles from her home and then returned home.</strong></p>`,

  // Q18
  '6a9c207c4471c51d35c19fcc': `<p>To find the mean mass of the 35 objects:</p>
<ol>
  <li>Calculate total mass for each row:
    <ul>
      <li>${f('10 \\times 12 = 120')}</li>
      <li>${f('20 \\times 6 = 120')}</li>
      <li>${f('30 \\times 8 = 240')}</li>
      <li>${f('40 \\times 9 = 360')}</li>
    </ul>
  </li>
  <li>Sum the masses:
    <p>${f('\\text{Total Mass} = 120 + 120 + 240 + 360 = 840\\text{ grams}')}</p>
  </li>
  <li>Divide by total count (35):
    <p>${f('\\text{Mean} = \\frac{840}{35} = 24\\text{ grams}')}</p>
  </li>
</ol>
<p>Thus, the mean mass is <strong>24</strong> grams.</p>`,

  // Q19
  '6a9c20c84471c51d35c19fd2': `<p>To find the y-intercept of ${f('y = -(4)^x - 39')}:</p>
<ol>
  <li>Set ${f('x = 0')}:
    <p>${f('y = -(4)^0 - 39')}</p>
  </li>
  <li>Since ${f('4^0 = 1')}:
    <p>${f('y = -(1) - 39 = -40')}</p>
  </li>
  <li>The point is ${f('(0, -40)')}.</li>
</ol>
<p>Thus, the y-intercept is <strong>(0, -40)</strong>.</p>`,

  // Q20
  '6a9c20f64471c51d35c19fd8': `<p>To find the area of the enlarged poster copy:</p>
<ol>
  <li>The original area is ${f('A = 330\\text{ in}^2')}.</li>
  <li>Increasing length and width by 50% gives a scale factor of ${f('k = 1.5')}.</li>
  <li>Area scales by ${f('k^2')}:
    <p>${f('A_{\\text{copy}} = 330 \\times (1.5)^2 = 330 \\times 2.25 = 742.5\\text{ in}^2')}</p>
  </li>
  <li>In fractional form:
    <p>${f('742.5 = \\frac{1485}{2}')}</p>
  </li>
</ol>
<p>Thus, the area of the copy is <strong>${f('\\frac{1485}{2}')}</strong> (or <strong>742.5</strong>) square inches.</p>`,

  // Q21
  '6aa0deebdf63ca493d479911': `<p>To convert the area of the town from square miles to square yards:</p>
<ol>
  <li>We are given the linear conversion ${f('1\\text{ mile} = 1{,}760\\text{ yards}')}.</li>
  <li>Square both sides to find the area conversion factor:
    <p>${f('1\\text{ square mile} = (1{,}760\\text{ yards})^2 = 3{,}097{,}600\\text{ square yards}')}</p>
  </li>
  <li>Multiply by the given area of 5.48 square miles:
    <p>${f('\\text{Area} = 5.48 \\times 3{,}097{,}600 = 16{,}974{,}848\\text{ square yards}')}</p>
  </li>
</ol>
<p>Thus, the area of the town is <strong>16,974,848</strong> square yards.</p>`,

  // Q22
  '6aa0df7edf63ca493d479917': `<p>To find the average of data set B:</p>
<ol>
  <li>The combined data sets have 56 values with an overall average of 193:
    <p>${f('\\text{Total Sum} = 56 \\times 193 = 10{,}808')}</p>
  </li>
  <li>Data set A has 32 values with an average of 208:
    <p>${f('\\text{Sum of A} = 32 \\times 208 = 6{,}656')}</p>
  </li>
  <li>Data set B has ${f('56 - 32 = 24')} values. Its sum is:
    <p>${f('\\text{Sum of B} = 10{,}808 - 6{,}656 = 4{,}152')}</p>
  </li>
  <li>Calculate the average of data set B:
    <p>${f('\\text{Average of B} = \\frac{4{,}152}{24} = 173')}</p>
  </li>
</ol>
<p>Thus, the average of data set B is <strong>173</strong>.</p>`
};

async function run() {
  console.log('Injecting 22 pedagogical explanations for May 2025 · INT 3 Module 1...\n');
  let count = 0;
  for (const [id, expl] of Object.entries(explanations)) {
    process.stdout.write(`Updating Q ${id} (${++count}/22)... `);
    await updateQuestion(id, { explanation: expl });
    console.log('✅');
  }
  console.log('\n🎉 Successfully injected all 22 M1 explanations!');
}

run().catch(console.error);
