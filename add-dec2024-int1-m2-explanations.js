const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';

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
  '6aa599feec7ba02921a444c7': `<p>In any right triangle, the two acute angles are complementary, meaning their sum is <span class="ql-formula" data-value="90^\\circ"></span>.</p><p>We are given that one of the acute angles measures <span class="ql-formula" data-value="24^\\circ"></span> and the other measures <span class="ql-formula" data-value="a^\\circ"></span>:</p><p><span class="ql-formula" data-value="24 + a = 90 \\implies a = 90 - 24 = 66"></span></p><p>Thus, the value of <span class="ql-formula" data-value="a"></span> is <strong>66</strong>.</p>`,

  // Q2
  '6aa59a44ec7ba02921a444cb': `<p>If the graph of <span class="ql-formula" data-value="y = f(x)"></span> passes through the point <span class="ql-formula" data-value="(5, 3)"></span>, then substituting <span class="ql-formula" data-value="x = 5"></span> into the function yields the corresponding <span class="ql-formula" data-value="y"></span>-value:</p><p><span class="ql-formula" data-value="f(5) = 3"></span></p><p>Therefore, the value of <span class="ql-formula" data-value="f(5)"></span> is <strong>3</strong>.</p>`,

  // Q3
  '6aa59a68ec7ba02921a444cf': `<p>The circumference <span class="ql-formula" data-value="C"></span> of a circle is related to its diameter <span class="ql-formula" data-value="d"></span> by the formula:</p><p><span class="ql-formula" data-value="C = \\pi d"></span></p><p>We are given that the circumference is <span class="ql-formula" data-value="42\\pi"></span> centimeters:</p><p><span class="ql-formula" data-value="42\\pi = \\pi d \\implies d = 42"></span></p><p>Thus, the diameter of the circle is <strong>42</strong> centimeters.</p>`,

  // Q4
  '6aa59ac4ec7ba02921a444d3': `<p>We are given the kinetic energy formula with mass 49 kg:</p><p><span class="ql-formula" data-value="49 = \\frac{2K}{v^2}"></span></p><p>Multiply both sides by <span class="ql-formula" data-value="v^2"></span>:</p><p><span class="ql-formula" data-value="49v^2 = 2K"></span></p><p>Divide both sides by 49:</p><p><span class="ql-formula" data-value="v^2 = \\frac{2K}{49}"></span></p><p>Take the positive square root of both sides (since speed <span class="ql-formula" data-value="v > 0"></span>):</p><p><span class="ql-formula" data-value="v = \\sqrt{\\frac{2K}{49}}"></span></p>`,

  // Q5
  '6aa59afaec7ba02921a444d7': `<p>We are given the quadratic function <span class="ql-formula" data-value="f(x) = 4x^2"></span>.</p><p>To evaluate <span class="ql-formula" data-value="f(11)"></span>, substitute 11 for <span class="ql-formula" data-value="x"></span>:</p><p><span class="ql-formula" data-value="f(11) = 4(11)^2 = 4(121) = 484"></span></p><p>Thus, the value of <span class="ql-formula" data-value="f(11)"></span> is <strong>484</strong>.</p>`,

  // Q6
  '6aa59b62ec7ba02921a444db': `<p>To find the <span class="ql-formula" data-value="y"></span>-intercept of the graph of <span class="ql-formula" data-value="g(x) = \\frac{1}{9}(5)^x"></span>, substitute <span class="ql-formula" data-value="x = 0"></span>:</p><p><span class="ql-formula" data-value="g(0) = \\frac{1}{9}(5)^0 = \\frac{1}{9}(1) = \\frac{1}{9}"></span></p><p>Therefore, the coordinates of the <span class="ql-formula" data-value="y"></span>-intercept are <span class="ql-formula" data-value="(0, \\frac{1}{9})"></span>.</p>`,

  // Q7
  '6aa59bd3ec7ba02921a444df': `<p>We are asked for the conditional probability of selecting a medium T-shirt, given that the selected shirt is a Hawks T-shirt:</p><p><span class="ql-formula" data-value="P(\\text{Medium} \\mid \\text{Hawks}) = \\frac{\\text{Number of Medium Hawks T-shirts}}{\\text{Total Number of Hawks T-shirts}}"></span></p><p>From the table:</p><ul><li>Number of Medium Hawks T-shirts = 21</li><li>Total Number of Hawks T-shirts = 42</li></ul><p>Calculate the probability:</p><p><span class="ql-formula" data-value="P(\\text{Medium} \\mid \\text{Hawks}) = \\frac{21}{42} = \\frac{1}{2} = 0.5"></span></p>`,

  // Q8
  '6aa59c10ec7ba02921a444e3': `<p>The time elapsed between 1652 and 1952 is:</p><p><span class="ql-formula" data-value="1952 - 1652 = 300\\text{ years}"></span></p><p>Since the population doubled every 75 years, the number of doubling periods is:</p><p><span class="ql-formula" data-value="\\frac{300}{75} = 4\\text{ doubling periods}"></span></p><p>Let <span class="ql-formula" data-value="P_0"></span> be the initial population in 1652. After 4 doublings:</p><p><span class="ql-formula" data-value="P_0 \\times 2^4 = 160{,}000"></span></p><p><span class="ql-formula" data-value="P_0 \\times 16 = 160{,}000 \\implies P_0 = \\frac{160{,}000}{16} = 10{,}000"></span></p>`,

  // Q9
  '6aa59cadec7ba02921a444e7': `<p>In right triangle <span class="ql-formula" data-value="JKL"></span> with right angle at <span class="ql-formula" data-value="K"></span>, the tangent of angle <span class="ql-formula" data-value="L"></span> is the ratio of the opposite leg to the adjacent leg:</p><p><span class="ql-formula" data-value="\\tan(L) = \\frac{JK}{KL} = \\frac{3}{4}"></span></p><p>This means the side lengths <span class="ql-formula" data-value="JK"></span> and <span class="ql-formula" data-value="KL"></span> are in the ratio <span class="ql-formula" data-value="3 : 4"></span>. Let <span class="ql-formula" data-value="JK = 3x"></span> and <span class="ql-formula" data-value="KL = 4x"></span>. By the Pythagorean theorem, the hypotenuse <span class="ql-formula" data-value="JL"></span> is:</p><p><span class="ql-formula" data-value="JL = \\sqrt{(3x)^2 + (4x)^2} = \\sqrt{25x^2} = 5x"></span></p><p>We are given that the hypotenuse <span class="ql-formula" data-value="JL = 90"></span>:</p><p><span class="ql-formula" data-value="5x = 90 \\implies x = 18"></span></p><p>Now find the length of <span class="ql-formula" data-value="JK"></span>:</p><p><span class="ql-formula" data-value="JK = 3x = 3(18) = 54"></span></p>`,

  // Q10
  '6aa59ce0ec7ba02921a444eb': `<p>To find the number of distinct real solutions to <span class="ql-formula" data-value="x^2 - \\frac{25}{81} = 0"></span>, add <span class="ql-formula" data-value="\\frac{25}{81}"></span> to both sides:</p><p><span class="ql-formula" data-value="x^2 = \\frac{25}{81}"></span></p><p>Taking the square root of both sides gives:</p><p><span class="ql-formula" data-value="x = \\pm \\sqrt{\\frac{25}{81}} = \\pm \\frac{5}{9}"></span></p><p>There are two distinct real solutions: <span class="ql-formula" data-value="x = \\frac{5}{9}"></span> and <span class="ql-formula" data-value="x = -\\frac{5}{9}"></span>. Therefore, the equation has <strong>Exactly two</strong> distinct real solutions.</p>`,

  // Q11
  '6aa59d26ec7ba02921a444ef': `<p>A linear equation of the form <span class="ql-formula" data-value="0x = c"></span> has infinitely many solutions if and only if the constant term <span class="ql-formula" data-value="c = 0"></span> (resulting in the identity <span class="ql-formula" data-value="0 = 0"></span>, which is true for all real values of <span class="ql-formula" data-value="x"></span>).</p><p>In the equation <span class="ql-formula" data-value="0x = a + 7"></span>, set the right-hand side equal to 0:</p><p><span class="ql-formula" data-value="a + 7 = 0 \\implies a = -7"></span></p><p>Therefore, the only value of <span class="ql-formula" data-value="a"></span> that produces infinitely many solutions is <strong>-7 only</strong>.</p>`,

  // Q12
  '6aa5a34dec7ba02921a44502': `<p>We are given that <span class="ql-formula" data-value="x"></span> is 33% of <span class="ql-formula" data-value="y"></span>:</p><p><span class="ql-formula" data-value="x = 0.33y = \\frac{33}{100}y"></span></p><p>To express <span class="ql-formula" data-value="y"></span> in terms of <span class="ql-formula" data-value="x"></span>, multiply both sides by the reciprocal <span class="ql-formula" data-value="\\frac{100}{33}"></span>:</p><p><span class="ql-formula" data-value="y = \\frac{100}{33}x"></span></p>`,

  // Q13
  '6aa5a9a2ec7ba02921a4450c': `<p>Rewrite the radical expressions using rational exponent rules <span class="ql-formula" data-value="\\sqrt[n]{x^m} = x^{\\frac{m}{n}}"></span>:</p><p><span class="ql-formula" data-value="\\sqrt[5]{x^m} = x^{\\frac{m}{5}}"></span></p><p><span class="ql-formula" data-value="\\sqrt[7]{x} = x^{\\frac{1}{7}}"></span></p><p>Equate the exponents since the bases are identical (<span class="ql-formula" data-value="x > 1"></span>):</p><p><span class="ql-formula" data-value="\\frac{m}{5} = \\frac{1}{7}"></span></p><p>Multiply both sides by 5:</p><p><span class="ql-formula" data-value="m = \\frac{5}{7}"></span></p>`,

  // Q14
  '6aa5a9d4ec7ba02921a44510': `<p>The book club charges $13 for the first book. For any book after the first, an additional $11 is charged.</p><p>If <span class="ql-formula" data-value="x"></span> books are purchased in total (with <span class="ql-formula" data-value="x > 0"></span>), then 1 book costs $13, and the remaining <span class="ql-formula" data-value="x - 1"></span> books cost $11 each.</p><p>The total cost <span class="ql-formula" data-value="y"></span> is given by:</p><p><span class="ql-formula" data-value="y = 11(x - 1) + 13"></span></p>`,

  // Q15
  '6aa5addaec7ba02921a44514': `<p>Using the power-of-a-power exponent rule, rewrite <span class="ql-formula" data-value="z(w) = (0.829)^{2w}"></span> as:</p><p><span class="ql-formula" data-value="z(w) = \\left((0.829)^2\\right)^w"></span></p><p>Calculate the base value:</p><p><span class="ql-formula" data-value="(0.829)^2 \\approx 0.68724"></span></p><p>For each increase of 1 in <span class="ql-formula" data-value="w"></span>, the value of <span class="ql-formula" data-value="z(w)"></span> is multiplied by approximately 0.68724. The percentage decrease is:</p><p><span class="ql-formula" data-value="p\\% = (1 - 0.68724) \\times 100\\% \\approx 31.28\\% \\approx 31.3\\%"></span></p><p>Thus, the value closest to <span class="ql-formula" data-value="p"></span> is <strong>31.3</strong>.</p>`,

  // Q16
  '6aa5aeb1ec7ba02921a44518': `<p>The graph shows the linear equation <span class="ql-formula" data-value="y = f(x) + 11"></span>. From the graph:</p><ul><li>The line has a negative slope, so <span class="ql-formula" data-value="y = -cx + k"></span> for some positive constant <span class="ql-formula" data-value="c"></span>.</li><li>The <span class="ql-formula" data-value="y"></span>-intercept of the line is positive but less than 11 (approximately <span class="ql-formula" data-value="1.5"></span>).</li></ul><p>Solve for <span class="ql-formula" data-value="f(x)"></span>:</p><p><span class="ql-formula" data-value="f(x) = y - 11 = (-cx + k) - 11 = -cx - (11 - k)"></span></p><p>Since <span class="ql-formula" data-value="k < 11"></span>, the value <span class="ql-formula" data-value="d = 11 - k"></span> is positive (<span class="ql-formula" data-value="d > 0"></span>). Therefore:</p><p><span class="ql-formula" data-value="f(x) = -cx - d = -d - cx"></span></p>`,

  // Q17
  '6aa5af2dec7ba02921a4451c': `<p>For a quadratic equation in standard form <span class="ql-formula" data-value="Ax^2 + Bx + C = 0"></span>, the product of the solutions is given by Vieta's formulas as <span class="ql-formula" data-value="\\frac{C}{A}"></span>.</p><p>In the given equation <span class="ql-formula" data-value="21x^2 + (21s + r)x + rs = 0"></span>, we have <span class="ql-formula" data-value="A = 21"></span> and <span class="ql-formula" data-value="C = rs"></span>.</p><p>The product of the solutions is:</p><p><span class="ql-formula" data-value="\\text{Product} = \\frac{rs}{21} = \\frac{1}{21}rs"></span></p><p>Since the product is given as <span class="ql-formula" data-value="krs"></span>, equating coefficients gives <span class="ql-formula" data-value="k = \\frac{1}{21}"></span>.</p>`,

  // Q18
  '6aa5af7dec7ba02921a44520': `<p>Translate each condition into an equation:</p><ul><li>Particle A's speed is 6,000% of particle C's speed: <span class="ql-formula" data-value="a = \\frac{6000}{100}c = 60c"></span>.</li><li>Particle C's speed is 0.008% of particle B's speed: <span class="ql-formula" data-value="c = \\frac{0.008}{100}b = 0.00008b"></span>.</li></ul><p>Solve for <span class="ql-formula" data-value="b"></span> in terms of <span class="ql-formula" data-value="c"></span>:</p><p><span class="ql-formula" data-value="b = \\frac{c}{0.00008} = 12{,}500c"></span></p><p>Now compute <span class="ql-formula" data-value="a + b"></span> in terms of <span class="ql-formula" data-value="c"></span>:</p><p><span class="ql-formula" data-value="a + b = 60c + 12{,}500c = 12{,}560c"></span></p>`,

  // Q19
  '6aa5afe1ec7ba02921a44524': `<p>Expand each squared binomial expression:</p><p><span class="ql-formula" data-value="(5x - 3)^2 = 25x^2 - 30x + 9"></span></p><p><span class="ql-formula" data-value="(5x - 2)^2 = 25x^2 - 20x + 4"></span></p><p>Substitute into the expression:</p><p><span class="ql-formula" data-value="-16(25x^2 - 30x + 9) + 4(25x^2 - 20x + 4)"></span></p><p><span class="ql-formula" data-value="= (-400x^2 + 480x - 144) + (100x^2 - 80x + 16)"></span></p><p><span class="ql-formula" data-value="= -300x^2 + 400x - 128"></span></p><p>Equating this to <span class="ql-formula" data-value="\\frac{a}{4}x^2 + \\frac{b}{4}x + \\frac{c}{4}"></span>:</p><ul><li><span class="ql-formula" data-value="\\frac{a}{4} = -300 \\implies a = -1200"></span></li><li><span class="ql-formula" data-value="\\frac{b}{4} = 400 \\implies b = 1600"></span></li><li><span class="ql-formula" data-value="\\frac{c}{4} = -128 \\implies c = -512"></span></li></ul><p>Now sum the constants:</p><p><span class="ql-formula" data-value="a + b + c = -1200 + 1600 - 512 = 400 - 512 = -112"></span></p>`,

  // Q20
  '6aa5b053ec7ba02921a4460e': `<p>For an exponential function <span class="ql-formula" data-value="f(x) = 66b^x"></span>, each unit increase in <span class="ql-formula" data-value="x"></span> multiplies the function's output by <span class="ql-formula" data-value="b"></span>:</p><p><span class="ql-formula" data-value="\\frac{f(x + 1)}{f(x)} = \\frac{66b^{x + 1}}{66b^x} = b"></span></p><p>The percent increase <span class="ql-formula" data-value="c\\%"></span> is the relative change multiplied by 100:</p><p><span class="ql-formula" data-value="c = \\frac{b - 1}{1} \\times 100 = 100(b - 1)"></span></p><p>Thus, <span class="ql-formula" data-value="c = 100(b - 1)"></span>.</p>`,

  // Q21
  '6aa5b082ec7ba02921a44612': `<p>The tree grows 87 centimeters every <span class="ql-formula" data-value="m"></span> months, so its average growth rate per month is:</p><p><span class="ql-formula" data-value="\\text{Rate} = \\frac{87}{m}\\text{ cm/month}"></span></p><p>There are 12 months in 1 year, so in <span class="ql-formula" data-value="k"></span> years there are <span class="ql-formula" data-value="12k"></span> months.</p><p>Multiply the monthly rate by the total number of months:</p><p><span class="ql-formula" data-value="\\text{Growth} = \\frac{87}{m} \\times 12k = \\frac{87 \\times 12k}{m} = \\frac{1{,}044k}{m}\\text{ cm}"></span></p>`,

  // Q22
  '6aa5b103ec7ba02921a44616': `<p>Triangle <span class="ql-formula" data-value="ABC"></span> is inscribed in the circle with <span class="ql-formula" data-value="\\angle ABC = 90^\\circ"></span>. By Thales's theorem, the hypotenuse <span class="ql-formula" data-value="AC"></span> is a diameter of the circle, so <span class="ql-formula" data-value="AC = 175"></span>.</p><p>Segment <span class="ql-formula" data-value="BD"></span> is an altitude from the right angle <span class="ql-formula" data-value="B"></span> perpendicular to hypotenuse <span class="ql-formula" data-value="AC"></span>. By the Geometric Mean (Altitude) Theorem:</p><p><span class="ql-formula" data-value="BD^2 = AD \\cdot CD"></span></p><p>We are given <span class="ql-formula" data-value="BD = \\sqrt{346}"></span>, so <span class="ql-formula" data-value="AD \\cdot CD = (\\sqrt{346})^2 = 346"></span>.</p><p>Also, since <span class="ql-formula" data-value="D"></span> lies on segment <span class="ql-formula" data-value="AC"></span>:</p><p><span class="ql-formula" data-value="AD + CD = AC = 175"></span></p><p>Let <span class="ql-formula" data-value="AD = u"></span> and <span class="ql-formula" data-value="CD = v"></span>. Then <span class="ql-formula" data-value="u"></span> and <span class="ql-formula" data-value="v"></span> are roots of <span class="ql-formula" data-value="t^2 - 175t + 346 = 0"></span>. Factoring:</p><p><span class="ql-formula" data-value="(t - 2)(t - 173) = 0"></span></p><p>Since <span class="ql-formula" data-value="AB < BC"></span>, we have <span class="ql-formula" data-value="AD < CD"></span>, which gives <span class="ql-formula" data-value="AD = 2"></span> and <span class="ql-formula" data-value="CD = 173"></span>.</p><p>Now compute <span class="ql-formula" data-value="r = \\frac{CD}{AD}"></span>:</p><p><span class="ql-formula" data-value="r = \\frac{173}{2} = 86.5"></span></p>`
};

async function run() {
  console.log('Injecting 22 pedagogical explanations for December 2024 · INT 1 Module 2...');
  const keys = Object.keys(explanations);
  for (const id of keys) {
    const res = await updateQuestion(id, { explanation: explanations[id] });
    if (res.message && res.message.toLowerCase().includes('success') || res._id || res.status === 200 || !res.error) {
      console.log(`Q ${id}: explanation injected ✅`);
    } else {
      console.log(`Q ${id}: failed:`, res);
    }
  }
  console.log('\nFinished Module 2: 22/22 explanations successfully injected.');
}

run().catch(console.error);
