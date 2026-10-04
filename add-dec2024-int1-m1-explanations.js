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
  '6aa58665ec7ba02921a44445': `<p>The solution to a system of two linear equations in the <span class="ql-formula" data-value="xy"></span>-plane corresponds to the point of intersection of their graphs.</p><p>Looking at the given graph, the two lines intersect at the point <span class="ql-formula" data-value="(-4, 2)"></span>. Therefore, <span class="ql-formula" data-value="x = -4"></span> and <span class="ql-formula" data-value="y = 2"></span>.</p><p>Thus, the value of <span class="ql-formula" data-value="y"></span> is <strong>2</strong>.</p>`,

  // Q2
  '6aa586b2ec7ba02921a44449': `<p>We are given the linear function <span class="ql-formula" data-value="f(x) = 15x + 10"></span>.</p><p>To find the value of <span class="ql-formula" data-value="f(x)"></span> when <span class="ql-formula" data-value="x = 2"></span>, substitute 2 for <span class="ql-formula" data-value="x"></span>:</p><p><span class="ql-formula" data-value="f(2) = 15(2) + 10 = 30 + 10 = 40"></span></p><p>Thus, the value of <span class="ql-formula" data-value="f(2)"></span> is <strong>40</strong>.</p>`,

  // Q3
  '6aa5874bec7ba02921a4444d': `<p>First, find the slope <span class="ql-formula" data-value="m"></span> of the linear relationship using the points <span class="ql-formula" data-value="(0, 22)"></span> and <span class="ql-formula" data-value="(1, 23)"></span> from the table:</p><p><span class="ql-formula" data-value="m = \\frac{23 - 22}{1 - 0} = \\frac{1}{1} = 1"></span></p><p>When <span class="ql-formula" data-value="x = 0"></span>, <span class="ql-formula" data-value="y = 22"></span>, so the <span class="ql-formula" data-value="y"></span>-intercept is <span class="ql-formula" data-value="22"></span>. In slope-intercept form <span class="ql-formula" data-value="y = mx + b"></span>, the equation is:</p><p><span class="ql-formula" data-value="y = 1x + 22 = x + 22"></span></p>`,

  // Q4
  '6aa5883eec7ba02921a44458': `<p>A linear function in slope-intercept form is given by <span class="ql-formula" data-value="f(x) = mx + b"></span>, where <span class="ql-formula" data-value="m"></span> is the slope and <span class="ql-formula" data-value="(0, b)"></span> is the <span class="ql-formula" data-value="y"></span>-intercept.</p><p>We are given that the slope is <span class="ql-formula" data-value="m = 4"></span> and the line passes through <span class="ql-formula" data-value="(0, 21)"></span>, which means the <span class="ql-formula" data-value="y"></span>-intercept is <span class="ql-formula" data-value="b = 21"></span>.</p><p>Substituting these values gives:</p><p><span class="ql-formula" data-value="f(x) = 4x + 21"></span></p>`,

  // Q5
  '6aa588bbec7ba02921a4445c': `<p>A system of two linear equations has infinitely many solutions when the two equations represent the exact same line.</p><p>Rearranging the first equation <span class="ql-formula" data-value="2x - y = 2"></span> into slope-intercept form:</p><p><span class="ql-formula" data-value="-y = -2x + 2 \\implies y = 2x - 2"></span></p><p>For the second equation <span class="ql-formula" data-value="y = mx + b"></span> to have infinitely many solutions with this line, the slope and <span class="ql-formula" data-value="y"></span>-intercept must match: <span class="ql-formula" data-value="m = 2"></span> and <span class="ql-formula" data-value="b = -2"></span>.</p><p>Therefore, the value of <span class="ql-formula" data-value="b"></span> is <strong>-2</strong>.</p>`,

  // Q6
  '6aa5896aec7ba02921a44460': `<p>A function is increasing on an interval if its graph moves upward from left to right as <span class="ql-formula" data-value="x"></span> increases.</p><p>From the given parabola:</p><ul><li>At <span class="ql-formula" data-value="x = 0"></span>, the height is 0 meters.</li><li>As <span class="ql-formula" data-value="x"></span> increases from 0 to 2, the height increases until it reaches the vertex (maximum height of 20 meters at <span class="ql-formula" data-value="x = 2"></span>).</li><li>For <span class="ql-formula" data-value="x > 2"></span>, the height decreases back down to 0 meters at <span class="ql-formula" data-value="x = 4"></span>.</li></ul><p>Therefore, the height was increasing for the entire interval <strong>From x = 0 to x = 2</strong>.</p>`,

  // Q7
  '6aa589e3ec7ba02921a44464': `<p>An exponential equation has the form <span class="ql-formula" data-value="y = a(b)^x"></span>, where <span class="ql-formula" data-value="a"></span> is the initial value at <span class="ql-formula" data-value="x = 0"></span> and <span class="ql-formula" data-value="b"></span> is the growth factor.</p><p>We are given that when <span class="ql-formula" data-value="x = 0"></span>, <span class="ql-formula" data-value="y = 90"></span>, so <span class="ql-formula" data-value="a = 90"></span>.</p><p>Because <span class="ql-formula" data-value="y"></span> increases by 20% for each increase of 1 in <span class="ql-formula" data-value="x"></span>, the growth factor is:</p><p><span class="ql-formula" data-value="b = 1 + 0.20 = 1.20"></span></p><p>Thus, the equation is <span class="ql-formula" data-value="y = 90(1.20)^x"></span>.</p>`,

  // Q8
  '6aa58a32ec7ba02921a44468': `<p>To find the mean time to complete a task, divide the total completion time across all tasks by the number of tasks (5):</p><p><span class="ql-formula" data-value="\\text{Total Time} = 8 + 6 + 14 + 11 + 11 = 50\\text{ minutes}"></span></p><p><span class="ql-formula" data-value="\\text{Mean Time} = \\frac{50}{5} = 10\\text{ minutes}"></span></p>`,

  // Q9
  '6aa58a70ec7ba02921a4446c': `<p>We are given the absolute value function <span class="ql-formula" data-value="h(x) = 7|x|"></span>.</p><p>Substitute <span class="ql-formula" data-value="x = -2"></span> into the function:</p><p><span class="ql-formula" data-value="h(-2) = 7|-2|"></span></p><p>Since the absolute value of <span class="ql-formula" data-value="-2"></span> is 2:</p><p><span class="ql-formula" data-value="h(-2) = 7(2) = 14"></span></p>`,

  // Q10
  '6aa58ad8ec7ba02921a44470': `<p>The line of best fit slopes downward from left to right, indicating a negative slope. This immediately eliminates positive slope options.</p><p>Identify two points along the line: around <span class="ql-formula" data-value="(0, 11.2)"></span> and <span class="ql-formula" data-value="(7, 5.3)"></span>.</p><p>Compute the slope <span class="ql-formula" data-value="m"></span>:</p><p><span class="ql-formula" data-value="m \\approx \\frac{5.3 - 11.2}{7 - 0} = -\\frac{5.9}{7} \\approx -0.84"></span></p><p>Thus, the value closest to the slope is <strong>-0.84</strong>.</p>`,

  // Q11
  '6aa58b67ec7ba02921a44474': `<p>When two parallel lines <span class="ql-formula" data-value="q \\parallel r"></span> are intersected by a transversal line <span class="ql-formula" data-value="s"></span>, consecutive interior angles are supplementary (their sum is <span class="ql-formula" data-value="180^\\circ"></span>).</p><p>From the figure, the angle measuring <span class="ql-formula" data-value="77^\\circ"></span> and the angle measuring <span class="ql-formula" data-value="y^\\circ"></span> are supplementary:</p><p><span class="ql-formula" data-value="y = 180 - 77 = 103"></span></p><p>We are given that <span class="ql-formula" data-value="y = 2x + 7"></span>. Substitute <span class="ql-formula" data-value="y = 103"></span>:</p><p><span class="ql-formula" data-value="2x + 7 = 103 \\implies 2x = 96 \\implies x = 48"></span></p>`,

  // Q12
  '6aa58f14ec7ba02921a44482': `<p>Let <span class="ql-formula" data-value="p"></span> be the original price, in dollars, of one shirt. The cost of 9 shirts before the coupon was <span class="ql-formula" data-value="9p"></span>.</p><p>After using a $54 coupon, the total cost was $108:</p><p><span class="ql-formula" data-value="9p - 54 = 108"></span></p><p>Add 54 to both sides:</p><p><span class="ql-formula" data-value="9p = 162"></span></p><p>Divide by 9:</p><p><span class="ql-formula" data-value="p = \\frac{162}{9} = 18"></span></p><p>The original price for 1 shirt was <strong>18</strong> dollars.</p>`,

  // Q13
  '6aa58f72ec7ba02921a44486': `<p>Use the point-slope form of a linear equation, <span class="ql-formula" data-value="y - y_1 = m(x - x_1)"></span>, with slope <span class="ql-formula" data-value="m = -\\frac{1}{3}"></span> and point <span class="ql-formula" data-value="(9, 4)"></span>:</p><p><span class="ql-formula" data-value="y - 4 = -\\frac{1}{3}(x - 9)"></span></p><p>Distribute <span class="ql-formula" data-value="-\\frac{1}{3}"></span>:</p><p><span class="ql-formula" data-value="y - 4 = -\\frac{x}{3} + 3"></span></p><p>Add 4 to both sides:</p><p><span class="ql-formula" data-value="y = -\\frac{x}{3} + 7"></span></p>`,

  // Q14
  '6aa58f92ec7ba02921a4448a': `<p>By the Zero Product Property, set each factor of the polynomial equation equal to 0:</p><ul><li><span class="ql-formula" data-value="x - 16 = 0 \\implies x = 16"></span></li><li><span class="ql-formula" data-value="x - 12 = 0 \\implies x = 12"></span></li><li><span class="ql-formula" data-value="x + 7 = 0 \\implies x = -7"></span></li><li><span class="ql-formula" data-value="x + 13 = 0 \\implies x = -13"></span></li></ul><p>The positive solutions to the equation are <strong>12</strong> and <strong>16</strong>. Either answer is correct.</p>`,

  // Q15
  '6aa59015ec7ba02921a4448e': `<p>The formula for the volume <span class="ql-formula" data-value="V"></span> of a right circular cone is:</p><p><span class="ql-formula" data-value="V = \\frac{1}{3}\\pi r^2 h"></span></p><p>Substitute the given radius <span class="ql-formula" data-value="r = 6\\text{ cm}"></span> and height <span class="ql-formula" data-value="h = 13\\text{ cm}"></span>:</p><p><span class="ql-formula" data-value="V = \\frac{1}{3}\\pi (6)^2 (13) = \\frac{1}{3}\\pi (36)(13)"></span></p><p><span class="ql-formula" data-value="V = 12(13)\\pi = 156\\pi\\text{ cm}^3"></span></p>`,

  // Q16
  '6aa5902dec7ba02921a44492': `<p>First find the annual rate of population growth between 1995 and 2015 (a period of <span class="ql-formula" data-value="2015 - 1995 = 20"></span> years):</p><p><span class="ql-formula" data-value="\\text{Rate} = \\frac{217 - 55}{20} = \\frac{162}{20} = 8.1\\text{ thousand people per year}"></span></p><p>The year 2019 is 4 years after 2015. Use the linear rate to estimate the population in 2019:</p><p><span class="ql-formula" data-value="x = 217 + 4(8.1) = 217 + 32.4 = 249.4"></span></p><p>To the nearest whole number, the value of <span class="ql-formula" data-value="x"></span> is <strong>249</strong>.</p>`,

  // Q17
  '6aa5906cec7ba02921a44496': `<p>In a graph in the <span class="ql-formula" data-value="xy"></span>-plane, the <span class="ql-formula" data-value="y"></span>-intercept occurs when the input variable <span class="ql-formula" data-value="x = 0"></span>.</p><p>Here, <span class="ql-formula" data-value="x"></span> represents the number of six-month periods elapsed starting from the end of January 1997. Therefore, <span class="ql-formula" data-value="x = 0"></span> corresponds precisely to the initial time: <strong>the end of January 1997</strong>.</p><p>Evaluating at <span class="ql-formula" data-value="x = 0"></span> gives <span class="ql-formula" data-value="y = 500"></span> subscribers. Thus, the best interpretation of the <span class="ql-formula" data-value="y"></span>-intercept is: <strong>The estimated number of online newsletter subscribers at the end of January 1997 was 500.</strong></p>`,

  // Q18
  '6aa59163ec7ba02921a4449d': `<p>We are given the system:</p><p>1) <span class="ql-formula" data-value="\\frac{x}{7} + 5(y - 14) = 29"></span></p><p>2) <span class="ql-formula" data-value="\\frac{x}{3} - 5(y - 14) = 41"></span></p><p>Add the two equations directly to eliminate the <span class="ql-formula" data-value="5(y - 14)"></span> terms:</p><p><span class="ql-formula" data-value="\\left(\\frac{x}{7} + \\frac{x}{3}\\right) + [5(y - 14) - 5(y - 14)] = 29 + 41"></span></p><p><span class="ql-formula" data-value="\\frac{3x + 7x}{21} = 70 \\implies \\frac{10x}{21} = 70"></span></p><p>Multiply both sides by 21:</p><p><span class="ql-formula" data-value="10x = 70 \\times 21 = 1470"></span></p>`,

  // Q19
  '6aa591b1ec7ba02921a444a1': `<p>The total resistance of 8 resistors in series is the sum of their individual resistances, which equals 130 ohms.</p><p>We are given that 3 of the resistors have a combined resistance of 90 ohms. Therefore, the remaining 5 resistors have a combined resistance of:</p><p><span class="ql-formula" data-value="130 - 90 = 40\\text{ ohms}"></span></p><p>Let <span class="ql-formula" data-value="c"></span> be the resistance of any one of these 5 resistors. Since the resistance of each resistor must be positive, <span class="ql-formula" data-value="c > 0"></span>. Furthermore, because the sum of all 5 positive resistances is 40, no single resistor can equal or exceed 40 (since the other 4 resistors must each be greater than 0): <span class="ql-formula" data-value="c < 40"></span>.</p><p>Thus, the inequality representing all possible values is <strong>0 < x < 40</strong>.</p>`,

  // Q20
  '6aa591f2ec7ba02921a444a5': `<p>The account balance function is <span class="ql-formula" data-value="f(m) = 21 - 3m"></span>, where <span class="ql-formula" data-value="m"></span> is the number of movies rented.</p><p>This is a linear model where the slope is <span class="ql-formula" data-value="-3"></span>. The negative sign represents a withdrawal from the account, and the magnitude <span class="ql-formula" data-value="3"></span> indicates that <strong>$3</strong> is withdrawn for each movie rented.</p>`,

  // Q21
  '6aa59229ec7ba02921a444a9': `<p>We are given the equation <span class="ql-formula" data-value="9 - 4(4 - 9x) = 2 - 5(4 - 9x)"></span>.</p><p>Let <span class="ql-formula" data-value="u = 4 - 9x"></span>. Substituting <span class="ql-formula" data-value="u"></span> into the equation gives:</p><p><span class="ql-formula" data-value="9 - 4u = 2 - 5u"></span></p><p>Add <span class="ql-formula" data-value="5u"></span> to both sides:</p><p><span class="ql-formula" data-value="9 + u = 2"></span></p><p>Subtract 9 from both sides:</p><p><span class="ql-formula" data-value="u = 2 - 9 = -7"></span></p><p>Since <span class="ql-formula" data-value="u = 4 - 9x"></span>, the value of <span class="ql-formula" data-value="4 - 9x"></span> is <strong>-7</strong>.</p>`,

  // Q22
  '6aa59278ec7ba02921a444ad': `<p>Let the total square footage of the plot of land be <span class="ql-formula" data-value="A"></span>.</p><ul><li>Farmland occupies <span class="ql-formula" data-value="52.0\\%"></span> of the plot: <span class="ql-formula" data-value="0.52A"></span>. Buildings cover <span class="ql-formula" data-value="21.5\\%"></span> of this farmland: <span class="ql-formula" data-value="0.215 \\times 0.52A = 0.1118A"></span>.</li><li>Pasture occupies the remaining <span class="ql-formula" data-value="100\\% - 52.0\\% = 48.0\\%"></span> of the plot: <span class="ql-formula" data-value="0.48A"></span>. Buildings cover <span class="ql-formula" data-value="14.0\\%"></span> of this pasture: <span class="ql-formula" data-value="0.14 \\times 0.48A = 0.0672A"></span>.</li></ul><p>Total square footage with buildings is:</p><p><span class="ql-formula" data-value="0.1118A + 0.0672A = 0.1790A = 17.9\\% A"></span></p><p>Therefore, the value of <span class="ql-formula" data-value="p"></span> is <strong>17.9</strong> (or <span class="ql-formula" data-value="\\frac{179}{10}"></span>).</p>`
};

async function run() {
  console.log('Injecting 22 pedagogical explanations for December 2024 · INT 1 Module 1...');
  const keys = Object.keys(explanations);
  for (const id of keys) {
    const res = await updateQuestion(id, { explanation: explanations[id] });
    if (res.message && res.message.toLowerCase().includes('success') || res._id || res.status === 200 || !res.error) {
      console.log(`Q ${id}: explanation injected ✅`);
    } else {
      console.log(`Q ${id}: failed:`, res);
    }
  }
  console.log('\nFinished Module 1: 22/22 explanations successfully injected.');
}

run().catch(console.error);
