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
  '6a98102fe57881aee77e871e': `<p>To find the total distance in kilometers traveled by the car using 39 gallons of gasoline:</p>
<ol>
  <li>We are given that the car travels ${f('1{,}950')} miles on 39 gallons of gasoline.</li>
  <li>We are given the conversion factor: ${f('1\\text{ mile} = 1.6\\text{ kilometers}')}.</li>
  <li>Multiply the distance in miles by 1.6 to convert to kilometers:
    <p>${f('\\text{Distance} = 1{,}950 \\times 1.6 = 3{,}120\\text{ kilometers}')}</p>
  </li>
</ol>
<p>Thus, the car travels <strong>3,120</strong> kilometers.</p>`,

  // Q2
  '6a984ad5e57881aee77ea217': `<p>To find the value of ${f('h(-3)')}:</p>
<ol>
  <li>The function is given by ${f('h(x) = 4x - 9')}.</li>
  <li>Substitute ${f('x = -3')} into the function:
    <p>${f('h(-3) = 4(-3) - 9')}</p>
  </li>
  <li>Evaluate the multiplication and subtraction:
    <p>${f('h(-3) = -12 - 9 = -21')}</p>
  </li>
</ol>
<p>Therefore, the value of ${f('h(-3)')} is <strong>-21</strong>.</p>`,

  // Q3
  '6a9843dae57881aee77e9f8a': `<p>To solve the system of linear equations for ${f('y')}:</p>
<ol>
  <li>From the first equation:
    <p>${f('10x = 110 \\implies x = 11')}</p>
  </li>
  <li>Substitute ${f('x = 11')} into the second equation ${f('8x - 86 = y')}:
    <p>${f('y = 8(11) - 86')}</p>
    <p>${f('y = 88 - 86 = 2')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('y')} is <strong>2</strong>.</p>`,

  // Q4
  '6a9846e0e57881aee77ea0f5': `<p>To factor the polynomial expression ${f('7x^5 - 6x^4 + 9x^3')}:</p>
<ol>
  <li>Identify the greatest common factor (GCF) of all three terms.</li>
  <li>The numerical coefficients 7, -6, and 9 share no common factors other than 1.</li>
  <li>The variable powers are ${f('x^5')}, ${f('x^4')}, and ${f('x^3')}. The lowest power of ${f('x')} present in all terms is ${f('x^3')}.</li>
  <li>Factor out ${f('x^3')}:
    <p>${f('7x^5 - 6x^4 + 9x^3 = x^3(7x^2 - 6x + 9)')}</p>
  </li>
</ol>
<p>Thus, the equivalent expression is <strong>${f('x^3(7x^2 - 6x + 9)')}</strong>.</p>`,

  // Q5
  '6a9847d6e57881aee77ea0fd': `<p>To find the solution ${f('(x, y)')} to the system:</p>
<ol>
  <li>We have ${f('y = 0')} and ${f('y = 8(x^2 - 36)')}.</li>
  <li>Set the two equations equal to each other:
    <p>${f('8(x^2 - 36) = 0')}</p>
  </li>
  <li>Divide both sides by 8:
    <p>${f('x^2 - 36 = 0 \\implies x^2 = 36')}</p>
    <p>${f('x = 6')} or ${f('x = -6')}</p>
  </li>
  <li>Since ${f('y = 0')}, the solutions are ${f('(6, 0)')} and ${f('(-6, 0)')}.</li>
</ol>
<p>Among the answer choices, <strong>(6, 0)</strong> is the correct ordered pair.</p>`,

  // Q6
  '6a984d17e57881aee77ea236': `<p>To model the total cost of cones and sundaes:</p>
<ol>
  <li>Let ${f('x')} be the number of ice cream cones purchased and ${f('y')} be the number of sundaes purchased.</li>
  <li>Each cone costs $1.40, so ${f('x')} cones cost ${f('1.40x')} dollars.</li>
  <li>We are given that 19 sundaes cost $64.60. Therefore, the unit price per sundae is:
    <p>${f('\\frac{64.60}{19} = 3.40\\text{ USD per sundae}')}</p>
    So ${f('y')} sundaes cost ${f('3.40y')} dollars.
  </li>
  <li>The total cost of both cones and sundaes is $85.60, giving the linear equation:
    <p>${f('1.40x + 3.40y = 85.60')}</p>
  </li>
</ol>
<p>Thus, the correct equation is <strong>${f('1.40x + 3.40y = 85.60')}</strong>.</p>`,

  // Q7
  '6a98507ee57881aee77ea953': `<p>To calculate the probability of selecting a blank tile:</p>
<ol>
  <li>Total number of tiles in the bag = 50.</li>
  <li>Number of blank tiles = 5.</li>
  <li>The probability of choosing a blank tile at random is:
    <p>${f('P(\\text{blank}) = \\frac{\\text{Number of blank tiles}}{\\text{Total tiles}} = \\frac{5}{50} = \\frac{1}{10} = 0.1')}</p>
  </li>
</ol>
<p>Thus, the probability is <strong>${f('\\frac{1}{10}')}</strong> (or <strong>0.1</strong>).</p>`,

  // Q8
  '6a985144e57881aee77ea9c7': `<p>To determine the possible measure of angle ${f('\\angle E')}:</p>
<ol>
  <li>In any triangle ${f('\\Delta DEF')}, the sum of interior angles is ${f('180^\\circ')}:
    <p>${f('\\angle D + \\angle E + \\angle F = 180^\\circ')}</p>
  </li>
  <li>Given ${f('\\angle D = 114^\\circ')}:
    <p>${f('114^\\circ + \\angle E + \\angle F = 180^\\circ \\implies \\angle E + \\angle F = 66^\\circ')}</p>
  </li>
  <li>Because ${f('\\angle F > 0^\\circ')}, the measure of ${f('\\angle E')} must be strictly less than ${f('66^\\circ')}:
    <p>${f('\\angle E < 66^\\circ')}</p>
  </li>
  <li>Among the options (115, 90, 67, and 65), only <strong>65</strong> is less than 66.</li>
</ol>
<p>Therefore, the only possible measure of ${f('\\angle E')} is <strong>65</strong> degrees.</p>`,

  // Q9
  '6a9851e3e57881aee77ea9cd': `<p>To determine the inequality represented by the graph:</p>
<ol>
  <li>Find the boundary line:
    <ul>
      <li>The line crosses the y-axis at ${f('(0, 7)')}, so the y-intercept is ${f('b = 7')}.</li>
      <li>Another point on the line is ${f('(-1, 4)')}. The slope is ${f('m = \\frac{7 - 4}{0 - (-1)} = 3')}.</li>
      <li>Thus, the equation of the boundary line is ${f('y = 3x + 7')}.</li>
    </ul>
  </li>
  <li>The boundary line is <strong>dashed</strong>, meaning the inequality is strict (${f('>')}) or (${f('<')}).</li>
  <li>The shaded region lies <strong>above</strong> the boundary line. For example, test the point ${f('(0, 10)')}:
    <p>${f('10 > 3(0) + 7 = 7')} (True).</p>
  </li>
</ol>
<p>Therefore, the inequality is <strong>${f('y > 3x + 7')}</strong>.</p>`,

  // Q10
  '6a98523fe57881aee77ea9df': `<p>To simplify the expression ${f('20x^2 + 3 + 5x^2')}:</p>
<ol>
  <li>Group the like terms (terms with ${f('x^2')}):
    <p>${f('(20x^2 + 5x^2) + 3')}</p>
  </li>
  <li>Add the coefficients:
    <p>${f('(20 + 5)x^2 + 3 = 25x^2 + 3')}</p>
  </li>
</ol>
<p>Therefore, the equivalent expression is <strong>${f('25x^2 + 3')}</strong>.</p>`,

  // Q11
  '6a9853d1e57881aee77eacb6': `<p>To find the exponential function modeling the account balance:</p>
<ol>
  <li>The initial balance at ${f('t = 0')} is $35,600, so the initial coefficient ${f('A(0) = 35{,}600')}.</li>
  <li>An exponential growth model has the form ${f('A(t) = P(1 + r)^t')}, where ${f('P = 35{,}600')} and ${f('r > 0')}.</li>
  <li>When ${f('1 + r = 1.09')} (a 9% annual interest rate), after ${f('t = 15')} years:
    <p>${f('A(15) = 35{,}600(1.09)^{15} \\approx 35{,}600 \\times 3.64248 \\approx 129{,}672.38')}</p>
    This exactly matches the given balance.
  </li>
</ol>
<p>Thus, the equation defining ${f('A')} is <strong>${f('A(t) = 35{,}600.00(1.09)^t')}</strong>.</p>`,

  // Q12
  '6a985475e57881aee77ead19': `<p>To find the y-intercept of the graph of ${f('y = 14^x')}:</p>
<ol>
  <li>The y-intercept occurs where ${f('x = 0')}.</li>
  <li>Substitute ${f('x = 0')} into the equation:
    <p>${f('y = 14^0 = 1')}</p>
  </li>
  <li>This gives the coordinates ${f('(0, 1)')}.</li>
</ol>
<p>Therefore, the y-intercept is <strong>(0, 1)</strong>.</p>`,

  // Q13
  '6a985535e57881aee77ead74': `<p>To find the value of ${f('b')} in the linear function ${f('f(x) = 2x + b')}:</p>
<ol>
  <li>We are given that ${f('f(7) = 6')}.</li>
  <li>Substitute ${f('x = 7')} and set the expression equal to 6:
    <p>${f('2(7) + b = 6')}</p>
  </li>
  <li>Simplify and solve for ${f('b')}:
    <p>${f('14 + b = 6 \\implies b = 6 - 14 = -8')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('b')} is <strong>-8</strong>.</p>`,

  // Q14
  '6a985607e57881aee77eaf50': `<p>To determine how many times ${f('g')} the number ${f('h')} is:</p>
<ol>
  <li>${f('f')} is 120% greater than ${f('g')}:
    <p>${f('f = g + 1.20g = 2.20g')}</p>
  </li>
  <li>${f('h')} is 90% less than ${f('f')}:
    <p>${f('h = f - 0.90f = 0.10f')}</p>
  </li>
  <li>Substitute ${f('f = 2.20g')} into the expression for ${f('h')}:
    <p>${f('h = 0.10(2.20g) = 0.22g')}</p>
  </li>
</ol>
<p>Thus, ${f('h')} is <strong>0.22</strong> times ${f('g')}.</p>`,

  // Q15
  '6a98567ce57881aee77eafc1': `<p>To compare the standard deviations of team A and team B:</p>
<ol>
  <li>Standard deviation measures how spread out data values are around the mean.</li>
  <li>For Team A, the histogram shows that the scores are heavily concentrated around the center (mean), indicating small variability and low dispersion.</li>
  <li>For Team B, the frequencies are highest at the outer extremes (a U-shaped distribution), indicating large variability and high dispersion away from the mean.</li>
  <li>Therefore, Team A has less spread than Team B.</li>
</ol>
<p>Thus, <strong>the standard deviation of scores for team A is less than the standard deviation of scores for team B</strong>.</p>`,

  // Q16
  '6a9af216838c4fe747f6d9b5': `<p>To find the value of ${f('4a')}:</p>
<ol>
  <li>The equation of Circle A is ${f('x^2 + (y - 5)^2 = 7')}. Here, ${f('r^2 = 7')}.</li>
  <li>Circle B is formed by translating Circle A 91 units to the right. A rigid translation preserves size and shape, so Circle B has the exact same radius as Circle A:
    <p>${f('r^2 = 7')}</p>
  </li>
  <li>The standard equation for Circle B is ${f('(x - h)^2 + (y - k)^2 = a')}. Since ${f('a = r^2')}, we have ${f('a = 7')}.</li>
  <li>Calculate ${f('4a')}:
    <p>${f('4a = 4(7) = 28')}</p>
  </li>
</ol>
<p>Thus, the value of ${f('4a')} is <strong>28</strong>.</p>`,

  // Q17
  '6a9af2e2838c4fe747f6de37': `<p>To find when the object hits the ground:</p>
<ol>
  <li>The height function is ${f('h(t) = -16t^2 + b')}.</li>
  <li>At ${f('t = 0')}, the height is 40.96 feet, so ${f('b = 40.96')}:
    <p>${f('h(t) = -16t^2 + 40.96')}</p>
  </li>
  <li>The object hits the ground when ${f('h(t) = 0')}:
    <p>${f('-16t^2 + 40.96 = 0 \\implies 16t^2 = 40.96')}</p>
  </li>
  <li>Divide by 16:
    <p>${f('t^2 = \\frac{40.96}{16} = 2.56')}</p>
    <p>${f('t = \\sqrt{2.56} = 1.6 = \\frac{8}{5}\\text{ seconds}')}</p>
  </li>
</ol>
<p>Thus, the object hits the ground <strong>1.6</strong> (or <strong>8/5</strong>) seconds after being dropped.</p>`,

  // Q18
  '6a9af4bf838c4fe747f6e2e8': `<p>To identify the true statement from the rainfall graph:</p>
<ol>
  <li>The graph plots cumulative rainfall ${f('y')} (in cm) over time ${f('x')} (in hours).</li>
  <li>Between ${f('x = 2')} and ${f('x = 4')}, the graph is a horizontal segment with a constant value of ${f('y = 4\\text{ cm}')}.</li>
  <li>The slope of a horizontal segment is 0, which means the rate of change of rainfall was:
    <p>${f('\\text{Rate} = \\frac{4 - 4}{4 - 2} = 0\\text{ cm per hour}')}</p>
  </li>
  <li>Therefore, no additional rain fell during this two-hour interval.</li>
</ol>
<p>Thus, the true statement is: <strong>The rate of rainfall was 0 centimeters per hour between x = 2 and x = 4.</strong></p>`,

  // Q19
  '6a9af4ec838c4fe747f6e335': `<p>To find the greatest of the three consecutive integers:</p>
<ol>
  <li>Let the three consecutive integers be ${f('n')}, ${f('n + 1')}, and ${f('n + 2')}.</li>
  <li>The greatest integer is ${f('n + 2')}, and the sum of the other two integers is:
    <p>${f('n + (n + 1) = 2n + 1')}</p>
  </li>
  <li>Subtracting the greatest integer from this sum gives 48:
    <p>${f('(2n + 1) - (n + 2) = 48')}</p>
  </li>
  <li>Simplify and solve for ${f('n')}:
    <p>${f('n - 1 = 48 \\implies n = 49')}</p>
  </li>
  <li>The three integers are 49, 50, and 51. The greatest integer is ${f('n + 2 = 51')}.</li>
</ol>
<p>Thus, the greatest integer is <strong>51</strong>.</p>`,

  // Q20
  '6a9af577838c4fe747f6e49c': `<p>To find the area of the enlarged banner copy:</p>
<ol>
  <li>Let the original length and width be ${f('L')} and ${f('W')}, where ${f('LW = 2{,}300\\text{ in}^2')}.</li>
  <li>Each linear dimension is increased by 20%, which means:
    <p>${f('L\' = 1.20L')} and ${f('W\' = 1.20W')}</p>
  </li>
  <li>The new area ${f('A\'')} is:
    <p>${f('A\' = L\' \\times W\' = (1.20L)(1.20W) = (1.20)^2 LW = 1.44 \\times 2{,}300')}</p>
  </li>
  <li>Calculate the product:
    <p>${f('A\' = 1.44 \\times 2{,}300 = 3{,}312\\text{ square inches}')}</p>
  </li>
</ol>
<p>Thus, the area of the copy is <strong>3,312</strong> square inches.</p>`,

  // Q21
  '6a9af5c0838c4fe747f6e4c1': `<p>To find the sum of the solutions to ${f('(x - 42)^2 = 1')}:</p>
<ol>
  <li>Take the square root of both sides:
    <p>${f('x - 42 = 1')} or ${f('x - 42 = -1')}</p>
  </li>
  <li>Solve for each root:
    <p>${f('x_1 = 42 + 1 = 43')}</p>
    <p>${f('x_2 = 42 - 1 = 41')}</p>
  </li>
  <li>Sum the solutions:
    <p>${f('x_1 + x_2 = 43 + 41 = 84')}</p>
  </li>
  <li>Alternatively, expanding the equation gives ${f('x^2 - 84x + 1763 = 0')}. By Vieta's formulas, the sum of solutions is ${f('-\\frac{-84}{1} = 84')}.</li>
</ol>
<p>Thus, the sum of the solutions is <strong>84</strong>.</p>`,

  // Q22
  '6a9af654838c4fe747f6e72d': `<p>To find the value of ${f('k')} such that the equation has no solution:</p>
<ol>
  <li>Expand the left side of the equation ${f('5(kx - n) = -\\frac{65}{14}x - \\frac{85}{18}')}:
    <p>${f('5kx - 5n = -\\frac{65}{14}x - \\frac{85}{18}')}</p>
  </li>
  <li>A linear equation in one variable has no solution if the coefficients of ${f('x')} are equal and the constant terms are unequal:
    <p>${f('5k = -\\frac{65}{14}')} and ${f('-5n \\ne -\\frac{85}{18}')}</p>
  </li>
  <li>Solve for ${f('k')}:
    <p>${f('k = -\\frac{65}{14 \\times 5} = -\\frac{13}{14}')}</p>
  </li>
  <li>Since ${f('n > 1')}, ${f('-5n < -5')}, whereas ${f('-\\frac{85}{18} \\approx -4.72')}, ensuring the constant terms are never equal.</li>
</ol>
<p>Therefore, the value of ${f('k')} is <strong>${f('-\\frac{13}{14}')}</strong>.</p>`
};

async function run() {
  console.log('Injecting 22 pedagogical explanations for May 2025 · INT 1 Module 1...\n');
  let count = 0;
  for (const [id, expl] of Object.entries(explanations)) {
    process.stdout.write(`Updating Q ${id} (${++count}/22)... `);
    await updateQuestion(id, { explanation: expl });
    console.log('✅');
  }
  console.log('\n🎉 Successfully injected all 22 M1 explanations!');
}

run().catch(console.error);
