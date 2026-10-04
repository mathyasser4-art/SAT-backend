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
  '6a623113c3d08d90637d34c1': `<p><strong>The correct answer is 12.</strong></p>
<p>Let ${f('n')} represent the number of attendees. The total cost consists of a one-time fee of $35 plus $15.25 per attendee:</p>
<p>${f('\\text{Total Cost} = 35 + 15.25n')}</p>
<p>To not exceed the budget of $225, set up the inequality:</p>
<p>${f('35 + 15.25n \\le 225')}</p>
<p>Subtract 35 from both sides:</p>
<p>${f('15.25n \\le 190')}</p>
<p>Divide by 15.25:</p>
<p>${f('n \\le \\frac{190}{15.25} \\approx 12.459')}</p>
<p>Since the number of attendees must be a whole number, the greatest possible number of attendees is <strong>12</strong>.</p>`,

  // Q2
  '6a6231cbc3d08d90637d34c7': `<p><strong>The correct answer is 10.</strong></p>
<p>The given function is defined by ${f('g(x) = 4x + 2')}. To find the value of ${f('g(x)')} when ${f('x = 2')}, substitute 2 for ${f('x')}:</p>
<p>${f('g(2) = 4(2) + 2 = 8 + 2 = 10')}</p>
<p>Thus, the value of ${f('g(2)')} is <strong>10</strong>.</p>`,

  // Q3
  '6a6231fbc3d08d90637d34cb': `<p><strong>The correct answer is ${f('7x(6x^2 + 1)')}.</strong></p>
<p>To factor the expression ${f('42x^3 + 7x')}, find the greatest common factor (GCF) of the two terms:</p>
<p>The greatest common factor of the numerical coefficients 42 and 7 is 7.</p>
<p>The greatest common factor of the variable parts ${f('x^3')} and ${f('x')} is ${f('x')}.</p>
<p>Factoring out ${f('7x')}:</p>
<p>${f('42x^3 + 7x = 7x(6x^2 + 1)')}</p>`,

  // Q4
  '6a623266c3d08d90637d34d7': `<p><strong>The correct answer is 134.</strong></p>
<p>The ratio of width ${f('W')} to length ${f('L')} is given as 1 to 2:</p>
<p>${f('\\frac{W}{L} = \\frac{1}{2} \\implies L = 2W')}</p>
<p>Given that the width is 67 centimeters, substitute ${f('W = 67')}:</p>
<p>${f('L = 2(67) = 134\\text{ centimeters}')}</p>`,

  // Q5
  '6a6232d6c3d08d90637d34db': `<p><strong>The correct answer is 7.5.</strong></p>
<p>Examining the scatterplot, the data displays a strong positive linear relationship between square footage (in thousands of square feet) and annual sales (in millions of dollars).</p>
<p>Notice the points nearby: at 3 thousand square feet, sales are between 4 and 7 million dollars, and at 5 to 6 thousand square feet, sales are between 7.7 and 12 million dollars.</p>
<p>A line of best fit through the data points passes through approximately ${f('(2, 4)')} and ${f('(6, 12)')}, yielding an estimated slope of:</p>
<p>${f('m \\approx \\frac{12 - 4}{6 - 2} = \\frac{8}{4} = 2')}</p>
<p>For a store of 4 thousand square feet, the predicted annual sales is approximately ${f('4 + 2(4 - 2) = 8')} million dollars. Among the given choices (4.1, 5.4, 7.5, 10.2), <strong>7.5</strong> is by far the best prediction.</p>`,

  // Q6
  '6a623318c3d08d90637d34df': `<p><strong>The correct answer is 2600.</strong></p>
<p>The equation is given by ${f('y = 2{,}600(a)^x')}, where ${f('x')} is the number of hours after the bacteria was initially measured.</p>
<p>The initially measured number corresponds to ${f('x = 0')}:</p>
<p>${f('y = 2{,}600(a)^0 = 2{,}600(1) = 2{,}600')}</p>
<p>Therefore, the predicted number of bacteria initially measured is <strong>2600</strong>.</p>`,

  // Q7
  '6a623350c3d08d90637d34eb': `<p><strong>The correct answer is 20.</strong></p>
<p>Start with the given linear equation:</p>
<p>${f('6x - 8 = 4')}</p>
<p>Add 8 to both sides to solve for ${f('6x')}:</p>
<p>${f('6x = 4 + 8 = 12')}</p>
<p>Now evaluate the expression ${f('6x + 8')} by substituting ${f('6x = 12')}:</p>
<p>${f('6x + 8 = 12 + 8 = 20')}</p>`,

  // Q8
  '6a6233acc3d08d90637d34ef': `<p><strong>The correct answer is 0.22.</strong></p>
<p>We are given that ${f('f')} is 120% greater than ${f('g')}:</p>
<p>${f('f = g + 1.20g = 2.20g')}</p>
<p>We are also given that ${f('h')} is 90% less than ${f('f')}:</p>
<p>${f('h = f - 0.90f = 0.10f')}</p>
<p>Substitute ${f('f = 2.20g')} into the equation for ${f('h')}:</p>
<p>${f('h = 0.10(2.20g) = 0.22g')}</p>
<p>Therefore, ${f('h')} is <strong>0.22</strong> times the number ${f('g')}.</p>`,

  // Q9
  '6a6233ddc3d08d90637d34f3': `<p><strong>The correct answer is 7.1%.</strong></p>
<p>To find the percentage of acres that contain rice, divide the number of rice acres by the total acres and multiply by 100%:</p>
<p>${f('\\text{Percentage} = \\frac{71}{1{,}000} \\times 100\\% = 0.071 \\times 100\\% = 7.1\\%')}</p>`,

  // Q10
  '6a623445c3d08d90637d34f7': `<p><strong>The correct answer is 32.</strong></p>
<p>In a right triangle, the sine of an acute angle is defined as the ratio of the length of the opposite side to the length of the hypotenuse:</p>
<p>${f('\\sin(\\theta) = \\frac{\\text{opposite}}{\\text{hypotenuse}}')}</p>
<p>In the given right triangle with hypotenuse ${f('c')}:</p>
<p>For the top acute angle (${f('58^\\circ')}), the opposite side is ${f('a')}, so ${f('\\sin(58^\\circ) = \\frac{a}{c}')}.</p>
<p>For the bottom-left acute angle, the opposite side is ${f('b')}, so its sine is ${f('\\frac{b}{c}')}.</p>
<p>Since we are given that ${f('\\sin D = \\frac{b}{c}')}, angle ${f('D')} must be the bottom-left acute angle.</p>
<p>Because the acute angles of a right triangle are complementary:</p>
<p>${f('m\\angle D = 90^\\circ - 58^\\circ = 32^\\circ')}</p>`,

  // Q11
  '6a623489c3d08d90637d34fb': `<p><strong>The correct answer is ${f('y < 46')}.</strong></p>
<p>In the figure, parallel lines ${f('\\ell')} and ${f('k')} are intersected by transversal line ${f('t')}.</p>
<p>The top-right angle at the intersection with line ${f('\\ell')} is ${f('x^\\circ')}. The adjacent angle forming a linear pair on line ${f('\\ell')} is ${f('(180 - x)^\\circ')}.</p>
<p>By corresponding angles formed by parallel lines cut by a transversal, the angle labeled ${f('y^\\circ')} corresponds directly to this adjacent angle:</p>
<p>${f('x + y = 180 \\implies y = 180 - x')}</p>
<p>We are given that ${f('x > 134')}. Multiplying the inequality by ${f('-1')} reverses the inequality sign:</p>
<p>${f('-x < -134')}</p>
<p>Add 180 to both sides:</p>
<p>${f('180 - x < 180 - 134 \\implies y < 46')}</p>
<p>Thus, ${f('y < 46')} must be true.</p>`,

  // Q12
  '6a6234e5c3d08d90637d34ff': `<p><strong>The correct answer is ${f('y = \\frac{x}{8} - 11')}.</strong></p>
<p>Use the point-slope form of a linear equation, ${f('y - y_1 = m(x - x_1)')}, with slope ${f('m = \\frac{1}{8}')} and point ${f('(x_1, y_1) = (32, -7)')}:</p>
<p>${f('y - (-7) = \\frac{1}{8}(x - 32)')}</p>
<p>${f('y + 7 = \\frac{1}{8}x - 4')}</p>
<p>Subtract 7 from both sides to convert to slope-intercept form:</p>
<p>${f('y = \\frac{x}{8} - 11')}</p>`,

  // Q13
  '6a62352dc3d08d90637d3503': `<p><strong>The correct answer is "Each game costs $16".</strong></p>
<p>In the graph of total cost ${f('y')} versus number of games ${f('x')}:</p>
<p>The slope of a linear graph represents the rate of change of the vertical axis variable with respect to the horizontal axis variable:</p>
<p>${f('\\text{Slope} = \\frac{\\Delta y}{\\Delta x} = \\frac{\\text{change in total cost (dollars)}}{\\text{change in number of games}}')}</p>
<p>From the graph, the line passes through ${f('(0, 50)')} and ${f('(10, 210)')}:</p>
<p>${f('\\text{Slope} = \\frac{210 - 50}{10 - 0} = \\frac{160}{10} = 16')}</p>
<p>This means each additional game increases the total cost by $16, or equivalently, <strong>each game costs $16</strong>.</p>
<p><em>Note:</em> The ${f('y')}-intercept of 50 represents the initial cost of the video game system alone ($50).</p>`,

  // Q14
  '6a623556c3d08d90637d3509': `<p><strong>The correct answer is 19.</strong></p>
<p>The standard equation of a circle in the ${f('xy')}-plane is:</p>
<p>${f('(x - h)^2 + (y - k)^2 = r^2')}</p>
<p>where ${f('(h, k)')} is the center and ${f('r')} is the radius of the circle.</p>
<p>Comparing this to the given equation ${f('(x + 2)^2 + (y + 6)^2 = 361')}:</p>
<p>${f('r^2 = 361')}</p>
<p>Taking the positive square root:</p>
<p>${f('r = \\sqrt{361} = 19')}</p>`,

  // Q15
  '6a623596c3d08d90637d350d': `<p><strong>The correct answer is -32.</strong></p>
<p>From the second equation, solve for ${f('y')}:</p>
<p>${f('y - 4x = 0 \\implies y = 4x')}</p>
<p>Substitute ${f('y = 4x')} into the first equation:</p>
<p>${f('x^2 + (4x)^2 = 1{,}088')}</p>
<p>${f('x^2 + 16x^2 = 1{,}088')}</p>
<p>${f('17x^2 = 1{,}088')}</p>
<p>Divide by 17:</p>
<p>${f('x^2 = 64')}</p>
<p>Since we are given that ${f('x < 0')}, ${f('x = -8')}.</p>
<p>Now find ${f('y')}:</p>
<p>${f('y = 4x = 4(-8) = -32')}</p>`,

  // Q16
  '6a6235bfc3d08d90637d3511': `<p><strong>The correct answer is 470.</strong></p>
<p>The given function is ${f('f(x) = 10(x^2 + 47) = 10x^2 + 470')}.</p>
<p>For all real values of ${f('x')}, ${f('x^2 \\ge 0')}. The minimum value of ${f('x^2')} is 0, which occurs at ${f('x = 0')}.</p>
<p>Substituting ${f('x = 0')}:</p>
<p>${f('f(0) = 10(0^2 + 47) = 10(47) = 470')}</p>
<p>Thus, the minimum value of ${f('f(x)')} is <strong>470</strong>.</p>`,

  // Q17
  '6a623607c3d08d90637d3515': `<p><strong>The correct answer is ${f('\\frac{19}{6}')}.</strong></p>
<p>We are given the two functions:</p>
<p>${f('j(x) = \\frac{10x + 5}{3p}')}</p>
<p>${f('k(x) = \\frac{j(x) \\cdot p}{x + 1}')}</p>
<p>Substitute the expression for ${f('j(x)')} into ${f('k(x)')}:</p>
<p>${f('k(x) = \\frac{\\left(\\frac{10x + 5}{3p}\\right) \\cdot p}{x + 1}')}</p>
<p>The constant ${f('p')} cancels in the numerator:</p>
<p>${f('k(x) = \\frac{\\frac{10x + 5}{3}}{x + 1} = \\frac{10x + 5}{3(x + 1)}')}</p>
<p>Now evaluate ${f('k(9)')}:</p>
<p>${f('k(9) = \\frac{10(9) + 5}{3(9 + 1)} = \\frac{90 + 5}{3(10)} = \\frac{95}{30}')}</p>
<p>Reduce the fraction by dividing the numerator and denominator by 5:</p>
<p>${f('\\frac{95 \\div 5}{30 \\div 5} = \\frac{19}{6}')}</p>`,

  // Q18
  '6a623696c3d08d90637d3519': `<p><strong>The correct answer is "The region where ${f('x < 0')} and ${f('y > 0')}".</strong></p>
<p>Rewrite the inequality ${f('7x - 6y > 42')} in terms of ${f('y')}:</p>
<p>${f('-6y > -7x + 42')}</p>
<p>Divide by ${f('-6')} and reverse the inequality sign:</p>
<p>${f('y < \\frac{7}{6}x - 7')}</p>
<p>Now consider the region where ${f('x < 0')} and ${f('y > 0')} (Quadrant II):</p>
<p>If ${f('x < 0')}, then ${f('\\frac{7}{6}x < 0')}, which means:</p>
<p>${f('\\frac{7}{6}x - 7 < -7')}</p>
<p>For any point in Quadrant II, ${f('y > 0')}. However, the inequality requires ${f('y < \\frac{7}{6}x - 7 < -7')}. A positive value of ${f('y')} can never be less than ${f('-7')}.</p>
<p>Therefore, this region contains no points in the solution set.</p>`,

  // Q19
  '6a6236d0c3d08d90637d3521': `<p><strong>The correct answer is "Infinitely many".</strong></p>
<p>Given the system of equations:</p>
<p>1) ${f('3x + 2y = 10')}</p>
<p>2) ${f('18x + 12y = 60')}</p>
<p>Divide the second equation by 6:</p>
<p>${f('\\frac{18x + 12y}{6} = \\frac{60}{6} \\implies 3x + 2y = 10')}</p>
<p>Since both equations represent the exact same line, every point on the line is a solution to the system. Therefore, the system has <strong>infinitely many solutions</strong>.</p>`,

  // Q20
  '6a6237e1c3d08d90637d352b': `<p><strong>The correct answer is 24.</strong></p>
<p>Start with the given equation:</p>
<p>${f('\\frac{|4x - 48| + 4}{8} = 6')}</p>
<p>Multiply both sides by 8:</p>
<p>${f('|4x - 48| + 4 = 48')}</p>
<p>Subtract 4 from both sides:</p>
<p>${f('|4x - 48| = 44')}</p>
<p>This gives two possible cases:</p>
<p><strong>Case 1:</strong></p>
<p>${f('4x - 48 = 44 \\implies 4x = 92 \\implies x = 23')}</p>
<p><strong>Case 2:</strong></p>
<p>${f('4x - 48 = -44 \\implies 4x = 4 \\implies x = 1')}</p>
<p>The sum of the values of ${f('x')} is:</p>
<p>${f('23 + 1 = 24')}</p>`,

  // Q21
  '6a6238b7c3d08d90637d3538': `<p><strong>The correct answer is ${f('p(w) = 1{,}485 - 165w')}.</strong></p>
<p>The initial population is 1,600 bees, and the goal is 2,975 bees.</p>
<p>In the first 2 weeks, the population increases by 110 bees per week:</p>
<p>${f('\\text{Population after 2 weeks} = 1{,}600 + 2(110) = 1{,}600 + 220 = 1{,}820')}</p>
<p>For ${f('w > 2')}, the number of additional weeks past week 2 is ${f('w - 2')}. During these weeks, the colony increases by 165 bees per week:</p>
<p>${f('\\text{Population at week } w = 1{,}820 + 165(w - 2) = 1{,}820 + 165w - 330 = 1{,}490 + 165w')}</p>
<p>The function ${f('p(w)')} gives the number of bees <em>still needed</em> to reach the goal of 2,975:</p>
<p>${f('p(w) = 2{,}975 - (1{,}490 + 165w) = 2{,}975 - 1{,}490 - 165w = 1{,}485 - 165w')}</p>`,

  // Q22
  '6a6238e4c3d08d90637d353c': `<p><strong>The correct answer is 0.</strong></p>
<p>Consider the equation ${f('(2x - 64)^2 = a')}:</p>
<p>If ${f('a > 0')}, taking the square root gives two distinct solutions: ${f('2x - 64 = \\pm\\sqrt{a}')}.</p>
<p>If ${f('a < 0')}, there are no real solutions because the square of any real expression is nonnegative.</p>
<p>If ${f('a = 0')}, the equation becomes ${f('(2x - 64)^2 = 0 \\implies 2x - 64 = 0 \\implies x = 32')}, which has exactly one real solution.</p>
<p>Therefore, the value of constant ${f('a')} must be <strong>0</strong>.</p>`
};

async function run() {
  console.log('🚀 Injecting 22 explanations for November 2025 · INT 3 Module 1...\n');
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
