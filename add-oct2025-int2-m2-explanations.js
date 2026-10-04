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
  '6a6289acc3d08d90637d379a': `<p><strong>The correct answer is ${f('12yz^3 + 6yz')}.</strong></p>
<p>Combine like terms in the expression ${f('9yz^3 + 6yz + 3yz^3')}:</p>
<p>Notice that ${f('9yz^3')} and ${f('3yz^3')} have identical variable parts:</p>
<p>${f('(9yz^3 + 3yz^3) + 6yz = (9 + 3)yz^3 + 6yz = 12yz^3 + 6yz')}</p>`,

  // Q2
  '6a628ce9c3d08d90637d37b8': `<p><strong>The correct answer is "2 years after the investment was made, the value of the CD was approximately 9,474.08 dollars."</strong></p>
<p>In the given function ${f('f(x) = 9{,}000(1 + 0.03)^x')}:</p>
<p>• The input variable ${f('x')} represents the number of years after the investment was initially made.</p>
<p>• The function output ${f('f(x)')} represents the value of the certificate of deposit (CD) in dollars.</p>
<p>Therefore, ${f('f(2) \\approx 9{,}474.08')} means that 2 years after the initial investment was made, the value of the CD was approximately $9,474.08.</p>`,

  // Q3
  '6a628d9fc3d08d90637d37be': `<p><strong>The correct answer is ${f('35x - 49y = -126')}.</strong></p>
<p>From the graph, the line passes through the points ${f('(-5, -1)')} and ${f('(2, 4)')}.</p>
<p>First, find the slope of the line:</p>
<p>${f('m = \\frac{4 - (-1)}{2 - (-5)} = \\frac{5}{7}')}</p>
<p>Using point-slope form with ${f('(2, 4)')}:</p>
<p>${f('y - 4 = \\frac{5}{7}(x - 2)')}</p>
<p>Multiply both sides by 7:</p>
<p>${f('7(y - 4) = 5(x - 2)')}</p>
<p>${f('7y - 28 = 5x - 10')}</p>
<p>Rearrange into standard form:</p>
<p>${f('5x - 7y = -18')}</p>
<p>To match the given options, multiply the entire equation by 7:</p>
<p>${f('7(5x - 7y) = 7(-18) \\implies 35x - 49y = -126')}</p>`,

  // Q4
  '6a628e90c3d08d90637d37c8': `<p><strong>The correct answer is 18.</strong></p>
<p>We are given the system of equations:</p>
<p>1) ${f('5y = 6x + 17')}</p>
<p>2) ${f('-5y = 7x - 23')}</p>
<p>Add both equations together to eliminate the ${f('y')} variable:</p>
<p>${f('5y + (-5y) = (6x + 17) + (7x - 23)')}</p>
<p>${f('0 = 13x - 6')}</p>
<p>${f('13x = 6')}</p>
<p>The question asks for the value of ${f('39x')}. Since ${f('39 = 3 \\times 13')}:</p>
<p>${f('39x = 3(13x) = 3(6) = 18')}</p>`,

  // Q5
  '6a628f63c3d08d90637d37d2': `<p><strong>The correct answer is ${f('y > 4x + 3')}.</strong></p>
<p>First, determine the equation of the boundary line:</p>
<p>• The line passes through the ${f('y')}-intercept ${f('(0, 3)')} and the point ${f('(2, 11)')}.</p>
<p>• The slope of the line is:</p>
<p>${f('m = \\frac{11 - 3}{2 - 0} = \\frac{8}{2} = 4')}</p>
<p>Thus, the equation of the boundary line is ${f('y = 4x + 3')}.</p>
<p>Because the line is dashed, the inequality is strict (${f('>')} or ${f('<')}).</p>
<p>The region above the line is shaded. Testing a point in the shaded region such as ${f('(-2, 2)')}:</p>
<p>${f('2 > 4(-2) + 3 \\implies 2 > -5')} (True).</p>
<p>Therefore, the inequality is ${f('y > 4x + 3')}.</p>`,

  // Q6
  '6a6291dec3d08d90637d380e': `<p><strong>The correct answer is ${f('(x + 5)^2 + (y - 2)^2 = 25')}.</strong></p>
<p>The standard equation of a circle with center ${f('(h, k)')} and radius ${f('r')} is:</p>
<p>${f('(x - h)^2 + (y - k)^2 = r^2')}</p>
<p>Given the center ${f('(h, k) = (-5, 2)')}, the equation begins:</p>
<p>${f('(x - (-5))^2 + (y - 2)^2 = r^2 \\implies (x + 5)^2 + (y - 2)^2 = r^2')}</p>
<p>Since the point ${f('(-9, 5)')} lies on the circle, calculate ${f('r^2')} using the distance formula:</p>
<p>${f('r^2 = (-9 - (-5))^2 + (5 - 2)^2 = (-4)^2 + 3^2 = 16 + 9 = 25')}</p>
<p>Therefore, the equation of the circle is:</p>
<p>${f('(x + 5)^2 + (y - 2)^2 = 25')}</p>`,

  // Q7
  '6a629268c3d08d90637d3818': `<p><strong>The correct answer is (-3, 0).</strong></p>
<p>Substitute each given point ${f('(x, y)')} into the inequality ${f('y < -3x + 18')}:</p>
<p>• For ${f('(-3, 0)')}: ${f('-3(-3) + 18 = 9 + 18 = 27')}. Since ${f('0 < 27')} is true, <strong>(-3, 0)</strong> is a solution.</p>
<p>• For ${f('(0, 19)')}: ${f('-3(0) + 18 = 18')}. ${f('19 < 18')} is false.</p>
<p>• For ${f('(-1, 22)')}: ${f('-3(-1) + 18 = 21')}. ${f('22 < 21')} is false.</p>
<p>• For ${f('(7, -1)')}: ${f('-3(7) + 18 = -3')}. ${f('-1 < -3')} is false.</p>`,

  // Q8
  '6a6292f1c3d08d90637d381e': `<p><strong>The correct answer is 45.</strong></p>
<p>Expand both sides of the given equation:</p>
<p>${f('18(x + 5) = 2(x + c) + 16x')}</p>
<p>${f('18x + 90 = 2x + 2c + 16x')}</p>
<p>Combine like terms on the right side:</p>
<p>${f('18x + 90 = 18x + 2c')}</p>
<p>For an equation to have infinitely many solutions, the coefficients of ${f('x')} must be equal and the constant terms must be equal:</p>
<p>${f('2c = 90 \\implies c = 45')}</p>`,

  // Q9
  '6a6293c9c3d08d90637d3828': `<p><strong>The correct answer is 196.</strong></p>
<p>From the table, when ${f('x = 6')}, ${f('y = 0')}.</p>
<p>Substitute ${f('(6, 0)')} into the quadratic equation ${f('y = 36x^2 - bx - 120')}:</p>
<p>${f('0 = 36(6)^2 - b(6) - 120')}</p>
<p>${f('0 = 36(36) - 6b - 120')}</p>
<p>${f('0 = 1{,}296 - 120 - 6b')}</p>
<p>${f('6b = 1{,}176')}</p>
<p>Divide by 6:</p>
<p>${f('b = \\frac{1{,}176}{6} = 196')}</p>`,

  // Q10
  '6a62950ac3d08d90637d382c': `<p><strong>The correct answer is ${f('7h + 10w = 114{,}450')}.</strong></p>
<p>Hannah saves ${f('\\frac{1}{5}')} of her salary ${f('h')}, and Wyatt saves ${f('\\frac{2}{7}')} of his salary ${f('w')}.</p>
<p>Their total monthly savings is $3,270:</p>
<p>${f('\\frac{1}{5}h + \\frac{2}{7}w = 3{,}270')}</p>
<p>Multiply the entire equation by the least common multiple of the denominators (35):</p>
<p>${f('35 \\left(\\frac{1}{5}h\\right) + 35 \\left(\\frac{2}{7}w\\right) = 35(3{,}270)')}</p>
<p>${f('7h + 10w = 114{,}450')}</p>`,

  // Q11
  '6a6296d3c3d08d90637d3832': `<p><strong>The correct answer is I and III only.</strong></p>
<p>Start with the equation:</p>
<p>${f('x - a = (x - a)(x - 24)')}</p>
<p>Subtract ${f('x - a')} from both sides:</p>
<p>${f('(x - a)(x - 24) - (x - a) = 0')}</p>
<p>Factor out the common factor ${f('(x - a)')}:</p>
<p>${f('(x - a)[(x - 24) - 1] = 0')}</p>
<p>${f('(x - a)(x - 25) = 0')}</p>
<p>Setting each factor to zero gives the solutions:</p>
<p>• ${f('x - a = 0 \\implies x = a')} (Statement I)</p>
<p>• ${f('x - 25 = 0 \\implies x = 25')} (Statement III)</p>
<p>Notice that ${f('x = 24')} is NOT a solution, since substituting ${f('x = 24')} yields ${f('24 - a = (24 - a)(0) = 0 \\implies a = 24')}, which contradicts ${f('a > 25')}.</p>
<p>Therefore, <strong>I and III only</strong> are solutions.</p>`,

  // Q12
  '6a629740c3d08d90637d383c': `<p><strong>The correct answer is 4.</strong></p>
<p>Given the equation:</p>
<p>${f('\\sqrt{x - 1} = 2')}</p>
<p>Square both sides of the equation:</p>
<p>${f('(\\sqrt{x - 1})^2 = 2^2')}</p>
<p>${f('x - 1 = 4')}</p>
<p>The question asks for the value of ${f('x - 1')}, which is <strong>4</strong>.</p>`,

  // Q13
  '6a6297e0c3d08d90637d3840': `<p><strong>The correct answer is 2.</strong></p>
<p>The rectangular pool has length 21 ft and width 11 ft, giving an area of:</p>
<p>${f('\\text{Area}_{\\text{pool}} = 21 \\times 11 = 231\\text{ ft}^2')}</p>
<p>The concrete path surrounds the pool with a uniform width of ${f('x')} ft. The total outer dimensions including the path are:</p>
<p>• Total length = ${f('21 + 2x')}</p>
<p>• Total width = ${f('11 + 2x')}</p>
<p>The total area of the pool plus the path is:</p>
<p>${f('\\text{Total Area} = (21 + 2x)(11 + 2x) = 231 + 64x + 4x^2')}</p>
<p>The area of the path alone is the total area minus the pool's area:</p>
<p>${f('\\text{Area}_{\\text{path}} = 4x^2 + 64x')}</p>
<p>We are given that the area of the path is 144 square feet:</p>
<p>${f('4x^2 + 64x = 144')}</p>
<p>Divide the entire equation by 4:</p>
<p>${f('x^2 + 16x = 36 \\implies x^2 + 16x - 36 = 0')}</p>
<p>Factor the quadratic equation:</p>
<p>${f('(x + 18)(x - 2) = 0')}</p>
<p>Since the path width must be positive, ${f('x = 2\\text{ ft}')}.</p>`,

  // Q14
  '6a629918c3d08d90637d384a': `<p><strong>The correct answer is "The median of data set B is equal to the median of data set A."</strong></p>
<p>Data set A contains 21 ordered observations, so its median is the 11th observation.</p>
<p>The errant value of 19 is an extreme value located at the upper end of the distribution.</p>
<p>Removing this largest value produces data set B with 20 observations, whose median is the average of the 10th and 11th values.</p>
<p>Because the middle values around the median in the data set are identical, both the 10th and 11th values equal the original median.</p>
<p>Therefore, the median of data set B is equal to the median of data set A.</p>`,

  // Q15
  '6a6299b7c3d08d90637d3850': `<p><strong>The correct answer is ${f('P = \\frac{w}{35}')}.</strong></p>
<p>The total wall area of the room is ${f('w')} square feet. Painting the walls twice means the total surface area to be painted is:</p>
<p>${f('\\text{Total Surface Area} = 2w\\text{ square feet}')}</p>
<p>Each gallon of paint covers 70 square feet. The number of gallons ${f('P')} required is:</p>
<p>${f('P = \\frac{2w}{70} = \\frac{w}{35}')}</p>`,

  // Q16
  '6a629a76c3d08d90637d385a': `<p><strong>The correct answer is ${f('f(x) = \\frac{1}{1024} \\left(\\frac{1}{4}\\right)^{5x}')}.</strong></p>
<p>The ${f('y')}-intercept of the graph of ${f('y = f(x)')} occurs at ${f('x = 0')}:</p>
<p>${f('f(0) = 4^{-5(0 + 1)} = 4^{-5} = \\frac{1}{4^5} = \\frac{1}{1{,}024}')}</p>
<p>Rewrite the function using properties of exponents:</p>
<p>${f('f(x) = 4^{-5(x + 1)} = 4^{-5x - 5} = 4^{-5} \\cdot 4^{-5x} = \\frac{1}{1{,}024} \\left(4^{-1}\\right)^{5x} = \\frac{1}{1{,}024} \\left(\\frac{1}{4}\\right)^{5x}')}</p>
<p>In this form, the ${f('y')}-intercept ${f('\\frac{1}{1{,}024}')}$ is explicitly displayed as the leading coefficient of the expression.</p>`,

  // Q17
  '6a629b37c3d08d90637d3860': `<p><strong>The correct answer is 0.125 (or 1/8).</strong></p>
<p>Express the radicals in exponential form with base ${f('(117n)')}:</p>
<p>${f('\\sqrt{117n} = (117n)^{1/2}')}</p>
<p>${f('(\\sqrt{117n})^2 = (117n)^1')}</p>
<p>Multiply the two factors using the product rule for exponents:</p>
<p>${f('\\sqrt{117n} (\\sqrt{117n})^2 = (117n)^{1/2} \\cdot (117n)^1 = (117n)^{1/2 + 1} = (117n)^{3/2}')}</p>
<p>We are given that this is equivalent to ${f('(117n)^{12x}')}:</p>
<p>${f('12x = \\frac{3}{2}')}</p>
<p>Divide by 12:</p>
<p>${f('x = \\frac{3}{2 \\times 12} = \\frac{3}{24} = \\frac{1}{8} = 0.125')}</p>`,

  // Q18
  '6a629d10c3d08d90637d386c': `<p><strong>The correct answer is 1680.</strong></p>
<p>From the table, the volume of cylinder A is ${f('V_A = 392\\pi')} and cylinder B is ${f('V_B = 10{,}584\\pi')}.</p>
<p>First, find the height ${f('h_A')} of cylinder A using its radius ${f('r_A = 7')}:</p>
<p>${f('V_A = \\pi r_A^2 h_A \\implies 392\\pi = \\pi (7^2) h_A = 49\\pi h_A')}</p>
<p>${f('h_A = \\frac{392}{49} = 8')}</p>
<p>Calculate the surface area of cylinder A:</p>
<p>${f('SA_A = 2\\pi r_A^2 + 2\\pi r_A h_A = 2\\pi(49) + 2\\pi(7)(8) = 98\\pi + 112\\pi = 210\\pi')}</p>
<p>Thus, ${f('k = 210')}.</p>
<p>Because the cylinders are similar, the ratio of their volumes is the cube of their linear scale factor ${f('c')}:</p>
<p>${f('c^3 = \\frac{V_B}{V_A} = \\frac{10{,}584\\pi}{392\\pi} = 27 \\implies c = \\sqrt[3]{27} = 3')}</p>
<p>The ratio of their surface areas is ${f('c^2 = 3^2 = 9')}:</p>
<p>${f('SA_B = 9 \\times SA_A = 9(210\\pi) = 1{,}890\\pi')}</p>
<p>Thus, ${f('n = 1{,}890')}.</p>
<p>Finally, find ${f('n - k')}:</p>
<p>${f('n - k = 1{,}890 - 210 = 1{,}680')}</p>`,

  // Q19
  '6a6638f3c3d08d90637d38a1': `<p><strong>The correct answer is 16,788.</strong></p>
<p>The volume of the wall of the hollow cylindrical pipe is:</p>
<p>${f('V = \\pi h (R^2 - r^2)')}</p>
<p>Given:</p>
<p>• Outside diameter = 60 inches ${f('\\implies R = 30\\text{ inches}')}</p>
<p>• Wall thickness = ${f('\\frac{5}{8} = 0.625\\text{ inches}')}</p>
<p>• Inside radius ${f('r = 30 - 0.625 = 29.375\\text{ inches}')}</p>
<p>• Height ${f('h = 144\\text{ inches}')}</p>
<p>Compute ${f('R^2 - r^2')}:</p>
<p>${f('R^2 - r^2 = (30 - 29.375)(30 + 29.375) = (0.625)(59.375) = 37.109375')}</p>
<p>Compute the volume:</p>
<p>${f('V = \\pi \\times 144 \\times 37.109375 = 5{,}343.75\\pi \\approx 16{,}787.9\\text{ cubic inches}')}</p>
<p>Rounding to the nearest integer gives <strong>16,788</strong>.</p>`,

  // Q20
  '6a66395fc3d08d90637d38ad': `<p><strong>The correct answer is 15.</strong></p>
<p>Notice the repeated expression ${f('5 - 2x')} on both sides of the equation:</p>
<p>${f('8(5 - 2x) + 3 = 7(5 - 2x) + 18')}</p>
<p>Let ${f('u = 5 - 2x')}. The equation simplifies to:</p>
<p>${f('8u + 3 = 7u + 18')}</p>
<p>Subtract ${f('7u')} from both sides:</p>
<p>${f('u + 3 = 18')}</p>
<p>Subtract 3 from both sides:</p>
<p>${f('u = 15')}</p>
<p>Therefore, the value of ${f('5 - 2x')} is <strong>15</strong>.</p>`,

  // Q21
  '6a6639fac3d08d90637d38b1': `<p><strong>The correct answer is ${f('\\frac{1}{4}\\pi')}.</strong></p>
<p>To convert an angle from degrees to radians, multiply by ${f('\\frac{\\pi}{180^\\circ}')}:</p>
<p>${f('\\text{Radians} = 45^\\circ \\times \\frac{\\pi}{180^\\circ} = \\frac{45}{180}\\pi = \\frac{1}{4}\\pi')}</p>`,

  // Q22
  '6a663ab4c3d08d90637d38b5': `<p><strong>The correct answer is 15435.</strong></p>
<p>The breaking strength is given by ${f('y = 900ax^2')}, where ${f('x')} is the circumference.</p>
<p>Notice that ${f('y')} is directly proportional to the square of the circumference (${f('x^2')}):</p>
<p>${f('\\frac{y_2}{y_1} = \\left(\\frac{x_2}{x_1}\\right)^2')}</p>
<p>Given ${f('x_1 = 1.75')} with ${f('y_1 = 3{,}858.75')}, and we want to find ${f('y_2')} for ${f('x_2 = 3.50')}:</p>
<p>Notice that ${f('x_2 = 2 \\times x_1')} (the circumference doubles):</p>
<p>${f('\\frac{y_2}{3{,}858.75} = \\left(\\frac{3.50}{1.75}\\right)^2 = 2^2 = 4')}</p>
<p>Multiply both sides by 3,858.75:</p>
<p>${f('y_2 = 4 \\times 3{,}858.75 = 15{,}435\\text{ pounds}')}</p>`
};

async function run() {
  console.log('🚀 Injecting 22 explanations for October 2025 · INT 2 Module 2...\n');
  const ids = Object.keys(explanations);
  let successCount = 0;

  for (let i = 0; i < ids.length; i++) {
    const id = ids[i];
    process.stdout.write(`Updating M2 Q${i + 1} (${id})... `);
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

  console.log(`\n🎉 Finished Module 2: ${successCount}/${ids.length} explanations injected successfully!`);
}

run().catch(console.error);
