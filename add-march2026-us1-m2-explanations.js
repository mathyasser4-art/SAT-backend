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
  '6a51b5e34d554e04aa1befee': `<p><strong>Choice B is correct.</strong></p>
<p>The probability of an event is calculated as the ratio of the number of favorable outcomes to the total number of possible outcomes:</p>
<p>${f('\\text{Probability} = \\frac{\\text{Number of favorable outcomes}}{\\text{Total number of outcomes}}')}</p>
<p>According to the given table, there were 9 people who chose a vegetarian entree out of a total of 50 attendees.</p>
<p>Therefore, the probability of selecting a person who chose a vegetarian entree is ${f('\\frac{9}{50}')}.</p>
<p><strong>Choice A is incorrect</strong> because it uses a denominator of 100 rather than the actual total of 50 people.</p>
<p><strong>Choice C is incorrect</strong> because it represents choosing 1 of the 4 entree types rather than the probability based on the number of people.</p>
<p><strong>Choice D is incorrect</strong> and may result from a calculation error.</p>`,

  // Q2
  '6a51b65a4d554e04aa1bf007': `<p><strong>Choice D is correct.</strong></p>
<p>We are given the linear equation ${f('3x = 7')} and asked to find the value of ${f('12x')}.</p>
<p>Notice that ${f('12x = 4 \\times (3x)')}. We can multiply both sides of the given equation by 4:</p>
<p>${f('4 \\times (3x) = 4 \\times 7')}</p>
<p>${f('12x = 28')}</p>
<p>Alternatively, solving for ${f('x')} gives ${f('x = \\frac{7}{3}')}. Substituting this into ${f('12x')} yields ${f('12 \\times \\frac{7}{3} = 4 \\times 7 = 28')}.</p>
<p><strong>Choice A is incorrect</strong> and may result from dividing rather than multiplying.</p>
<p><strong>Choice B is incorrect</strong> and may result from adding 4 instead of multiplying by 4 (${f('7 + 4 = 11')}).</p>
<p><strong>Choice C is incorrect</strong> and may result from an arithmetic error.</p>`,

  // Q3
  '6a51b6f84d554e04aa1bf013': `<p><strong>The correct answer is 320.</strong></p>
<p>The function is defined by the equation ${f('f(x) = 32x')}.</p>
<p>To find the value of ${f('f(10)')}, substitute ${f('x = 10')} into the function definition:</p>
<p>${f('f(10) = 32(10) = 320')}</p>`,

  // Q4
  '6a5259f84d554e04aa1bf136': `<p><strong>The correct answer is 12.</strong></p>
<p>To multiply the monomials ${f('4x^3')} and ${f('3x^4')}, multiply the numerical coefficients and use the product rule of exponents (${f('x^a \\cdot x^b = x^{a+b}')}) for the variable parts:</p>
<p>${f('4x^3 \\cdot 3x^4 = (4 \\cdot 3)(x^3 \\cdot x^4) = 12x^{3+4} = 12x^7')}</p>
<p>The resulting expression is ${f('12x^7')}. Setting this equal to ${f('bx^7')}, we see that ${f('b = 12')}.</p>`,

  // Q5
  '6a525a634d554e04aa1bf142': `<p><strong>Choice B is correct.</strong></p>
<p>A system of two linear equations in two variables has infinitely many solutions if and only if both equations represent the exact same line (that is, the equations are equivalent).</p>
<p>The first equation is:</p>
<p>${f('y = 10x + 48')}</p>
<p>Subtracting ${f('10x')} from both sides of the equation yields:</p>
<p>${f('y - 10x = 48')}</p>
<p>This is identical to the equation in Choice B, so the system has infinitely many solutions.</p>
<p><strong>Choice A is incorrect</strong> because ${f('y - 10x = -48')} has the same slope but a different y-intercept, meaning the lines are parallel and would have zero solutions.</p>
<p><strong>Choices C and D are incorrect</strong> because their slope is different (${f('m = 12')} instead of ${f('m = 10')}), resulting in exactly one solution.</p>`,

  // Q6
  '6a525c754d554e04aa1bf157': `<p><strong>Choice C is correct.</strong></p>
<p>In a right triangle, the cosine of an acute angle is defined as the ratio of the length of the adjacent leg to the length of the hypotenuse:</p>
<p>${f('\\cos(A) = \\frac{\\text{Adjacent leg}}{\\text{Hypotenuse}}')}</p>
<p>From the given figure:</p>
<p>• The leg adjacent to angle ${f('A')} is ${f('AC = 22')}.</p>
<p>• The hypotenuse is ${f('AB = 43')}.</p>
<p>Therefore:</p>
<p>${f('\\cos(A) = \\frac{22}{43}')}</p>
<p><strong>Choices A and B are incorrect</strong> because they incorrectly use 1 in the numerator.</p>
<p><strong>Choice D is incorrect</strong> because it is the reciprocal (${f('\\sec(A) = \\frac{43}{22}')}).</p>`,

  // Q7
  '6a525dde4d554e04aa1bf175': `<p><strong>Choice A is correct.</strong></p>
<p>We are given the formula:</p>
<p>${f('R = \\frac{0.43l}{A}')}</p>
<p>To express ${f('l')} in terms of ${f('R')} and ${f('A')}, isolate ${f('l')}:</p>
<p>1. Multiply both sides by ${f('A')}:</p>
<p>${f('RA = 0.43l')}</p>
<p>2. Divide both sides by 0.43:</p>
<p>${f('l = \\frac{RA}{0.43}')}</p>
<p><strong>Choice B is incorrect</strong> because it adds ${f('R')} and ${f('A')} instead of multiplying them.</p>
<p><strong>Choice C is incorrect</strong> because ${f('A')} should be in the numerator, not the denominator.</p>
<p><strong>Choice D is incorrect</strong> because ${f('RA')} and ${f('AR')} are equivalent, but Choice A is the standard representation.</p>`,

  // Q8
  '6a525e5a4d554e04aa1bf17b': `<p><strong>Choice B is correct.</strong></p>
<p>There are 450 total objects, and 8% of them are spheres. To find the number of spheres, multiply 450 by 0.08 (the decimal equivalent of 8%):</p>
<p>${f('450 \\times 0.08 = 36')}</p>
<p>Therefore, there are 36 spheres in the box.</p>
<p><strong>Choice A is incorrect</strong> because 8 is the percentage, not the actual count.</p>
<p><strong>Choice C is incorrect</strong> and may result from calculating 40% of 450.</p>
<p><strong>Choice D is incorrect</strong> because it subtracts 8 from 450 (${f('450 - 8 = 442')}).</p>`,

  // Q9
  '6a525ec84d554e04aa1bf187': `<p><strong>Choice C is correct.</strong></p>
<p>The area of a rectangle is equal to the product of its length and its width:</p>
<p>${f('\\text{Area} = \\text{length} \\times \\text{width}')}</p>
<p>Given a length of 10 centimeters and a width of 6.000 centimeters:</p>
<p>${f('\\text{Area} = 10 \\times 6.000 = 60.000\\text{ cm}^2')}</p>
<p><strong>Choice A is incorrect</strong> because 10 is only the length.</p>
<p><strong>Choice B is incorrect</strong> because it represents adding the dimensions rather than multiplying them.</p>
<p><strong>Choice D is incorrect</strong> and may result from an addition error.</p>`,

  // Q10
  '6a525fdc4d554e04aa1bf191': `<p><strong>The correct answer is 580.6.</strong></p>
<p>The surface area of a right rectangular pyramid is the sum of the area of the rectangular base and the areas of the four triangular lateral faces.</p>
<p><strong>1. Area of the base:</strong></p>
<p>${f('\\text{Base Area} = l \\times w = 16 \\times 8 = 128')}</p>
<p><strong>2. Lateral faces with base ${f('l = 16')}:</strong></p>
<p>The distance from the center of the base to the edge of length 16 is ${f('\\frac{w}{2} = \\frac{8}{2} = 4')}.</p>
<p>Using the Pythagorean theorem, the slant height ${f('s_1')} is:</p>
<p>${f('s_1 = \\sqrt{h^2 + 4^2} = \\sqrt{18^2 + 16} = \\sqrt{324 + 16} = \\sqrt{340}')}</p>
<p>The area of these two triangular faces combined is:</p>
<p>${f('2 \\times \\left(\\frac{1}{2} \\times 16 \\times \\sqrt{340}\\right) = 16\\sqrt{340} \\approx 16 \\times 18.43909 = 295.025')}</p>
<p><strong>3. Lateral faces with base ${f('w = 8')}:</strong></p>
<p>The distance from the center of the base to the edge of width 8 is ${f('\\frac{l}{2} = \\frac{16}{2} = 8')}.</p>
<p>Using the Pythagorean theorem, the slant height ${f('s_2')} is:</p>
<p>${f('s_2 = \\sqrt{h^2 + 8^2} = \\sqrt{18^2 + 64} = \\sqrt{324 + 64} = \\sqrt{388}')}</p>
<p>The area of these two triangular faces combined is:</p>
<p>${f('2 \\times \\left(\\frac{1}{2} \\times 8 \\times \\sqrt{388}\\right) = 8\\sqrt{388} \\approx 8 \\times 19.69772 = 157.582')}</p>
<p><strong>4. Total surface area:</strong></p>
<p>${f('\\text{Total Surface Area} = 128 + 295.025 + 157.582 = 580.607')}</p>
<p>Rounded to the nearest tenth, the surface area is <strong>580.6</strong>.</p>`,

  // Q11
  '6a5261c04d554e04aa1bf1b0': `<p><strong>Choice A is correct.</strong></p>
<p>To determine the number of solutions, solve the linear equation for ${f('x')}:</p>
<p>${f('6x + 4 = 22')}</p>
<p>Subtract 4 from both sides:</p>
<p>${f('6x = 18')}</p>
<p>Divide both sides by 6:</p>
<p>${f('x = 3')}</p>
<p>Because there is a single, unique value of ${f('x')} that satisfies the equation, the equation has <strong>exactly one</strong> solution.</p>
<p><strong>Choices B, C, and D are incorrect</strong> because a linear equation in one variable with a nonzero coefficient on ${f('x')} always has exactly one solution.</p>`,

  // Q12
  '6a52623d4d554e04aa1bf1b6': `<p><strong>Choice B is correct.</strong></p>
<p>The function is defined by ${f('f(x) = 3x - 7')}.</p>
<p>Substitute ${f('x = a + 1')} into the function:</p>
<p>${f('f(a + 1) = 3(a + 1) - 7 = 3a + 3 - 7 = 3a - 4')}</p>
<p>We are given that ${f('f(a + 1) = 2a')}, so set the expressions equal to each other:</p>
<p>${f('3a - 4 = 2a')}</p>
<p>Subtract ${f('2a')} from both sides:</p>
<p>${f('a - 4 = 0')}</p>
<p>Add 4 to both sides:</p>
<p>${f('a = 4')}</p>
<p><strong>Choice A is incorrect</strong> and may result from miscalculating ${f('3(1) - 7')}.</p>
<p><strong>Choices C and D are incorrect</strong> and may result from sign errors during simplification.</p>`,

  // Q13
  '6a5263144d554e04aa1bf1bc': `<p><strong>The correct answer is 12.</strong></p>
<p>In the equation ${f('7x + 12y = 180')}, ${f('x')} represents the number of mugs and ${f('y')} represents the number of plates.</p>
<p>Substitute ${f('y = 8')} into the equation:</p>
<p>${f('7x + 12(8) = 180')}</p>
<p>${f('7x + 96 = 180')}</p>
<p>Subtract 96 from both sides:</p>
<p>${f('7x = 84')}</p>
<p>Divide both sides by 7:</p>
<p>${f('x = 12')}</p>
<p>Therefore, there are 12 mugs in the collection.</p>`,

  // Q14
  '6a5263854d554e04aa1bf1cc': `<p><strong>Choice B is correct.</strong></p>
<p>We can identify the correct equation by examining the y-intercept and slope of the line of best fit:</p>
<p>1. <strong>y-intercept:</strong> When ${f('x = 0')}, the line crosses the vertical axis at approximately ${f('y = 12.4')}. This eliminates Choice C.</p>
<p>2. <strong>Slope:</strong> As ${f('x')} increases, ${f('y')} decreases, meaning the line has a negative slope (${f('m < 0')}). This eliminates Choice A (which has a positive slope of ${f('+0.7')}).</p>
<p>Therefore, the line of best fit is represented by ${f('y = 12.4 - 0.7x')}.</p>
<p><strong>Choice A is incorrect</strong> because it has a positive slope.</p>
<p><strong>Choice C is incorrect</strong> because it has a negative y-intercept of -12.4.</p>
<p><strong>Choice D is incorrect</strong> because it does not represent a line in slope-intercept form.</p>`,

  // Q15
  '6a5264254d554e04aa1bf1e5': `<p><strong>Choice A is correct.</strong></p>
<p>To find the equivalent expression, factor out the greatest common factor (GCF) from the two terms in ${f('4x^3 + 20x^2')}:</p>
<p>• The GCF of the coefficients 4 and 20 is 4.</p>
<p>• The GCF of the variable terms ${f('x^3')} and ${f('x^2')} is ${f('x^2')}.</p>
<p>Factoring out ${f('4x^2')}:</p>
<p>${f('4x^3 + 20x^2 = 4x^2(x) + 4x^2(5) = 4x^2(x + 5)')}</p>
<p><strong>Choices B, C, and D are incorrect</strong> because expanding them does not produce the original expression ${f('4x^3 + 20x^2')}.</p>`,

  // Q16
  '6a5264f34d554e04aa1bf1f1': `<p><strong>Choice A is correct.</strong></p>
<p>When a geometric figure is dilated by a scale factor of ${f('k')}, each side length in the dilated image is obtained by multiplying the corresponding side length of the original figure by ${f('k')}:</p>
<p>${f('S\'T\' = k \\times ST')}</p>
<p>Given that ${f('ST = 9')} and the scale factor is ${f('k = \\frac{1}{3}')}:</p>
<p>${f('S\'T\' = \\frac{1}{3} \\times 9 = 3')}</p>
<p><strong>Choice B is incorrect</strong> because 7 is the dilated length of side ${f('RS')} (${f('\\frac{1}{3} \\times 21 = 7')}), not ${f('ST')}.</p>
<p><strong>Choice C is incorrect</strong> because it multiplies 9 by 3 instead of dividing by 3.</p>
<p><strong>Choice D is incorrect</strong> because it multiplies 21 by 3.</p>`,

  // Q17
  '6a52657e4d554e04aa1bf201': `<p><strong>Choice C is correct.</strong></p>
<p>We are given the equation:</p>
<p>${f('z = y + 47x')}</p>
<p>To express ${f('x')} in terms of ${f('y')} and ${f('z')}, isolate ${f('x')}:</p>
<p>1. Subtract ${f('y')} from both sides:</p>
<p>${f('z - y = 47x')}</p>
<p>2. Divide both sides by 47:</p>
<p>${f('x = \\frac{z - y}{47}')}</p>
<p><strong>Choices A, B, and D are incorrect</strong> because they incorrectly square terms or use incorrect algebraic operations.</p>`,

  // Q18
  '6a52661b4d554e04aa1bf215': `<p><strong>Choice B is correct.</strong></p>
<p>In the linear model ${f('y = 50x + 120')}:</p>
<p>• ${f('x')} represents the number of months of cable service.</p>
<p>• The coefficient 50 represents the monthly service fee of 50 dollars per month.</p>
<p>• The constant term 120 represents the initial fee charged at ${f('x = 0')} months, which is the onetime installation fee of 120 dollars.</p>
<p>Therefore, the amount of the onetime installation fee is 120 dollars.</p>
<p><strong>Choice A is incorrect</strong> because 170 is the total charge for the first month (${f('50(1) + 120 = 170')}).</p>
<p><strong>Choice C is incorrect</strong> because it subtracts 50 from 120.</p>
<p><strong>Choice D is incorrect</strong> because the installation fee is nonzero.</p>`,

  // Q19
  '6a52681a4d554e04aa1bf22b': `<p><strong>Choice C is correct.</strong></p>
<p>To graph the inequality ${f('4x + 5y < 9')}:</p>
<p>1. <strong>Boundary Line:</strong> Convert the inequality to slope-intercept form:</p>
<p>${f('5y < -4x + 9')}</p>
<p>${f('y < -\\frac{4}{5}x + \\frac{9}{5}')}</p>
<p>The boundary line has a slope of ${f('-\\frac{4}{5} = -0.8')} and a y-intercept of ${f('(0, 1.8)')}. The x-intercept occurs when ${f('y = 0')}, giving ${f('4x = 9 \\implies x = 2.25')}.</p>
<p>Because the inequality uses a strict less-than symbol (${f('<')}), the boundary line must be a <strong>dashed line</strong>.</p>
<p>2. <strong>Shaded Region:</strong> Test the origin ${f('(0, 0)')}:</p>
<p>${f('4(0) + 5(0) = 0 < 9')}</p>
<p>Since this statement is true, the region containing ${f('(0, 0)')} (below and to the left of the boundary line) is shaded.</p>
<p>Graph C correctly shows the dashed boundary line with negative slope and shading containing the origin.</p>
<p><strong>Choices A, B, and D are incorrect</strong> because they shade the wrong half-plane or show an incorrect boundary line.</p>`,

  // Q20
  '6a526a854d554e04aa1bf241': `<p><strong>The correct answer is 30/13 (or 2.308).</strong></p>
<p>The slope ${f('m')} of a line passing through points ${f('(x_1, y_1)')} and ${f('(x_2, y_2)')} is given by:</p>
<p>${f('m = \\frac{y_2 - y_1}{x_2 - x_1}')}</p>
<p>The line passes through the x-intercept ${f('(-6, 0)')} and the y-intercept ${f('(0, p)')}. Using these coordinates with the given slope ${f('\\frac{5}{13}')}:</p>
<p>${f('\\frac{5}{13} = \\frac{p - 0}{0 - (-6)} = \\frac{p}{6}')}</p>
<p>Multiply both sides by 6:</p>
<p>${f('p = 6 \\times \\frac{5}{13} = \\frac{30}{13}')}</p>
<p>In decimal form, ${f('\\frac{30}{13} \\approx 2.308')}.</p>`,

  // Q21
  '6a526b154d554e04aa1bf247': `<p><strong>Choice D is correct.</strong></p>
<p>We are given that angle ${f('S')} has a measure of ${f('\\frac{\\pi}{11}')} radians. The measure of angle ${f('T')} is 2 times angle ${f('S')}:</p>
<p>${f('T = 2 \\times \\frac{\\pi}{11} = \\frac{2\\pi}{11}\\text{ radians}')}</p>
<p>To convert an angle from radians to degrees, multiply by the conversion factor ${f('\\frac{180^\\circ}{\\pi\\text{ radians}}')}:</p>
<p>${f('\\text{Degrees} = \\text{Radians} \\times \\frac{180}{\\pi}')}</p>
<p>Multiplying gives:</p>
<p>${f('\\text{Measure in degrees} = \\frac{\\pi}{11} \\times 180 \\times 2')}</p>
<p>This matches the expression in Choice D.</p>
<p><strong>Choices A, B, and C are incorrect</strong> because they incorrectly use ${f('\\frac{9\\pi}{11}')} or use ${f('90^\\circ')} instead of ${f('180^\\circ')}.</p>`,

  // Q22
  '6a526c0e4d554e04aa1bf25c': `<p><strong>Choice B is correct.</strong></p>
<p>When estimating a population mean using a simple random sample, the margin of error (${f('\\text{ME}')}) is inversely proportional to the square root of the sample size ${f('n')}:</p>
<p>${f('\\text{ME} = z^* \\frac{s}{\\sqrt{n}}')}</p>
<p>where ${f('z^*')} is the critical value and ${f('s')} is the sample standard deviation. As the sample size ${f('n')} increases, the denominator ${f('\\sqrt{n}')} increases, resulting in a smaller margin of error.</p>
<p>Because the first sample obtained a smaller margin of error (1 minute) than the second sample (2.2 minutes) using the same methodology, the first sample must have had a larger sample size.</p>
<p>Therefore, the first sample contained more ovens than the second sample.</p>
<p><strong>Choice A is incorrect</strong> because fewer ovens would result in a larger margin of error.</p>
<p><strong>Choices C and D are incorrect</strong> because the average preheat time (the sample mean) does not determine the margin of error.</p>`
};

async function main() {
  console.log('🚀 Uploading explanations for March 2026 US 1 Module 2 (22 questions)...\n');
  const questionIds = Object.keys(explanations);
  
  for (let i = 0; i < questionIds.length; i++) {
    const qid = questionIds[i];
    const explanation = explanations[qid];
    process.stdout.write(`Updating M2 Q${i + 1} (${qid})... `);
    try {
      const res = await updateQuestionExplanation(qid, explanation);
      if (res && res.message === 'success') {
        console.log('✅ Success');
      } else {
        console.log('⚠️ Unexpected response:', res);
      }
    } catch (err) {
      console.log('❌ Error:', err.message);
    }
  }
  console.log('\n🎉 Finished Module 2 explanations (22 questions updated).');
}

main();
