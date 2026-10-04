const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';

function f(formula) {
  return `<span class="ql-formula" data-value="${formula}"></span>`;
}

function updateExplanation(questionId, explanationHtml) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({ explanation: explanationHtml });
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
  '6a666305c3d08d90637d3a82':
    `<p>The inequality is ${f('y > -36')}:</p>` +
    `<p>1. The boundary line is ${f('y = -36')}, which is a horizontal line passing through ${f('(0, -36)')}.</p>` +
    `<p>2. Because the inequality is strict (using ${f('>')}), the boundary line must be dashed, not solid.</p>` +
    `<p>3. Because ${f('y')} is strictly greater than ${f('-36')}, the solution set consists of all points with ${f('y')}-coordinates above ${f('-36')}, so the region above the dashed line is shaded.</p>` +
    `<p>Thus, the graph showing a dashed horizontal line at ${f('y = -36')} with shading above represents the solutions.</p>`,

  // Q2
  '6a6673e5c3d08d90637d3a92':
    `<p>The total mass of the mixture is the sum of the masses of compounds A, B, and C:</p>` +
    `<p>${f('25 + 35 + x = 125')}</p>` +
    `<p>${f('60 + x = 125')}</p>` +
    `<p>Subtract 60 from both sides:</p>` +
    `<p>${f('x = 125 - 60 = 65')}</p>` +
    `<p>Thus, the value of ${f('x')} is <strong>65</strong>.</p>`,

  // Q3
  '6a667416c3d08d90637d3a96':
    `<p>The solution to a system of equations in the ${f('xy')}-plane corresponds to the coordinates of the point of intersection between the two graphs.</p>` +
    `<p>Looking at the given graph, the line and the curve intersect at the point with coordinates ${f('x = 5')} and ${f('y = 4')}.</p>` +
    `<p>Therefore, the solution to the system is <strong>(5, 4)</strong>.</p>`,

  // Q4
  '6a667434c3d08d90637d3a9a':
    `<p>Carmen needs at least 100 signatures and already has 51 signatures.</p>` +
    `<p>To find the minimum number of additional signatures needed, subtract the signatures collected from the required total:</p>` +
    `<p>${f('100 - 51 = 49')}</p>` +
    `<p>Thus, Carmen needs at least <strong>49</strong> additional signatures.</p>`,

  // Q5
  '6a667457c3d08d90637d3a9e':
    `<p>The total number of seats is 340. Students occupied 50% of the seats:</p>` +
    `<p>${f('\\text{Occupied seats} = 0.50 \\times 340 = 170')}</p>` +
    `<p>Therefore, the students occupied <strong>170</strong> seats during the assembly.</p>`,

  // Q6
  '6a66749ac3d08d90637d3aa2':
    `<p>The ${f('y')}-intercept of a graph is the point where the curve crosses the vertical ${f('y')}-axis (where ${f('x = 0')}).</p>` +
    `<p>Examining the graph, the curve passes through the ${f('y')}-axis at ${f('(0, 5)')}.</p>` +
    `<p>Thus, the value of ${f('y')} is <strong>5</strong>.</p>`,

  // Q7
  '6a6674cec3d08d90637d3aa8':
    `<p>We are given that ${f('5c = 15')}.</p>` +
    `<p>Substitute ${f('15')} directly in place of ${f('5c')} in the expression ${f('5c - 8')}:</p>` +
    `<p>${f('5c - 8 = 15 - 8 = 7')}</p>` +
    `<p>Thus, the value of ${f('5c - 8')} is <strong>7</strong>.</p>`,

  // Q8
  '6a66750cc3d08d90637d3aac':
    `<p>Because the ratio of ${f('k')} to ${f('p')} is constant, we can set up a proportion:</p>` +
    `<p>${f('\\frac{k}{p} = \\frac{7}{6}')}</p>` +
    `<p>When ${f('p = 336')}:</p>` +
    `<p>${f('k = \\frac{7}{6} \\times 336 = 7 \\times 56 = 392')}</p>` +
    `<p>Thus, the value of ${f('k')} is <strong>392</strong>.</p>`,

  // Q9
  '6a667578c3d08d90637d3ab2':
    `<p>The probability of selecting an animal of species Y is the number of species Y animals divided by the total number of animals:</p>` +
    `<p>${f('P(\\text{species Y}) = \\frac{\\text{Frequency of species Y}}{\\text{Total animals}} = \\frac{3}{185}')}</p>`,

  // Q10
  '6a6675eac3d08d90637d3ab8':
    `<p>Find the row corresponding to an air temperature of ${f('29^\\circ\\text{F}')} and look across to the column labeled "Wind chill temperature at wind speed 15 mph".</p>` +
    `<p>The table gives a value of ${f('18^\\circ\\text{F}')}.</p>` +
    `<p>Disregarding the degree symbol, the answer is <strong>18</strong>.</p>`,

  // Q11
  '6a667618c3d08d90637d3abc':
    `<p>In a right triangle, the sum of all three angles is ${f('180^\\circ')}. Since the right angle is ${f('90^\\circ')}, the two acute angles must sum to ${f('90^\\circ')}:</p>` +
    `<p>${f('\\theta_1 + \\theta_2 = 90^\\circ')}</p>` +
    `<p>Given that one acute angle is ${f('14^\\circ')}:</p>` +
    `<p>${f('\\theta_2 = 90^\\circ - 14^\\circ = 76^\\circ')}</p>` +
    `<p>Disregarding the degree symbol, the answer is <strong>76</strong>.</p>`,

  // Q12
  '6a667672c3d08d90637d3ac2':
    `<p>Factor the expression by finding the greatest common factor of the terms in ${f('3x^2 + 57x + 15')}:</p>` +
    `<p>Notice that each coefficient (${f('3')}, ${f('57')}, and ${f('15')}) is divisible by 3:</p>` +
    `<p>${f('3x^2 + 57x + 15 = 3(x^2 + 19x + 5)')}</p>` +
    `<p>Therefore, <strong>3</strong> is a factor of the given expression.</p>`,

  // Q13
  '6a667740c3d08d90637d3ac6':
    `<p>Population is calculated as ${f('\\text{population} = \\text{area} \\times \\text{population density}')}:</p>` +
    `<p>The city's population is ${f('1,035x')}.</p>` +
    `<p>The adjacent suburb's population is ${f('535y')}.</p>` +
    `<p>The combined population of the city and suburb is 13,165, which gives:</p>` +
    `<p>${f('1,035x + 535y = 13,165')}</p>`,

  // Q14
  '6a66775fc3d08d90637d3aca':
    `<p>The area of a triangle is given by the formula:</p>` +
    `<p>${f('\\text{Area} = \\frac{1}{2} \\times \\text{base} \\times \\text{height}')}</p>` +
    `<p>Substitute ${f('\\text{base} = 48\\text{ cm}')} and ${f('\\text{height} = 96\\text{ cm}')}:</p>` +
    `<p>${f('\\text{Area} = \\frac{1}{2} \\times 48 \\times 96 = 24 \\times 96 = 2,304\\text{ cm}^2')}</p>`,

  // Q15
  '6a667797c3d08d90637d3ace':
    `<p>To find the predicted height 3 minutes after descent begins, substitute ${f('x = 3')} into ${f('f(x)')}:</p>` +
    `<p>${f('f(3) = -40(3) + 340')}</p>` +
    `<p>${f('f(3) = -120 + 340 = 220')}</p>` +
    `<p>Thus, the predicted height is <strong>220</strong> feet.</p>`,

  // Q16
  '6a667844c3d08d90637d3ad2':
    `<p>Start with the given equation:</p>` +
    `<p>${f('5a = \\frac{4b^2}{a} - 20a')}</p>` +
    `<p>Add ${f('20a')} to both sides to combine like terms:</p>` +
    `<p>${f('25a = \\frac{4b^2}{a}')}</p>` +
    `<p>Multiply both sides by ${f('a')}:</p>` +
    `<p>${f('25a^2 = 4b^2')}</p>` +
    `<p>Divide both sides by 25:</p>` +
    `<p>${f('a^2 = \\frac{4b^2}{25}')}</p>` +
    `<p>Take the principal square root of both sides (since ${f('a')} and ${f('b')} are positive):</p>` +
    `<p>${f('a = \\sqrt{\\frac{4b^2}{25}} = \\frac{2b}{5}')}</p>`,

  // Q17
  '6a667875c3d08d90637d3ad6':
    `<p>First, calculate how much money Charles saves each week:</p>` +
    `<p>${f('\\text{Weekly savings} = \\frac{3}{5} \\times 225 = 3 \\times 45 = 135\\text{ dollars}')}</p>` +
    `<p>Over 3 weeks, the total savings will be:</p>` +
    `<p>${f('\\text{Total savings} = 3 \\times 135 = 405\\text{ dollars}')}</p>`,

  // Q18
  '6a6678c2c3d08d90637d3adc':
    `<p>Substitute ${f('x = 1')} into ${f('f(x)')}:</p>` +
    `<p>${f('f(1) = 2(1)^3 + \\frac{1}{3}(1)^2 - (1)')}</p>` +
    `<p>${f('f(1) = 2(1) + \\frac{1}{3}(1) - 1')}</p>` +
    `<p>${f('f(1) = 2 - 1 + \\frac{1}{3} = 1 + \\frac{1}{3} = \\frac{4}{3}')}</p>`,

  // Q19
  '6a66791ac3d08d90637d3ae0':
    `<p>The slope of a line passing through points ${f('(x_1, y_1)')} and ${f('(x_2, y_2)')} is:</p>` +
    `<p>${f('m = \\frac{y_2 - y_1}{x_2 - x_1}')}</p>` +
    `<p>Using the points ${f('(0, 0)')} and ${f('(13, 14)')}:</p>` +
    `<p>${f('m = \\frac{14 - 0}{13 - 0} = \\frac{14}{13}')}</p>`,

  // Q20
  '6a667971c3d08d90637d3ae4':
    `<p>Expand ${f('f(x)')} and ${f('g(x)')}:</p>` +
    `<p>${f('f(x) = (2x - 5)^2 = 4x^2 - 20x + 25')}</p>` +
    `<p>${f('g(x) = 2(2x + 7) = 4x + 14')}</p>` +
    `<p>Add the two functions:</p>` +
    `<p>${f('f(x) + g(x) = (4x^2 - 20x + 25) + (4x + 14)')}</p>` +
    `<p>Combine like terms:</p>` +
    `<p>${f('4x^2 + (-20x + 4x) + (25 + 14) = 4x^2 - 16x + 39')}</p>`,

  // Q21
  '6a667996c3d08d90637d3ae8':
    `<p>The given equation is:</p>` +
    `<p>${f('15x^2 = 15(9)')}</p>` +
    `<p>Divide both sides by 15:</p>` +
    `<p>${f('x^2 = 9')}</p>` +
    `<p>Take the square root of both sides:</p>` +
    `<p>${f('x = \\pm 3')}</p>` +
    `<p>The question asks for the negative solution, which is <strong>-3</strong>.</p>`,

  // Q22
  '6a6679eac3d08d90637d3aec':
    `<p>Since the graph of ${f('y = f(x)')} passes through ${f('(0, 13)')}, when ${f('x = 0')}, ${f('y = 13')}.</p>` +
    `<p>By definition, ${f('f(0)')} is the ${f('y')}-value corresponding to ${f('x = 0')}.</p>` +
    `<p>Therefore, ${f('f(0) = 13')}.</p>`
};

async function run() {
  console.log('🚀 Injecting 22 explanations for October 2025 · US 1 (M2)...\n');
  const ids = Object.keys(explanations);
  let count = 0;
  for (const id of ids) {
    process.stdout.write(`Updating explanation for ${id}... `);
    const res = await updateExplanation(id, explanations[id]);
    if (res.message === 'success') {
      count++;
      console.log('✅ Success');
    } else {
      console.log('⚠️ Failed:', JSON.stringify(res));
    }
  }
  console.log(`\n🎉 Injected ${count}/${ids.length} explanations for Module 2!`);
}

run().catch(console.error);
