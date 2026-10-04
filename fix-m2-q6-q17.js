const axios = require('axios');

const BASE_URL = 'https://sat-backend-production.up.railway.app';

// Helper to make Quill math formula HTML
function mathSpan(latex) {
  return `<span class="ql-formula" data-value="${latex}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow></mrow><annotation encoding="application/x-tex">${latex}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.7em;"></span><span class="mord">${latex}</span></span></span></span></span>﻿</span>`;
}

async function fixQuestions() {
  console.log('Fixing M2 Q6 and M2 Q17 stems/choices on Railway...');

  // 1. M2 Q6: ID 6a53bcea4d554e04aa1bf764
  // Stem: \frac{1}{3 - x} = \frac{x - 1}{x} + 1.4
  // Key: 2.5
  // Wrong: [0.75, 3, 4]
  const q6Id = '6a53bcea4d554e04aa1bf764';
  const q6Stem = `<p>${mathSpan('\\frac{1}{3 - x} = \\frac{x - 1}{x} + 1.4')}</p><p>Which of the following is a solution to the given equation?</p>`;
  const q6Key = `<p>${mathSpan('2.5')}</p>`;
  const q6Wrong = [
    `<p>${mathSpan('0.75')}</p>`,
    `<p>${mathSpan('3')}</p>`,
    `<p>${mathSpan('4')}</p>`
  ];

  try {
    const res6 = await axios.put(`${BASE_URL}/question/updateQuestion/${q6Id}`, {
      questionText: q6Stem,
      correctAnswer: q6Key,
      wrongAnswer: q6Wrong
    });
    console.log(`M2 Q6 updated: ${res6.data.message || 'success'}`);
  } catch (err) {
    console.error('Failed to update M2 Q6:', err.response?.data || err.message);
  }

  // 2. M2 Q17: ID 6a53cdfc4d554e04aa1bf832
  // Stem: \frac{8cx + 7}{5} = 2x - 7
  // Key: \frac{5}{4}
  // Wrong: [\frac{1}{4}, \frac{1}{5}, 2]
  const q17Id = '6a53cdfc4d554e04aa1bf832';
  const q17Stem = `<p>${mathSpan('\\frac{8cx + 7}{5} = 2x - 7')}</p><p>In the given equation, ${mathSpan('c')} is a constant. If the equation has no solution, what is the value of ${mathSpan('c')}?</p>`;
  const q17Key = `<p>${mathSpan('\\frac{5}{4}')}</p>`;
  const q17Wrong = [
    `<p>${mathSpan('\\frac{1}{4}')}</p>`,
    `<p>${mathSpan('\\frac{1}{5}')}</p>`,
    `<p>${mathSpan('2')}</p>`
  ];

  try {
    const res17 = await axios.put(`${BASE_URL}/question/updateQuestion/${q17Id}`, {
      questionText: q17Stem,
      correctAnswer: q17Key,
      wrongAnswer: q17Wrong
    });
    console.log(`M2 Q17 updated: ${res17.data.message || 'success'}`);
  } catch (err) {
    console.error('Failed to update M2 Q17:', err.response?.data || err.message);
  }
}

fixQuestions();
