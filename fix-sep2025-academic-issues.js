const axios = require('axios');
const fs = require('fs');

const BASE_URL = 'https://sat-backend-production.up.railway.app';
const M1_CHAP = '6a6855e1c3d08d90637d3b47';
const M2_CHAP = '6a6855eec3d08d90637d3b4d';

function mathSpan(latex) {
  return `<span class="ql-formula" data-value="${latex}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow></mrow><annotation encoding="application/x-tex">${latex}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.7em;"></span><span class="mord">${latex}</span></span></span></span></span>﻿</span>`;
}

async function fixAll() {
  console.log('🚀 Fixing academic issues and deduplicating choices for September 2025 INT 1...\n');

  // 1. Fetch live questions from both modules
  for (const [modName, chapId] of [['Module 1', M1_CHAP], ['Module 2', M2_CHAP]]) {
    console.log(`Processing ${modName}...`);
    const res = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${chapId}`);
    const questions = res.data.chapter.questions;

    for (const q of questions) {
      const updates = {};
      let needsUpdate = false;

      // A. MCQ Deduplication / Choice Verification
      if (q.typeOfAnswer === 'MCQ' && q.wrongAnswer && q.wrongAnswer.length > 0) {
        // wrongAnswer must always contain all 4 choices including correctAnswer
        const seenClean = new Set();
        const newWrong = [];

        // Always ensure correctAnswer is included
        const cleanKey = q.correctAnswer.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
        seenClean.add(cleanKey);
        newWrong.push(q.correctAnswer);

        for (const w of q.wrongAnswer) {
          const cleanW = w.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
          if (!seenClean.has(cleanW)) {
            seenClean.add(cleanW);
            newWrong.push(w);
          }
        }

        // If wrongAnswer did not have all 4 unique choices including key, update
        if (newWrong.length !== q.wrongAnswer.length || !q.wrongAnswer.some(w => w.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim() === cleanKey)) {
          console.log(`  [${modName}] Q (${q._id}): Normalizing choices to 4 options (was ${q.wrongAnswer.length})`);
          updates.wrongAnswer = newWrong;
          needsUpdate = true;
        }
      }

      // B. Specific question fixes
      // M1 Q15: Add 5/3, 1.666, 1.667 to accepted answers
      if (q._id === '6a6865ebc3d08d90637d3bce') {
        console.log(`  [M1 Q15] Adding exact fractions and proper decimals to answer array...`);
        updates.answer = ['5/3', '1.66', '1.67', '1.666', '1.667'];
        needsUpdate = true;
      }

      // M1 Q21: Add 7/3, 2.33, 2.333 to accepted answers
      if (q._id === '6a686b70c3d08d90637d3bfa') {
        console.log(`  [M1 Q21] Adding exact fraction 7/3 and proper decimals to answer array...`);
        updates.answer = ['7/3', '2.33', '2.333', '2.34'];
        needsUpdate = true;
      }

      // M2 Q8: Fix incorrect key -3k - 5r - 3 -> -3k + 17r - 3 with all 4 choices
      if (q._id === '6a68849ec3d08d90637d3c4e') {
        console.log(`  [M2 Q8] Correcting answer key to -3k + 17r - 3 with 4 choices...`);
        updates.correctAnswer = `<p>${mathSpan('-3k + 17r - 3')}</p>`;
        updates.wrongAnswer = [
          `<p>${mathSpan('-3k + 17r - 3')}</p>`,
          `<p>${mathSpan('-3k - 5r - 3')}</p>`,
          `<p>${mathSpan('-3k + 17r + 3')}</p>`,
          `<p>${mathSpan('-3k - 5r + 3')}</p>`
        ];
        needsUpdate = true;
      }

      // M2 Q10: Add 0.166, 0.167 to accepted answers
      if (q._id === '6a688580c3d08d90637d3c56') {
        console.log(`  [M2 Q10] Expanding accepted answers for 1/6...`);
        updates.answer = ['1/6', '0.166', '0.167'];
        needsUpdate = true;
      }

      // M2 Q19: Add 61/65, 0.938, 0.94 to accepted answers
      if (q._id === '6a688c8ec3d08d90637d3c88') {
        console.log(`  [M2 Q19] Adding exact fraction 61/65 and 0.938, 0.94 to answer array...`);
        updates.answer = ['61/65', '0.938', '0.94', '0.93'];
        needsUpdate = true;
      }

      if (needsUpdate) {
        try {
          const updateRes = await axios.put(`${BASE_URL}/question/updateQuestion/${q._id}`, updates);
          console.log(`    Updated ${q._id}: ${updateRes.data.message || 'success'}`);
        } catch (err) {
          console.error(`    Failed to update ${q._id}:`, err.response?.data || err.message);
        }
      }
    }
  }

  console.log('\n🎉 Finished academic fixes and choice deduplication for September 2025 INT 1.');
}

fixAll();
