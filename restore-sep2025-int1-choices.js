const axios = require('axios');
const fs = require('fs');

const BASE_URL = 'https://sat-backend-production.up.railway.app';
const M1_CHAP = '6a6855e1c3d08d90637d3b47';
const M2_CHAP = '6a6855eec3d08d90637d3b4d';

function strip(s) {
  return (s || '').replace(/<[^>]+>/g, '').replace(/[\s\u200B\u3164]+/g, ' ').trim();
}

async function restoreChoices() {
  console.log('🚀 Restoring 4 choices for September 2025 INT 1 (Module 1 and Module 2)...\n');

  for (const [modName, modId] of [['Module 1', M1_CHAP], ['Module 2', M2_CHAP]]) {
    console.log(`=================== ${modName} ===================`);
    const res = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${modId}`);
    const questions = res.data.chapter.questions;

    let updatedCount = 0;

    for (let i = 0; i < questions.length; i++) {
      const q = questions[i];
      const qNum = `${modName} Q${i + 1}`;

      if (q.typeOfAnswer === 'MCQ') {
        const currentWrongs = q.wrongAnswer || [];

        if (currentWrongs.length === 3) {
          const newWrong = [q.correctAnswer, ...currentWrongs];

          // Sanity check: ensure 4 unique choices
          if (q._id === '6a686213c3d08d90637d3baa') {
            const uniqueImgs = new Set(newWrong);
            if (uniqueImgs.size !== 4) {
              throw new Error(`${qNum} image choices are not 4 unique!`);
            }
          } else {
            const uniqueTexts = new Set(newWrong.map(strip));
            if (uniqueTexts.size !== 4) {
              throw new Error(`${qNum} choices are not 4 unique! Size: ${uniqueTexts.size}`);
            }
          }

          console.log(`Updating ${qNum} (${q._id}): expanding from 3 choices to 4 choices...`);
          const updateRes = await axios.put(`${BASE_URL}/question/updateQuestion/${q._id}`, {
            wrongAnswer: newWrong
          });

          if (updateRes.data.message !== 'success' && !updateRes.data.question) {
            console.error(`  ⚠️ Warning: update response for ${qNum}:`, updateRes.data);
          } else {
            updatedCount++;
            console.log(`  ✅ Successfully updated ${qNum} to 4 choices.`);
          }
        } else if (currentWrongs.length === 4) {
          console.log(`  ℹ️ ${qNum} already has 4 choices.`);
        } else {
          console.warn(`  ⚠️ ${qNum} has unexpected number of choices: ${currentWrongs.length}`);
        }
      }
    }

    console.log(`\n${modName}: ${updatedCount} MCQs updated to 4 choices.\n`);
  }

  console.log('✨ All updates completed. Running live verification...\n');

  // Verify
  let totalMCQs = 0;
  let passedMCQs = 0;

  for (const [modName, modId] of [['Module 1', M1_CHAP], ['Module 2', M2_CHAP]]) {
    const res = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${modId}`);
    const questions = res.data.chapter.questions;

    for (let i = 0; i < questions.length; i++) {
      const q = questions[i];
      if (q.typeOfAnswer === 'MCQ') {
        totalMCQs++;
        const choices = q.wrongAnswer || [];
        const isFour = choices.length === 4;
        const containsCorrect = choices.some(c => c === q.correctAnswer || strip(c) === strip(q.correctAnswer));
        
        let isGradeOk = false;
        try {
          const gradeRes = await axios.post(`${BASE_URL}/question/checkTheAnswer/${q._id}`, {
            questionAnswer: q.correctAnswer
          });
          isGradeOk = gradeRes.data.message === 'success';
        } catch (e) {
          isGradeOk = false;
        }

        if (isFour && containsCorrect && isGradeOk) {
          passedMCQs++;
          console.log(`✅ ${modName} Q${i + 1} (${q._id}): 4 choices, contains correct answer, grading PASS`);
        } else {
          console.error(`❌ ${modName} Q${i + 1} (${q._id}): 4 choices: ${isFour} (${choices.length}), containsCorrect: ${containsCorrect}, grading: ${isGradeOk}`);
        }
      }
    }
  }

  console.log(`\n==================================================`);
  console.log(`VERIFICATION RESULT: ${passedMCQs} / ${totalMCQs} MCQs PASSED WITH 4 CHOICES!`);
  console.log(`==================================================`);
}

restoreChoices().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
