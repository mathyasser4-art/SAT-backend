const axios = require('axios');
const fs = require('fs');

const BASE_URL = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a6946b7c3d08d90637d3cc3';
const M2_ID = '6a6946bec3d08d90637d3cc9';

function strip(s) {
  return (s || '').replace(/<[^>]+>/g, '').replace(/[\s\u200B\u3164\uFEFF]+/g, ' ').trim();
}

async function restoreChoices() {
  console.log('🚀 Restoring 4 choices for September 2025 US 1 (Module 1 & Module 2)...\n');

  for (const [modName, modId, scratchFile] of [
    ['Module 1', M1_ID, 'scratch_sep2025_us1_m1.json'],
    ['Module 2', M2_ID, 'scratch_sep2025_us1_m2.json']
  ]) {
    console.log(`=================== ${modName} ===================`);
    const res = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${modId}`);
    const liveQuestions = res.data.chapter.questions;
    const scratchQuestions = JSON.parse(fs.readFileSync(scratchFile, 'utf8')).chapter.questions;

    let updatedCount = 0;

    for (let i = 0; i < liveQuestions.length; i++) {
      const q = liveQuestions[i];
      const qNum = `${modName} Q${i + 1}`;

      if (q.typeOfAnswer === 'MCQ') {
        const sq = scratchQuestions.find(item => item._id === q._id);
        if (!sq) {
          throw new Error(`Question ${q._id} not found in ${scratchFile}`);
        }

        const scratchChoices = sq.wrongAnswer || [];
        if (scratchChoices.length !== 4) {
          throw new Error(`Question ${qNum} does not have 4 choices in scratch: got ${scratchChoices.length}`);
        }

        // Verify choices are unique
        const uniqueChoices = new Set(scratchChoices.map(strip));
        if (uniqueChoices.size !== 4) {
          throw new Error(`Question ${qNum} does not have 4 unique choices in scratch! Size: ${uniqueChoices.size}`);
        }

        // Verify scratch choices contain live correctAnswer
        const containsCorrect = scratchChoices.some(c => c === q.correctAnswer || strip(c) === strip(q.correctAnswer));
        if (!containsCorrect) {
          throw new Error(`Question ${qNum} scratch choices do not contain correctAnswer!`);
        }

        console.log(`Updating ${qNum} (${q._id}): restoring 4 choices...`);
        const updateRes = await axios.put(`${BASE_URL}/question/updateQuestion/${q._id}`, {
          wrongAnswer: scratchChoices
        });

        if (updateRes.data.message !== 'success' && !updateRes.data.question) {
          console.error(`  ⚠️ Warning: update response for ${qNum}:`, updateRes.data);
        } else {
          updatedCount++;
          console.log(`  ✅ Successfully updated ${qNum} to 4 choices.`);
        }
      }
    }

    console.log(`\n${modName}: ${updatedCount} MCQs updated to 4 choices.\n`);
  }

  console.log('✨ All updates completed. Running live verification...\n');

  let totalMCQs = 0;
  let passedMCQs = 0;

  for (const [modName, modId] of [['Module 1', M1_ID], ['Module 2', M2_ID]]) {
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
