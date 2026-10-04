const axios = require('axios');

const BASE_URL = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a52d43b4d554e04aa1bf37e';
const M2_ID = '6a52d4434d554e04aa1bf384';

async function verifyAll() {
  console.log('🔍 Comprehensive Verification of March 2026 US 2 (Modules 1 & 2)...\n');

  for (const [modName, modId] of [['Module 1', M1_ID], ['Module 2', M2_ID]]) {
    console.log(`=================== ${modName} ===================`);
    const res = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${modId}`);
    const questions = res.data.chapter.questions;
    console.log(`Retrieved ${questions.length} questions.`);

    let passedCount = 0;

    for (let i = 0; i < questions.length; i++) {
      const q = questions[i];
      const qNum = `${modName} Q${i + 1}`;
      let ok = true;
      const issues = [];

      // 1. Check choices count if MCQ
      if (q.typeOfAnswer === 'MCQ') {
        const choices = [q.correctAnswer, ...(q.wrongAnswer || [])];
        if (choices.length !== 4) {
          ok = false;
          issues.push(`MCQ does not have 4 choices (has ${choices.length})`);
        }
      }

      // 2. Check explanation exists
      if (!q.explanation || q.explanation.trim() === '') {
        ok = false;
        issues.push(`Missing explanation`);
      } else {
        // Check for bare dollar signs (e.g. $ followed by digit)
        if (/\$\d+/.test(q.explanation)) {
          ok = false;
          issues.push(`Contains unescaped currency dollar sign`);
        }
      }

      // 3. Test grading endpoint
      try {
        let answerToSend;
        if (q.typeOfAnswer === 'MCQ') {
          answerToSend = q.correctAnswer;
        } else {
          answerToSend = q.answer[0];
        }

        const gradeRes = await axios.post(`${BASE_URL}/question/checkTheAnswer/${q._id}`, {
          questionAnswer: answerToSend
        });

        if (gradeRes.data.message !== 'success' || !gradeRes.data.explanation) {
          ok = false;
          issues.push(`Grading API failed: message=${gradeRes.data.message}, hasExplanation=${Boolean(gradeRes.data.explanation)}`);
        }
      } catch (err) {
        ok = false;
        issues.push(`Grading API error: ${err.message}`);
      }

      if (ok) {
        passedCount++;
        console.log(`  ${qNum} (${q._id}): ✅ PASS [Type: ${q.typeOfAnswer}, Image: ${q.questionPic?.secure_url ? 'Yes' : 'No'}]`);
      } else {
        console.log(`  ${qNum} (${q._id}): ❌ FAIL: ${issues.join('; ')}`);
      }
    }

    console.log(`\n${modName} Results: ${passedCount} / ${questions.length} PASSED\n`);
  }
}

verifyAll();
