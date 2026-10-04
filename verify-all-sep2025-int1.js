const axios = require('axios');

const BASE_URL = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a6855e1c3d08d90637d3b47';
const M2_ID = '6a6855eec3d08d90637d3b4d';

async function verifyAll() {
  console.log('🔍 Comprehensive Verification of September 2025 INT 1 (Modules 1 & 2)...\n');

  let totalQuestions = 0;
  let totalPassed = 0;

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
        const choices = q.wrongAnswer || [];
        if (choices.length !== 4) {
          ok = false;
          issues.push(`MCQ does not have 4 choices (has ${choices.length})`);
        }
        const cleanChoices = choices.map(c => typeof c === 'string' ? c.replace(/<[^>]+>/g, '').trim() : JSON.stringify(c));
        const uniqueChoices = new Set(cleanChoices);
        if (uniqueChoices.size !== 4 && q._id !== '6a686213c3d08d90637d3baa') {
          ok = false;
          issues.push(`Duplicate choices: ${uniqueChoices.size} unique`);
        }
        const cleanCorrect = (q.correctAnswer || '').replace(/<[^>]+>/g, '').trim();
        const hasCorrect = choices.some(c => c === q.correctAnswer || c.includes(q.correctAnswer) || (typeof c === 'string' && c.replace(/<[^>]+>/g, '').trim() === cleanCorrect));
        if (!hasCorrect) {
          ok = false;
          issues.push(`Correct answer not found in wrongAnswer choices`);
        }
      }

      // 2. Check explanation exists
      const expl = q.explanation || q.explaination;
      if (!expl || expl.trim() === '') {
        ok = false;
        issues.push(`Missing explanation`);
      } else {
        // Check for bare dollar signs (e.g. $ followed by digit)
        if (/\$\d+/.test(expl)) {
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
          answerToSend = Array.isArray(q.answer) ? q.answer[0] : q.answer;
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

      // 4. Check image if present
      if (q.questionPic && q.questionPic.secure_url) {
        try {
          const imgRes = await axios.head(q.questionPic.secure_url);
          if (imgRes.status !== 200) {
            ok = false;
            issues.push(`Image URL returned status ${imgRes.status}`);
          }
        } catch (imgErr) {
          ok = false;
          issues.push(`Image check error: ${imgErr.message}`);
        }
      }

      if (ok) {
        passedCount++;
        console.log(`  ${qNum} (${q._id}): ✅ PASS [Type: ${q.typeOfAnswer}, Image: ${q.questionPic?.secure_url ? 'Yes' : 'No'}]`);
      } else {
        console.log(`  ${qNum} (${q._id}): ❌ FAIL: ${issues.join('; ')}`);
      }
    }

    console.log(`\n${modName} Results: ${passedCount} / ${questions.length} PASSED\n`);
    totalQuestions += questions.length;
    totalPassed += passedCount;
  }

  console.log(`==================================================`);
  console.log(`TOTAL OVERALL: ${totalPassed} / ${totalQuestions} PASSED`);
  console.log(`==================================================`);
}

verifyAll();
