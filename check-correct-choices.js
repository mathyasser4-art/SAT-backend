const axios = require('axios');
const fs = require('fs');

const BASE_URL = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a6946b7c3d08d90637d3cc3';
const M2_ID = '6a6946bec3d08d90637d3cc9';

async function checkCorrectAnswers() {
  for (const [modName, modId, scratchFile] of [
    ['Module 1', M1_ID, 'scratch_sep2025_us1_m1.json'],
    ['Module 2', M2_ID, 'scratch_sep2025_us1_m2.json']
  ]) {
    console.log(`\n=== ${modName} ===`);
    const res = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${modId}`);
    const liveQuestions = res.data.chapter.questions;
    const scratchQuestions = JSON.parse(fs.readFileSync(scratchFile, 'utf8')).chapter.questions;

    liveQuestions.forEach((lq, idx) => {
      if (lq.typeOfAnswer === 'MCQ') {
        const sq = scratchQuestions.find(q => q._id === lq._id);
        const exactMatch = sq.wrongAnswer.includes(lq.correctAnswer);
        const correctIndex = sq.wrongAnswer.indexOf(lq.correctAnswer);
        console.log(`[Q${idx+1}] ID: ${lq._id} - Exact correctAnswer in scratch wrongAnswer: ${exactMatch} (index ${correctIndex} = Option ${String.fromCharCode(65 + correctIndex)})`);
        if (!exactMatch) {
          console.log('   Live correctAnswer:', lq.correctAnswer);
          console.log('   Scratch wrongAnswer:', sq.wrongAnswer);
        }
      }
    });
  }
}

checkCorrectAnswers().catch(console.error);
