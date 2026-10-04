const axios = require('axios');
const fs = require('fs');

const BASE_URL = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a6946b7c3d08d90637d3cc3';
const M2_ID = '6a6946bec3d08d90637d3cc9';

async function checkChoices() {
  console.log('Checking live September 2025 US 1 choices in database...');
  for (const [modName, modId, scratchFile] of [
    ['Module 1', M1_ID, 'scratch_sep2025_us1_m1.json'],
    ['Module 2', M2_ID, 'scratch_sep2025_us1_m2.json']
  ]) {
    console.log(`\n=================== ${modName} ===================`);
    const res = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${modId}`);
    const liveQuestions = res.data.chapter.questions;

    let scratchQuestions = [];
    if (fs.existsSync(scratchFile)) {
      scratchQuestions = JSON.parse(fs.readFileSync(scratchFile, 'utf8')).chapter?.questions || [];
    }

    console.log(`Total questions in live: ${liveQuestions.length}`);

    let mcqCount = 0;
    let threeChoiceCount = 0;
    let fourChoiceCount = 0;
    let otherChoiceCount = 0;

    liveQuestions.forEach((q, idx) => {
      if (q.typeOfAnswer === 'MCQ') {
        mcqCount++;
        const choices = q.wrongAnswer || [];
        const scratchQ = scratchQuestions.find(sq => sq._id === q._id);
        const scratchChoices = scratchQ?.wrongAnswer || [];

        console.log(`[Q${idx + 1}] ID: ${q._id} | Live choices: ${choices.length} | Scratch choices: ${scratchChoices.length}`);
        if (choices.length === 3) {
          threeChoiceCount++;
          console.log(`   Live choices:`, choices);
          console.log(`   Correct answer:`, q.correctAnswer);
          if (scratchQ) {
            console.log(`   Scratch wrongAnswer:`, scratchQ.wrongAnswer);
            console.log(`   Scratch correctAnswer:`, scratchQ.correctAnswer);
          }
        } else if (choices.length === 4) {
          fourChoiceCount++;
        } else {
          otherChoiceCount++;
          console.log(`   Unusual choices count: ${choices.length}`, choices);
        }
      } else {
        console.log(`[Q${idx + 1}] ID: ${q._id} | Non-MCQ (${q.typeOfAnswer})`);
      }
    });

    console.log(`Summary for ${modName}:`);
    console.log(`  MCQs: ${mcqCount}`);
    console.log(`  With 3 choices: ${threeChoiceCount}`);
    console.log(`  With 4 choices: ${fourChoiceCount}`);
    console.log(`  Other: ${otherChoiceCount}`);
  }
}

checkChoices().catch(err => {
  console.error(err);
});
