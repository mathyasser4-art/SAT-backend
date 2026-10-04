const axios = require('axios');
const fs = require('fs');

const BASE_URL = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a6946b7c3d08d90637d3cc3';
const M2_ID = '6a6946bec3d08d90637d3cc9';

function strip(s) {
  return (s || '').replace(/<[^>]+>/g, '').replace(/[\s\u200B\u3164\uFEFF]+/g, ' ').trim();
}

async function validateAll() {
  console.log('Validating 32 MCQs against scratch files and live correctAnswers...');
  
  for (const [modName, modId, scratchFile] of [
    ['Module 1', M1_ID, 'scratch_sep2025_us1_m1.json'],
    ['Module 2', M2_ID, 'scratch_sep2025_us1_m2.json']
  ]) {
    console.log(`\n=================== ${modName} ===================`);
    const res = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${modId}`);
    const liveQuestions = res.data.chapter.questions;
    const scratchQuestions = JSON.parse(fs.readFileSync(scratchFile, 'utf8')).chapter.questions;

    let idx = 0;
    for (const lq of liveQuestions) {
      idx++;
      if (lq.typeOfAnswer === 'MCQ') {
        const sq = scratchQuestions.find(q => q._id === lq._id);
        if (!sq) {
          console.error(`❌ ${modName} Q${idx} (${lq._id}): NOT FOUND in scratch file!`);
          continue;
        }

        const scratchChoices = sq.wrongAnswer || [];
        if (scratchChoices.length !== 4) {
          console.error(`❌ ${modName} Q${idx} (${lq._id}): scratch has ${scratchChoices.length} choices, not 4!`);
          continue;
        }

        // Check if scratch choices are 4 unique choices
        const uniqueTexts = new Set(scratchChoices.map(strip));
        const has4Unique = uniqueTexts.size === 4;

        // Check if live correctAnswer matches one of the 4 scratch choices
        const correctClean = strip(lq.correctAnswer);
        const containsCorrect = scratchChoices.some(c => strip(c) === correctClean || c === lq.correctAnswer);

        // Check if live 3 choices are subset of scratch 4 choices
        const liveWrongsClean = (lq.wrongAnswer || []).map(strip);
        const allLiveInScratch = liveWrongsClean.every(lw => uniqueTexts.has(lw));

        console.log(`${has4Unique && containsCorrect && allLiveInScratch ? '✅' : '⚠️'} ${modName} Q${idx} (${lq._id}): unique4=${has4Unique} (${uniqueTexts.size}), containsCorrect=${containsCorrect}, liveSubset=${allLiveInScratch}`);
        if (!has4Unique || !containsCorrect || !allLiveInScratch) {
          console.log('   Live correctAnswer:', lq.correctAnswer);
          console.log('   Live wrongAnswer:', lq.wrongAnswer);
          console.log('   Scratch wrongAnswer:', scratchChoices);
        }
      }
    }
  }
}

validateAll().catch(console.error);
