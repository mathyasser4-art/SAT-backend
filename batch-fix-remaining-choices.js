const axios = require('axios');
const fs = require('fs');

const BASE_URL = 'https://sat-backend-production.up.railway.app';
const dir = JSON.parse(fs.readFileSync('all_real_exams_directory.json', 'utf8'));

function strip(s) {
  return (s || '').replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/[\s\u200B\u3164\uFEFF]+/g, ' ').trim();
}

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
  console.log('='.repeat(70));
  console.log('SECOND PASS: Fix remaining 3-choice MCQs by adding correctAnswer');
  console.log('='.repeat(70));

  let grandFixed = 0;
  let grandErrors = 0;
  let grandAlreadyOk = 0;

  for (const exam of dir) {
    if (!exam.m1 || !exam.m2) continue;

    for (const [modKey, modLabel] of [['m1', 'Module 1'], ['m2', 'Module 2']]) {
      const mod = exam[modKey];
      if (!mod || !mod.id) continue;

      let questions;
      try {
        const res = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${mod.id}`);
        questions = res.data.chapter.questions;
      } catch (err) {
        console.error(`  ❌ ${exam.name} ${modLabel}: API error: ${err.message}`);
        grandErrors++;
        continue;
      }

      let modFixed = 0;
      let modSkipped = 0;

      for (let i = 0; i < questions.length; i++) {
        const q = questions[i];
        if (q.typeOfAnswer !== 'MCQ') continue;

        const currentWrongs = q.wrongAnswer || [];
        if (currentWrongs.length === 4) {
          modSkipped++;
          continue; // already fixed
        }

        if (currentWrongs.length !== 3) {
          console.error(`    ⚠️ ${exam.name} ${modLabel} Q${i+1} (${q._id}): unexpected ${currentWrongs.length} choices`);
          grandErrors++;
          continue;
        }

        // Has 3 choices - need to add correctAnswer to make 4
        // Check correctAnswer is not already in the list (by stripped text)
        const correctClean = strip(q.correctAnswer);
        const alreadyInList = currentWrongs.some(w => strip(w) === correctClean);

        if (alreadyInList) {
          // correctAnswer text already exists among the 3 wrongs - this is a different problem
          console.error(`    ⚠️ ${exam.name} ${modLabel} Q${i+1} (${q._id}): correctAnswer already in wrongAnswer (duplicate text), skipping`);
          grandErrors++;
          continue;
        }

        // Insert correctAnswer at a random position among the 4 choices
        const randomPos = Math.floor(Math.random() * 4);
        const newWrongs = [...currentWrongs];
        newWrongs.splice(randomPos, 0, q.correctAnswer);

        // Verify we now have 4 unique choices
        const uniqueTexts = new Set(newWrongs.map(strip));
        if (uniqueTexts.size !== 4) {
          console.error(`    ⚠️ ${exam.name} ${modLabel} Q${i+1} (${q._id}): would not produce 4 unique choices (${uniqueTexts.size}), skipping`);
          grandErrors++;
          continue;
        }

        try {
          const updateRes = await axios.put(`${BASE_URL}/question/updateQuestion/${q._id}`, {
            wrongAnswer: newWrongs
          });
          if (updateRes.data.message === 'success' || updateRes.data.question) {
            modFixed++;
          } else {
            console.error(`    ⚠️ ${exam.name} ${modLabel} Q${i+1} (${q._id}): unexpected response`);
            grandErrors++;
          }
        } catch (err) {
          console.error(`    ⚠️ ${exam.name} ${modLabel} Q${i+1} (${q._id}): update failed: ${err.message}`);
          grandErrors++;
        }
      }

      if (modFixed > 0) {
        console.log(`  ✅ ${exam.name} ${modLabel}: fixed ${modFixed} MCQs (${modSkipped} already OK)`);
      }
      grandFixed += modFixed;
      grandAlreadyOk += modSkipped;

      await sleep(200);
    }
  }

  // ===================== FULL VERIFICATION =====================
  console.log('\n' + '='.repeat(70));
  console.log('FULL VERIFICATION: All real exams');
  console.log('='.repeat(70));

  let allPass = true;
  for (const exam of dir) {
    if (!exam.m1 || !exam.m2) continue;

    let examOk = true;
    let details = [];

    for (const [modKey, modLabel] of [['m1', 'M1'], ['m2', 'M2']]) {
      const mod = exam[modKey];
      if (!mod || !mod.id) continue;

      try {
        const res = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${mod.id}`);
        const questions = res.data.chapter.questions;
        let totalMCQ = 0, with4 = 0, with3 = 0;
        for (const q of questions) {
          if (q.typeOfAnswer === 'MCQ') {
            totalMCQ++;
            const c = (q.wrongAnswer || []).length;
            if (c === 4) with4++;
            if (c === 3) with3++;
          }
        }
        details.push(`${modLabel}=${with4}/${totalMCQ}`);
        if (with3 > 0) examOk = false;
      } catch (err) {
        details.push(`${modLabel}=ERR`);
        examOk = false;
      }
      await sleep(150);
    }

    if (!examOk) allPass = false;
    console.log(`${examOk ? '✅' : '❌'} ${exam.name}: ${details.join(' ')}`);
  }

  console.log('\n' + '='.repeat(70));
  console.log(`SUMMARY: Fixed ${grandFixed} remaining MCQs. Errors: ${grandErrors}. Already OK: ${grandAlreadyOk}`);
  console.log(allPass ? '🎉 ALL EXAMS NOW HAVE 4 CHOICES!' : '⚠️ Some exams still have issues');
  console.log('='.repeat(70));
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
