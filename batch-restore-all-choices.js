const axios = require('axios');
const fs = require('fs');

const BASE_URL = 'https://sat-backend-production.up.railway.app';

function strip(s) {
  return (s || '').replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/[\s\u200B\u3164\uFEFF]+/g, ' ').trim();
}

// Map of exams that need fixing, with their chapter IDs and scratch files
const EXAMS_TO_FIX = [
  {
    name: 'September 2025 · US 2',
    m1: { id: '6a6964cbc3d08d90637d3df5', scratch: 'scratch_sep2025_us2_m1.json' },
    m2: { id: '6a6964d0c3d08d90637d3dfb', scratch: 'scratch_sep2025_us2_m2.json' },
  },
  {
    name: 'March 2026 · US 2',
    m1: { id: '6a52d43b4d554e04aa1bf37e', scratch: 'scratch_march_2026_us2_m1.json' },
    m2: { id: '6a52d4434d554e04aa1bf384', scratch: 'scratch_march_2026_us2_m2.json' },
  },
  {
    name: 'March 2026 · INT 1',
    m1: { id: '6a5308df4d554e04aa1bf552', scratch: 'scratch_march_2026_int1_m1.json' },
    m2: { id: '6a534dbd4d554e04aa1bf642', scratch: 'scratch_march_2026_int1_m2.json' },
  },
  {
    name: 'March 2026 · INT 2',
    m1: { id: '6a53d2914d554e04aa1bf8e2', scratch: 'scratch_march_2026_int2_m1.json' },
    m2: { id: '6a53d2994d554e04aa1bf8e8', scratch: 'scratch_march_2026_int2_m2.json' },
  },
  {
    name: 'November 2025 · INT 2',
    m1: { id: '6a5b439dc3d08d90637d30f9', scratch: 'scratch_nov2025_int2_m1.json' },
    m2: { id: '6a5b43a2c3d08d90637d30ff', scratch: 'scratch_nov2025_int2_m2.json' },
  },
  {
    name: 'November 2025 · INT 1',
    m1: { id: '6a5b4659c3d08d90637d313e', scratch: 'scratch_nov2025_int1_m1.json' },
    m2: { id: '6a5b4663c3d08d90637d3144', scratch: 'scratch_nov2025_int1_m2.json' },
  },
  {
    name: 'November 2025 · INT 3',
    m1: { id: '6a622fc3c3d08d90637d34a6', scratch: 'scratch_nov2025_int3_m1.json' },
    m2: { id: '6a622fc8c3d08d90637d34ac', scratch: 'scratch_nov2025_int3_m2.json' },
  },
  {
    name: 'October 2025 · INT 1',
    m1: { id: '6a624c21c3d08d90637d361e', scratch: 'scratch_oct2025_int1_m1.json' },
    m2: { id: '6a624c27c3d08d90637d3624', scratch: 'scratch_oct2025_int1_m2.json' },
  },
  {
    name: 'October 2025 · INT 2',
    m1: { id: '6a626236c3d08d90637d367e', scratch: 'scratch_oct2025_int2_m1.json' },
    m2: { id: '6a626240c3d08d90637d3684', scratch: 'scratch_oct2025_int2_m2.json' },
  },
  {
    name: 'October 2025 · US 1',
    m1: { id: '6a66595cc3d08d90637d39ee', scratch: 'scratch_oct2025_us1_m1.json' },
    m2: { id: '6a665962c3d08d90637d39f4', scratch: 'scratch_oct2025_us1_m2.json' },
  },
  {
    name: 'August 2025 · INT 2',
    m1: { id: '6a6cb17cc3d08d90637d4043', scratch: 'scratch_aug2025_int2_m1.json' },
    m2: { id: '6a6cb182c3d08d90637d4049', scratch: 'scratch_aug2025_int2_m2.json' },
  },
  {
    name: 'June 2025 · INT 1',
    m1: { id: '6a6d285814cab24f9785a709', scratch: 'scratch_june2025_int1_m1.json' },
    m2: { id: '6a6d285d14cab24f9785a70f', scratch: 'scratch_june2025_int1_m2.json' },
  },
  {
    name: 'June 2025 · INT 2',
    m1: { id: '6a6d4b8e14cab24f9785a814', scratch: 'scratch_june2025_int2_m1.json' },
    m2: { id: '6a6d4b9614cab24f9785a81a', scratch: 'scratch_june2025_int2_m2.json' },
  },
  {
    name: 'June 2025 · US 1',
    m1: { id: '6a6d680707c5da645a88cae3', scratch: 'scratch_june2025_us1_m1.json' },
    m2: { id: '6a6d680d07c5da645a88caeb', scratch: 'scratch_june2025_us1_m2.json' },
  },
  {
    name: 'May 2025 · INT 1',
    m1: { id: '6a6e262e5db514110caca7b9', scratch: 'scratch_may2025_int1_m1.json' },
    m2: { id: '6a6e26345db514110caca7bf', scratch: 'scratch_may2025_int1_m2.json' },
  },
  {
    name: 'May 2025 · INT 2',
    m1: { id: '6a9b2dcc111ffc76c2e611cb', scratch: 'scratch_may2025_int2_m1.json' },
    m2: { id: '6a9b2dd4111ffc76c2e611d1', scratch: 'scratch_may2025_int2_m2.json' },
  },
  {
    name: 'May 2025 · INT 3',
    m1: { id: '6a9c19964471c51d35c19dd3', scratch: 'scratch_may2025_int3_m1.json' },
    m2: { id: '6a9c199e4471c51d35c19dd9', scratch: 'scratch_may2025_int3_m2.json' },
  },
  {
    name: 'March 2025 · INT 1',
    m1: { id: '6aa0f076df63ca493d4799ef', scratch: 'scratch_march2025_int1_m1.json' },
    m2: { id: '6aa0f07cdf63ca493d4799f5', scratch: 'scratch_march2025_int1_m2.json' },
  },
  {
    name: 'March 2025 · INT 2',
    m1: { id: '6aa120d2ec7ba02921a31dca', scratch: 'scratch_march2025_int2_m1.json' },
    m2: { id: '6aa120d9ec7ba02921a31dd0', scratch: 'scratch_march2025_int2_m2.json' },
  },
  {
    name: 'March 2025 · INT 3',
    m1: { id: '6aa47c31ec7ba02921a43f25', scratch: 'scratch_march2025_int3_m1.json' },
    m2: { id: '6aa47c38ec7ba02921a43f2b', scratch: 'scratch_march2025_int3_m2.json' },
  },
  {
    name: 'December 2024 · INT1',
    m1: { id: '6aa5832dec7ba02921a44437', scratch: 'scratch_dec2024_int1_m1.json' },
    m2: { id: '6aa58333ec7ba02921a4443d', scratch: 'scratch_dec2024_int1_m2.json' },
  },
];

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function fixOneModule(examName, modLabel, chapterId, scratchFile) {
  // Load scratch data
  if (!fs.existsSync(scratchFile)) {
    console.error(`  ❌ SKIP ${modLabel}: scratch file ${scratchFile} not found!`);
    return { updated: 0, skipped: 0, errors: 0, notFound: 1 };
  }

  const scratchData = JSON.parse(fs.readFileSync(scratchFile, 'utf8'));
  const scratchQuestions = scratchData.chapter?.questions || [];
  if (scratchQuestions.length === 0) {
    console.error(`  ❌ SKIP ${modLabel}: scratch file has no questions!`);
    return { updated: 0, skipped: 0, errors: 0, notFound: 1 };
  }

  // Fetch live data
  let liveQuestions;
  try {
    const res = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${chapterId}`);
    liveQuestions = res.data.chapter.questions;
  } catch (err) {
    console.error(`  ❌ SKIP ${modLabel}: API error: ${err.message}`);
    return { updated: 0, skipped: 0, errors: 1, notFound: 0 };
  }

  let updated = 0;
  let skipped = 0;
  let errors = 0;

  for (let i = 0; i < liveQuestions.length; i++) {
    const lq = liveQuestions[i];
    if (lq.typeOfAnswer !== 'MCQ') continue;

    const liveChoices = lq.wrongAnswer || [];
    if (liveChoices.length === 4) {
      skipped++;
      continue; // already has 4 choices
    }

    // Find matching scratch question
    const sq = scratchQuestions.find(q => q._id === lq._id);
    if (!sq) {
      console.error(`    ⚠️ Q${i+1} (${lq._id}): not found in scratch file`);
      errors++;
      continue;
    }

    const scratchChoices = sq.wrongAnswer || [];
    if (scratchChoices.length !== 4) {
      console.error(`    ⚠️ Q${i+1} (${lq._id}): scratch has ${scratchChoices.length} choices, not 4`);
      errors++;
      continue;
    }

    // Verify scratch choices contain the correctAnswer
    const correctClean = strip(lq.correctAnswer);
    const containsCorrect = scratchChoices.some(c => c === lq.correctAnswer || strip(c) === correctClean);
    if (!containsCorrect) {
      console.error(`    ⚠️ Q${i+1} (${lq._id}): scratch choices do NOT contain correctAnswer!`);
      errors++;
      continue;
    }

    // Update the question
    try {
      const updateRes = await axios.put(`${BASE_URL}/question/updateQuestion/${lq._id}`, {
        wrongAnswer: scratchChoices
      });
      if (updateRes.data.message === 'success' || updateRes.data.question) {
        updated++;
      } else {
        console.error(`    ⚠️ Q${i+1} (${lq._id}): unexpected response:`, updateRes.data);
        errors++;
      }
    } catch (err) {
      console.error(`    ⚠️ Q${i+1} (${lq._id}): update failed: ${err.message}`);
      errors++;
    }
  }

  return { updated, skipped, errors, notFound: 0 };
}

async function verifyModule(modLabel, chapterId) {
  try {
    const res = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${chapterId}`);
    const questions = res.data.chapter.questions;
    let totalMCQ = 0;
    let with4 = 0;
    for (const q of questions) {
      if (q.typeOfAnswer === 'MCQ') {
        totalMCQ++;
        if ((q.wrongAnswer || []).length === 4) with4++;
      }
    }
    return { totalMCQ, with4, pass: totalMCQ === with4 };
  } catch (err) {
    return { totalMCQ: 0, with4: 0, pass: false, error: err.message };
  }
}

async function main() {
  console.log('='.repeat(70));
  console.log('BATCH RESTORE: Fixing 4 choices across all affected real exams');
  console.log('='.repeat(70));
  console.log(`Total exams to fix: ${EXAMS_TO_FIX.length}\n`);

  const summary = [];

  for (let e = 0; e < EXAMS_TO_FIX.length; e++) {
    const exam = EXAMS_TO_FIX[e];
    console.log(`\n[${ e + 1}/${EXAMS_TO_FIX.length}] ===== ${exam.name} =====`);

    // Fix Module 1
    console.log(`  Module 1 (${exam.m1.id}) ← ${exam.m1.scratch}`);
    const r1 = await fixOneModule(exam.name, 'Module 1', exam.m1.id, exam.m1.scratch);
    console.log(`    → Updated: ${r1.updated}, Already OK: ${r1.skipped}, Errors: ${r1.errors}`);

    // Small delay to avoid rate limiting
    await sleep(300);

    // Fix Module 2
    console.log(`  Module 2 (${exam.m2.id}) ← ${exam.m2.scratch}`);
    const r2 = await fixOneModule(exam.name, 'Module 2', exam.m2.id, exam.m2.scratch);
    console.log(`    → Updated: ${r2.updated}, Already OK: ${r2.skipped}, Errors: ${r2.errors}`);

    await sleep(300);

    summary.push({
      name: exam.name,
      m1: r1,
      m2: r2,
      totalUpdated: r1.updated + r2.updated,
      totalErrors: r1.errors + r2.errors,
    });
  }

  // ===================== VERIFICATION PASS =====================
  console.log('\n' + '='.repeat(70));
  console.log('VERIFICATION PASS: Checking all exams now have 4 choices');
  console.log('='.repeat(70));

  let allPass = true;

  for (const exam of EXAMS_TO_FIX) {
    const v1 = await verifyModule('Module 1', exam.m1.id);
    const v2 = await verifyModule('Module 2', exam.m2.id);
    const examPass = v1.pass && v2.pass;
    if (!examPass) allPass = false;

    const icon = examPass ? '✅' : '❌';
    console.log(`${icon} ${exam.name}: M1=${v1.with4}/${v1.totalMCQ} M2=${v2.with4}/${v2.totalMCQ}${v1.error ? ' (M1 err: ' + v1.error + ')' : ''}${v2.error ? ' (M2 err: ' + v2.error + ')' : ''}`);
    await sleep(200);
  }

  // ===================== FINAL SUMMARY =====================
  console.log('\n' + '='.repeat(70));
  console.log('FINAL SUMMARY');
  console.log('='.repeat(70));

  let grandUpdated = 0;
  let grandErrors = 0;
  for (const s of summary) {
    grandUpdated += s.totalUpdated;
    grandErrors += s.totalErrors;
    console.log(`  ${s.totalErrors === 0 ? '✅' : '⚠️'} ${s.name}: ${s.totalUpdated} MCQs updated, ${s.totalErrors} errors`);
  }

  console.log(`\nGrand Total: ${grandUpdated} MCQs updated across ${EXAMS_TO_FIX.length} exams. Errors: ${grandErrors}`);
  console.log(allPass ? '\n🎉 ALL EXAMS NOW HAVE 4 CHOICES!' : '\n⚠️ SOME EXAMS STILL HAVE ISSUES - CHECK ERRORS ABOVE');
  console.log('='.repeat(70));
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
