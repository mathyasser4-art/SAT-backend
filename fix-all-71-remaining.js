const axios = require('axios');
const fs = require('fs');

const BASE_URL = 'https://sat-backend-production.up.railway.app';
const dir = JSON.parse(fs.readFileSync('all_real_exams_directory.json', 'utf8'));

function normalizeChoice(html) {
  if (!html) return '';
  let parts = [];
  
  // Extract data-value attributes (formula content)
  const formulaRegex = /data-value="([^"]*)"/g;
  let m;
  while ((m = formulaRegex.exec(html)) !== null) {
    parts.push(m[1]);
  }
  
  // Extract img src attributes
  const imgRegex = /<img[^>]+src="([^">]+)"/g;
  while ((m = imgRegex.exec(html)) !== null) {
    parts.push(m[1]);
  }

  // Extract raw text
  const text = (html || '')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/[\s\u200B\u3164\uFEFF]+/g, ' ')
    .trim();

  if (text) {
    parts.push(text);
  }

  return parts.join(' ').trim();
}

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
  console.log('='.repeat(70));
  console.log('FINAL PASS: Restoring 4 choices for all remaining 71 MCQs');
  console.log('='.repeat(70));

  let fixedCount = 0;
  let errorCount = 0;

  for (const exam of dir) {
    if (!exam.m1 || !exam.m2) continue;

    for (const [modKey, modLabel] of [['m1', 'Module 1'], ['m2', 'Module 2']]) {
      const mod = exam[modKey];
      if (!mod || !mod.id) continue;

      let questions;
      try {
        const res = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${mod.id}`);
        questions = res.data.chapter?.questions || [];
      } catch (err) {
        console.error(`  ❌ Failed to fetch ${exam.name} ${modLabel}: ${err.message}`);
        errorCount++;
        continue;
      }

      let modFixed = 0;

      for (let i = 0; i < questions.length; i++) {
        const q = questions[i];
        if (q.typeOfAnswer !== 'MCQ') continue;

        const currentWrongs = q.wrongAnswer || [];
        if (currentWrongs.length === 4) continue; // Already has 4 choices

        if (currentWrongs.length !== 3) {
          console.error(`  ⚠️ ${exam.name} ${modLabel} Q${i+1} (${q._id}): unexpected length ${currentWrongs.length}`);
          errorCount++;
          continue;
        }

        const correctNorm = normalizeChoice(q.correctAnswer);
        const wrongNorms = currentWrongs.map(normalizeChoice);

        if (wrongNorms.includes(correctNorm)) {
          console.error(`  ⚠️ ${exam.name} ${modLabel} Q${i+1} (${q._id}): correctAnswer already exists in choices!`);
          errorCount++;
          continue;
        }

        // Insert correctAnswer at a random index 0..3
        const insertIdx = Math.floor(Math.random() * 4);
        const newWrongs = [...currentWrongs];
        newWrongs.splice(insertIdx, 0, q.correctAnswer);

        // Sanity check: must now be 4 choices
        if (newWrongs.length !== 4) {
          console.error(`  ⚠️ ${exam.name} ${modLabel} Q${i+1}: length is not 4 after insert`);
          errorCount++;
          continue;
        }

        try {
          const updateRes = await axios.put(`${BASE_URL}/question/updateQuestion/${q._id}`, {
            wrongAnswer: newWrongs
          });

          if (updateRes.data.message === 'success' || updateRes.data.question) {
            modFixed++;
            fixedCount++;
          } else {
            console.error(`  ⚠️ ${exam.name} ${modLabel} Q${i+1} (${q._id}): unexpected response:`, updateRes.data);
            errorCount++;
          }
        } catch (err) {
          console.error(`  ❌ ${exam.name} ${modLabel} Q${i+1} (${q._id}): update error: ${err.message}`);
          errorCount++;
        }

        await sleep(100);
      }

      if (modFixed > 0) {
        console.log(`  ✅ Fixed ${modFixed} MCQs in ${exam.name} ${modLabel}`);
      }
    }
  }

  console.log('\n' + '='.repeat(70));
  console.log(`PASS COMPLETE: Successfully updated ${fixedCount} MCQs. Errors: ${errorCount}`);
  console.log('='.repeat(70));

  // ===================== FULL COMPREHENSIVE AUDIT =====================
  console.log('\n' + '='.repeat(70));
  console.log('COMPREHENSIVE AUDIT OF ALL REAL EXAMS');
  console.log('='.repeat(70));

  let totalExams = 0;
  let perfectExams = 0;
  let examsWithIssues = [];

  for (const exam of dir) {
    if (!exam.m1 || !exam.m2) continue;
    totalExams++;
    let examOk = true;
    let details = [];

    for (const [modKey, modLabel] of [['m1', 'M1'], ['m2', 'M2']]) {
      const mod = exam[modKey];
      if (!mod || !mod.id) continue;

      try {
        const res = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${mod.id}`);
        const qs = res.data.chapter?.questions || [];
        let mcqs = 0;
        let with4 = 0;
        let non4 = [];

        for (let idx = 0; idx < qs.length; idx++) {
          const q = qs[idx];
          if (q.typeOfAnswer === 'MCQ') {
            mcqs++;
            const count = (q.wrongAnswer || []).length;
            if (count === 4) {
              with4++;
            } else {
              non4.push({ q: idx + 1, count, id: q._id });
              examOk = false;
            }
          }
        }

        if (non4.length > 0) {
          details.push(`${modLabel}: ${with4}/${mcqs} (bad: ${non4.map(b => `Q${b.q}[${b.count}]`).join(', ')})`);
        } else {
          details.push(`${modLabel}: ${with4}/${mcqs} (100%)`);
        }
      } catch (err) {
        details.push(`${modLabel}: ERR(${err.message})`);
        examOk = false;
      }

      await sleep(100);
    }

    if (examOk) {
      perfectExams++;
      console.log(`✅ ${exam.name}: ${details.join(' | ')}`);
    } else {
      examsWithIssues.push({ name: exam.name, details: details.join(' | ') });
      console.log(`❌ ${exam.name}: ${details.join(' | ')}`);
    }
  }

  console.log('\n' + '='.repeat(70));
  console.log(`FINAL REPORT: ${perfectExams}/${totalExams} real exams have 100% of MCQs with exactly 4 choices.`);
  if (examsWithIssues.length === 0) {
    console.log('🎉 ALL REAL EXAMS ARE FULLY VERIFIED AND PERFECT!');
  } else {
    console.log(`⚠️ ${examsWithIssues.length} exams still have issues.`);
  }
  console.log('='.repeat(70));
}

main().catch(err => {
  console.error('Fatal crash:', err);
  process.exit(1);
});
