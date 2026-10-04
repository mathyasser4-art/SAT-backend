const fs = require('fs');

function checkScratch() {
  for (const file of ['scratch_sep2025_us1_m1.json', 'scratch_sep2025_us1_m2.json']) {
    console.log(`\n=== Checking ${file} ===`);
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    const questions = data.chapter.questions;
    console.log(`Total questions: ${questions.length}`);
    let mcqCount = 0;
    let fourCount = 0;

    questions.forEach((q, idx) => {
      if (q.typeOfAnswer === 'MCQ') {
        mcqCount++;
        const wrongs = q.wrongAnswer || [];
        if (wrongs.length === 4) {
          fourCount++;
        } else {
          console.log(`Q${idx+1} (${q._id}): length = ${wrongs.length}`);
        }
      }
    });

    console.log(`MCQs: ${mcqCount}, Exactly 4 choices: ${fourCount}`);
  }
}

checkScratch();
