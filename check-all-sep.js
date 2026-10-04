const axios = require('axios');
const fs = require('fs');

const BASE_URL = 'https://sat-backend-production.up.railway.app';
const dir = JSON.parse(fs.readFileSync('all_real_exams_directory.json', 'utf8'));

async function checkSepExams() {
  const sepExams = dir.filter(e => e.name && e.name.includes('September 2025'));
  for (const e of sepExams) {
    console.log(`\nExam: ${e.name}`);
    for (const modKey of ['m1', 'm2']) {
      const mod = e[modKey];
      if (!mod || !mod.id) continue;
      const res = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${mod.id}`);
      const questions = res.data.chapter.questions;
      let mcqs = 0;
      let with3 = 0;
      let with4 = 0;
      questions.forEach(q => {
        if (q.typeOfAnswer === 'MCQ') {
          mcqs++;
          const c = (q.wrongAnswer || []).length;
          if (c === 3) with3++;
          if (c === 4) with4++;
        }
      });
      console.log(`  ${mod.title} (${mod.id}): MCQs=${mcqs}, 3choices=${with3}, 4choices=${with4}`);
    }
  }
}

checkSepExams().catch(console.error);
