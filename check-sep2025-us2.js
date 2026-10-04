const axios = require('axios');

const BASE_URL = 'https://sat-backend-production.up.railway.app';
// Find chapters for US 2
const fs = require('fs');

async function checkUS2() {
  const dir = JSON.parse(fs.readFileSync('all_real_exams_directory.json', 'utf8'));
  const sepUS2 = dir.find(e => e.examName && (e.examName.includes('September 2025') || e.examName.includes('Sep 2025')) && (e.examName.includes('US 2') || e.examName.includes('US2')));
  console.log('September 2025 US 2 exam entry:', sepUS2);

  if (sepUS2 && sepUS2.modules) {
    for (const mod of sepUS2.modules) {
      console.log(`Checking ${mod.moduleName} (${mod.chapterId})...`);
      const res = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${mod.chapterId}`);
      const questions = res.data.chapter.questions;
      let mcqs = 0;
      let with3 = 0;
      let with4 = 0;
      questions.forEach((q, i) => {
        if (q.typeOfAnswer === 'MCQ') {
          mcqs++;
          const cCount = (q.wrongAnswer || []).length;
          if (cCount === 3) with3++;
          if (cCount === 4) with4++;
        }
      });
      console.log(`  MCQs: ${mcqs}, 3 choices: ${with3}, 4 choices: ${with4}`);
    }
  }
}

checkUS2().catch(console.error);
