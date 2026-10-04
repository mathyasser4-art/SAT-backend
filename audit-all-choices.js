const axios = require('axios');
const fs = require('fs');

const BASE_URL = 'https://sat-backend-production.up.railway.app';
const dir = JSON.parse(fs.readFileSync('all_real_exams_directory.json', 'utf8'));

async function auditAll() {
  console.log('Auditing choices count across all real exams...\n');
  const results = [];

  for (const e of dir) {
    if (!e.m1 || !e.m2) continue;
    let examIssues = 0;
    const examInfo = { name: e.name, m1Issues: 0, m2Issues: 0 };

    for (const [modKey, label] of [['m1', 'Module 1'], ['m2', 'Module 2']]) {
      const mod = e[modKey];
      try {
        const res = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${mod.id}`);
        const questions = res.data.chapter.questions || [];
        let count3 = 0;
        questions.forEach(q => {
          if (q.typeOfAnswer === 'MCQ' && (q.wrongAnswer || []).length === 3) {
            count3++;
          }
        });
        if (modKey === 'm1') examInfo.m1Issues = count3;
        else examInfo.m2Issues = count3;
        examIssues += count3;
      } catch (err) {
        console.error(`Error fetching ${e.name} ${label}:`, err.message);
      }
    }

    if (examIssues > 0) {
      console.log(`⚠️ ${e.name}: M1 has ${examInfo.m1Issues} 3-choice MCQs, M2 has ${examInfo.m2Issues} 3-choice MCQs`);
    } else {
      console.log(`✅ ${e.name}: All MCQs have 4 choices`);
    }
    results.push(examInfo);
  }
}

auditAll().catch(console.error);
