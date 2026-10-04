const axios = require('axios');

const BASE_URL = 'https://sat-backend-production.up.railway.app';
const Q_TYPE_ID = '65a4963482dbaac16d820fc6';

async function findExam() {
  console.log('Searching for September 2025 in Real Exams...');
  try {
    const sysRes = await axios.get(`${BASE_URL}/system/getAllSystem`);
    const real = sysRes.data.allSystem.find(s => s.systemName === 'Real Exams');
    if (!real) {
      console.log('Real Exams not found!');
      return;
    }
    console.log(`Found Real Exams system with ${real.subjects.length} subjects.`);

    real.subjects.forEach((s, idx) => {
      console.log(`[${idx + 1}] ID: ${s._id} | SubjectName: "${s.subjectName}"`);
    });

    const targetSub = real.subjects.find(s => 
      s.subjectName.toLowerCase().includes('sep') ||
      s.subjectName.toLowerCase().includes('september')
    );

    if (targetSub) {
      console.log(`\n🎯 Found Target Subject: ID: ${targetSub._id} | "${targetSub.subjectName}"`);
      const unitsRes = await axios.get(`${BASE_URL}/unit/getUnit/${Q_TYPE_ID}/${targetSub._id}`);
      const units = unitsRes.data.allUnit || [];
      console.log(`Found ${units.length} units.`);
      for (const u of units) {
        console.log(`\nUnit ID: ${u._id} | Name: "${u.unitName}"`);
        for (const ch of (u.chapters || [])) {
          console.log(`  Chapter ID: ${ch._id} | ChapterName: "${ch.chapterName}"`);
          const chapRes = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${ch._id}`);
          const qCount = chapRes.data.chapter?.questions?.length || 0;
          console.log(`    Questions Count: ${qCount}`);
        }
      }
    } else {
      console.log('\n❌ No subject found matching "sep" or "september".');
    }
  } catch (err) {
    console.error('Error:', err.message);
  }
}

findExam();
