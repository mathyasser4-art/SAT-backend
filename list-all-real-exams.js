const https = require('https');
const fs = require('fs');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const Q_TYPE_ID = '65a4963482dbaac16d820fc6';
const REAL_EXAMS_SYSTEM_ID = '69e7cbcac0cd6fbad9c578af';

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', reject);
  });
}

async function run() {
  const sysRes = await fetchJson(`${API_BASE}/system/getAllSystem`);
  const realSystem = sysRes.allSystem.find(s => s._id === REAL_EXAMS_SYSTEM_ID || s.systemName === 'Real Exams');

  console.log(`Found ${realSystem.subjects.length} exams in Real Exams system:`);
  const exams = [];

  for (let i = 0; i < realSystem.subjects.length; i++) {
    const sub = realSystem.subjects[i];
    const examName = sub.subjectName.trim();
    let unitsRes = await fetchJson(`${API_BASE}/unit/getUnit/${Q_TYPE_ID}/${sub._id}`);
    const unit = (unitsRes.allUnit || [])[0];
    const m1 = unit?.chapters?.[0];
    const m2 = unit?.chapters?.[1];

    exams.push({
      index: i + 1,
      name: examName,
      subjectId: sub._id,
      unitId: unit?._id,
      unitName: unit?.unitName,
      m1: { title: m1?.chapterName, id: m1?._id },
      m2: { title: m2?.chapterName, id: m2?._id }
    });
    console.log(`${i + 1}. ${examName} | Sub: ${sub._id} | M1: ${m1?._id} | M2: ${m2?._id}`);
  }

  fs.writeFileSync('all_real_exams_directory.json', JSON.stringify(exams, null, 2));
  console.log('Saved all_real_exams_directory.json successfully!');
}

run().catch(console.error);
