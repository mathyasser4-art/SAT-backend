const https = require('https');

const sampleIds = [
  { mod: 'M1 Q1', id: '6a518ce14d554e04aa1bec40' },
  { mod: 'M1 Q5', id: '6a5191724d554e04aa1bec70' },
  { mod: 'M1 Q8', id: '6a51955e4d554e04aa1becca' },
  { mod: 'M2 Q6', id: '6a525c754d554e04aa1bf157' },
  { mod: 'M2 Q10', id: '6a525fdc4d554e04aa1bf191' },
  { mod: 'M2 Q19', id: '6a52681a4d554e04aa1bf22b' },
  { mod: 'M2 Q21', id: '6a526b154d554e04aa1bf247' }
];

function fetchQ(id) {
  return new Promise((resolve, reject) => {
    https.get(`https://sat-backend-production.up.railway.app/question/getQuestionDetails/${id}`, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(JSON.parse(data)));
    }).on('error', reject);
  });
}

function checkAns(id, ans) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({ questionAnswer: ans });
    const req = https.request(`https://sat-backend-production.up.railway.app/question/checkTheAnswer/${id}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(JSON.parse(data)));
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

async function run() {
  console.log('Verifying March 2026 US 1 updates...\n');
  for (const s of sampleIds) {
    const qData = await fetchQ(s.id);
    const q = qData.question;
    console.log(`[${s.mod}] ID: ${s.id}`);
    console.log(`  Stem: ${q.questionText ? q.questionText.substring(0, 70).replace(/\n/g, ' ') : ''}...`);
    console.log(`  QuestionPic: ${q.questionPic || 'None'}`);
    console.log(`  Explanation Length: ${q.explanation ? q.explanation.length : 0} chars`);
    
    // Test checkTheAnswer with correct answer
    const ansToSend = q.typeOfAnswer === 'Essay' ? q.answer[0] : q.correctAnswer;
    const checkRes = await checkAns(s.id, ansToSend);
    console.log(`  checkTheAnswer Status: ${checkRes.message}, Explanation Returned: ${Boolean(checkRes.explanation)}`);
    console.log('--------------------------------------------------');
  }
}

run().catch(console.error);
