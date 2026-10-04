const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';

function updateQuestion(questionId, payloadObj) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(payloadObj);
    const req = https.request(`${API_BASE}/question/updateQuestion/${questionId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          resolve({ raw: data });
        }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

async function run() {
  console.log('🚀 Updating October 2025 INT 2 Grid-In / Essay Questions with correct answers and accepted answers...\n');

  const fixes = [
    {
      label: 'M1 Q5',
      id: '6a62714dc3d08d90637d36dc',
      payload: {
        correctAnswer: '<p>0.25</p>',
        answer: ['0.25', '1/4', '.25']
      }
    },
    {
      label: 'M2 Q9',
      id: '6a6293c9c3d08d90637d3828',
      payload: {
        correctAnswer: '<p>196</p>',
        answer: ['196']
      }
    },
    {
      label: 'M2 Q17',
      id: '6a629b37c3d08d90637d3860',
      payload: {
        correctAnswer: '<p>1/8</p>',
        answer: ['0.125', '1/8', '.125']
      }
    },
    {
      label: 'M2 Q18',
      id: '6a629d10c3d08d90637d386c',
      payload: {
        correctAnswer: '<p>1680</p>',
        answer: ['1680', '1,680', '1.680']
      }
    },
    {
      label: 'M2 Q22',
      id: '6a663ab4c3d08d90637d38b5',
      payload: {
        correctAnswer: '<p>15435</p>',
        answer: ['15435', '15,435']
      }
    }
  ];

  for (const f of fixes) {
    process.stdout.write(`Updating ${f.label} (${f.id})... `);
    try {
      const res = await updateQuestion(f.id, f.payload);
      console.log(res.message === 'success' ? '✅ Updated' : JSON.stringify(res));
    } catch (err) {
      console.log('❌ Error:', err.message);
    }
  }

  console.log('\nAll 5 Grid-In / Essay questions now have complete accepted answers and correctAnswer fields.');
}

run();
