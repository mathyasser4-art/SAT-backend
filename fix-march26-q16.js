const https = require('https');
const fs = require('fs');
const API_BASE = 'https://sat-backend-production.up.railway.app';

function updateQuestion(questionId, payload) {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify(payload);
        const req = https.request(`${API_BASE}/question/updateQuestion/${questionId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(data)
            }
        }, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(body));
                } catch (e) {
                    resolve({ raw: body });
                }
            });
        });
        req.on('error', reject);
        req.write(data);
        req.end();
    });
}

async function fix() {
    const d = JSON.parse(fs.readFileSync('scratch_march_2026_us1_m2.json', 'utf8'));
    const qId = '6a5264f34d554e04aa1bf1f1';
    const q = d.chapter.questions.find(x => x._id === qId);
    let stem = q.question;
    
    // Replace KST with RST in the data-value and annotation
    stem = stem.replace(/KST/g, 'RST');
    // Replace <mi>K</mi> with <mi>R</mi>
    stem = stem.replace(/<mi>K<\/mi>/g, '<mi>R</mi>');
    // Replace >K< with >R< inside the span (there should be only one such K)
    stem = stem.replace(/>K</g, '>R<');
    
    console.log("Sending update...");
    const res = await updateQuestion(qId, { question: stem });
    console.log("Update response:", res);
}
fix();
