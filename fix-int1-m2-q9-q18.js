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
    const d = JSON.parse(fs.readFileSync('scratch_march_2026_int1_m2.json', 'utf8'));
    
    // --- FIX Q9 ---
    const q9Id = '6a53571b4d554e04aa1bf687';
    
    const wrongAnswers = [
        '<p><span class="ql-formula" data-value="\\frac{8}{11} \\times 90 \\times 2"></span></p>',
        '<p><span class="ql-formula" data-value="\\frac{8}{11} \\times 180 \\times 2"></span></p>',
        '<p><span class="ql-formula" data-value="\\frac{8}{11\\pi} \\times 90 \\times 2"></span></p>',
        '<p><span class="ql-formula" data-value="\\frac{8\\pi}{11} \\times 180 \\times 2"></span></p>'
    ];
    
    console.log("Fixing Q9... Sending update");
    const res9 = await updateQuestion(q9Id, { 
        wrongAnswer: wrongAnswers,
        correctAnswer: wrongAnswers[1] 
    });
    console.log("Q9 update response:", res9);
    
    // --- FIX Q18 ---
    const q18Id = '6a5496cd4d554e04aa1bfda6';
    const newAnswers = ["2.8", "14/5", "3.2", "16/5"]; // Accepting all valid variants
    
    console.log("Fixing Q18... Sending update");
    const res18 = await updateQuestion(q18Id, { answer: newAnswers });
    console.log("Q18 update response:", res18);
}

fix();
