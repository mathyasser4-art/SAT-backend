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
    // --- FIX Q16 ---
    const q16Id = '6a53dcac4d554e04aa1bf988';
    
    const q16Answers = [
        '<p>0</p>',
        '<p>7</p>',
        '<p>72</p>',
        '<p>79</p>'
    ];
    
    console.log("Fixing Q16... Sending update");
    const res16 = await updateQuestion(q16Id, { 
        wrongAnswer: q16Answers,
        correctAnswer: '<p>79</p>'
    });
    console.log("Q16 update response:", res16);
    
    // --- FIX Q17 ---
    const q17Id = '6a53dd5a4d554e04aa1bf994';
    
    const q17Answers = [
        '<p><span class="ql-formula" data-value="\\frac{9}{11} \\times 90 \\times 3"></span></p>',
        '<p><span class="ql-formula" data-value="\\frac{9}{11} \\times 540"></span></p>',
        '<p><span class="ql-formula" data-value="\\frac{90}{11\\pi} \\times 3"></span></p>',
        '<p><span class="ql-formula" data-value="\\frac{9\\pi}{11} \\times 180 \\times 3"></span></p>'
    ];
    
    console.log("Fixing Q17... Sending update");
    const res17 = await updateQuestion(q17Id, { 
        wrongAnswer: q17Answers,
        correctAnswer: q17Answers[1] 
    });
    console.log("Q17 update response:", res17);
}

fix();
