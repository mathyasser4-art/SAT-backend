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
    const q7Id = '6a533f0a4d554e04aa1bf59c';
    
    // Exact choices from the screenshot
    const choices = [
        '<p><span class="ql-formula" data-value="(x + 13)(x - 24) = 0"></span></p>',
        '<p><span class="ql-formula" data-value="(x - 13)(x - 24) = 0"></span></p>',
        '<p><span class="ql-formula" data-value="(x - 13)(x + 24) = 0"></span></p>',
        '<p><span class="ql-formula" data-value="(x + 13)(x + 24) = 0"></span></p>'
    ];
    
    console.log("Fixing Q7... Sending update");
    const res7 = await updateQuestion(q7Id, { 
        wrongAnswer: choices,
        correctAnswer: choices[2] // Choice C is the correct one
    });
    console.log("Q7 update response:", res7);
}

fix();
