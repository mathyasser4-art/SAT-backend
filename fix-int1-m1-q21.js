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
    const q21Id = '6a534cb24d554e04aa1bf62f';
    
    // I will construct the correct choices by adding the parenthesis
    const choices = [
        '<p><span class="ql-formula" data-value="(x - 2)^2 + (y - 7)^2 = 50"></span></p>',
        '<p><span class="ql-formula" data-value="(x - 2)^2 + (y - 7)^2 = 100"></span></p>',
        '<p><span class="ql-formula" data-value="(x - 2)^2 + (y - 7)^2 = 250"></span></p>',
        '<p><span class="ql-formula" data-value="(x - 2)^2 + (y - 7)^2 = 625"></span></p>'
    ];
    
    console.log("Fixing Q21... Sending update");
    const res21 = await updateQuestion(q21Id, { 
        wrongAnswer: choices,
        correctAnswer: choices[1] // 100 is correct because radius is 5 * 2 = 10, r^2 = 100
    });
    console.log("Q21 update response:", res21);
}

fix();
