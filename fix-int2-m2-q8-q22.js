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
    // --- FIX Q8 ---
    const q8Id = '6a53f2fc4d554e04aa1bfa47';
    
    const q8Stem = '<p>What value of <span class="ql-formula" data-value="x"></span> is the solution to the given equation?</p><p><span class="ql-formula" data-value="97 - x + 5 = 95"></span></p>';
    
    console.log("Fixing Q8... Sending update");
    const res8 = await updateQuestion(q8Id, { 
        question: q8Stem
    });
    console.log("Q8 update response:", res8);
    
    // --- FIX Q22 ---
    const q22Id = '6a53fb134d554e04aa1bfb2c';
    
    const q22Stem = '<p>In the given equation, <span class="ql-formula" data-value="p"></span> and <span class="ql-formula" data-value="w"></span> are integer constants. The equation has exactly one real solution. Which is NOT a possible value of <span class="ql-formula" data-value="w"></span>?</p><p><span class="ql-formula" data-value="4x^2 - px + w = -85"></span></p>';
    
    console.log("Fixing Q22... Sending update");
    const res22 = await updateQuestion(q22Id, { 
        question: q22Stem
    });
    console.log("Q22 update response:", res22);
}

fix();
