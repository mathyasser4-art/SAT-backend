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
    const d = JSON.parse(fs.readFileSync('scratch_march_2026_int1_m1.json', 'utf8'));
    
    // --- FIX Q13 ---
    const q13Id = '6a5345554d554e04aa1bf5db';
    const q13 = d.chapter.questions.find(x => x._id === q13Id);
    let stem13 = q13.question;
    
    // Replace "3x + 58x - 7" with "3x + 58x^2 - 7"
    stem13 = stem13.replace(/data-value="3x \+ 58x - 7"/g, 'data-value="3x + 58x^2 - 7"');
    // Replace KaTeX wrapper entirely
    stem13 = stem13.replace(/<span class="ql-formula" data-value="3x \+ 58x - 7">.*?﻿<\/span>/g, '<span class="ql-formula" data-value="3x + 58x^2 - 7"></span>');
    
    console.log("Fixing Q13... Sending update");
    const res13 = await updateQuestion(q13Id, { question: stem13 });
    console.log("Q13 update response:", res13);
    
    // --- FIX Q16 ---
    const q16Id = '6a5347894d554e04aa1bf5f9';
    const q16 = d.chapter.questions.find(x => x._id === q16Id);
    let stem16 = q16.question;
    
    // Replace "x - 2x - 8x + 3" with "x^3 - 2x^2 - 8x + 3"
    stem16 = stem16.replace(/data-value="x - 2x - 8x \+ 3"/g, 'data-value="x^3 - 2x^2 - 8x + 3"');
    stem16 = stem16.replace(/<span class="ql-formula" data-value="x - 2x - 8x \+ 3">.*?﻿<\/span>/g, '<span class="ql-formula" data-value="x^3 - 2x^2 - 8x + 3"></span>');
    // There is also f(x) = x - 2x - 8x + 3
    stem16 = stem16.replace(/data-value="f\(x\) = x - 2x - 8x \+ 3"/g, 'data-value="f(x) = x^3 - 2x^2 - 8x + 3"');
    stem16 = stem16.replace(/<span class="ql-formula" data-value="f\(x\) = x - 2x - 8x \+ 3">.*?﻿<\/span>/g, '<span class="ql-formula" data-value="f(x) = x^3 - 2x^2 - 8x + 3"></span>');

    console.log("Fixing Q16... Sending update");
    const res16 = await updateQuestion(q16Id, { question: stem16 });
    console.log("Q16 update response:", res16);
}

fix();
