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
    const d = JSON.parse(fs.readFileSync('scratch_march_2026_us2_m1.json', 'utf8'));
    
    // --- FIX Q7 ---
    const q7Id = '6a52e25a4d554e04aa1bf40c';
    const q7 = d.chapter.questions.find(x => x._id === q7Id);
    let stem7 = q7.question;
    
    // Replace 86 with -86
    stem7 = stem7.replace(/data-value="4x\^2 - px \+ w = 86"/g, 'data-value="4x^2 - px + w = -86"');
    // For KaTeX, I will replace the span entirely just like I did for Q1
    stem7 = stem7.replace(/<span class="ql-formula" data-value="4x\^2 - px \+ w = 86">.*?﻿<\/span>/g, '<span class="ql-formula" data-value="4x^2 - px + w = -86"></span>');
    
    console.log("Fixing Q7... Sending update");
    const res7 = await updateQuestion(q7Id, { 
        question: stem7,
        correctAnswer: '<p>25</p>'
    });
    console.log("Q7 update response:", res7);
    
    // --- FIX Q9 ---
    const q9Id = '6a52e3b64d554e04aa1bf41e';
    const q9 = d.chapter.questions.find(x => x._id === q9Id);
    let stem9 = q9.question;
    
    stem9 = stem9.replace(/data-value="6x\^4 \+ 17x\^2 \+ 5"/g, 'data-value="6x^4 + 17x^2 + 7"');
    stem9 = stem9.replace(/<span class="ql-formula" data-value="6x\^4 \+ 17x\^2 \+ 5">.*?﻿<\/span>/g, '<span class="ql-formula" data-value="6x^4 + 17x^2 + 7"></span>');
    
    stem9 = stem9.replace(/data-value="\(3x\^2 \+ a\)\(x\^2 \+ b\)"/g, 'data-value="(3x^2 + a)(2x^2 + b)"');
    stem9 = stem9.replace(/<span class="ql-formula" data-value="\(3x\^2 \+ a\)\(x\^2 \+ b\)">.*?﻿<\/span>/g, '<span class="ql-formula" data-value="(3x^2 + a)(2x^2 + b)"></span>');
    
    stem9 = stem9.replace(/data-value="\(3x\^2 \+ c\)\(x\^2 \+ d\)"/g, 'data-value="(3x^2 + c)(2x^2 + d)"');
    stem9 = stem9.replace(/<span class="ql-formula" data-value="\(3x\^2 \+ c\)\(x\^2 \+ d\)">.*?﻿<\/span>/g, '<span class="ql-formula" data-value="(3x^2 + c)(2x^2 + d)"></span>');
    
    console.log("Fixing Q9... Sending update");
    const res9 = await updateQuestion(q9Id, {
        question: stem9
    });
    console.log("Q9 update response:", res9);
}

fix();
