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
    const d = JSON.parse(fs.readFileSync('scratch_march_2026_us2_m2.json', 'utf8'));
    
    // --- FIX Q6 ---
    const q6Id = '6a53bcea4d554e04aa1bf764';
    const q6 = d.chapter.questions.find(x => x._id === q6Id);
    let stem6 = q6.question;
    
    // Replace "1.75" with "1.4" and "x - 3" with "3 - x"
    stem6 = stem6.replace(/data-value="\\frac\{1\}\{x - 3\} = \\frac\{x - 1\}\{x\} \+ 1\.75"/g, 'data-value="\\frac{1}{3 - x} = \\frac{x - 1}{x} + 1.4"');
    // Replace KaTeX wrapper entirely
    stem6 = stem6.replace(/<span class="ql-formula" data-value="\\frac\{1\}\{x - 3\} = \\frac\{x - 1\}\{x\} \+ 1\.75">.*?﻿<\/span>/g, '<span class="ql-formula" data-value="\\frac{1}{3 - x} = \\frac{x - 1}{x} + 1.4"></span>');
    
    console.log("Fixing Q6... Sending update");
    const res6 = await updateQuestion(q6Id, { question: stem6 });
    console.log("Q6 update response:", res6);
    
    // --- FIX Q17 ---
    const q17Id = '6a53cdfc4d554e04aa1bf832';
    const q17 = d.chapter.questions.find(x => x._id === q17Id);
    let stem17 = q17.question;
    
    // Replace "4x - 7" with "2x - 7"
    stem17 = stem17.replace(/data-value="\\frac\{8cx \+ 7\}\{5\} = 4x - 7"/g, 'data-value="\\frac{8cx + 7}{5} = 2x - 7"');
    // Replace KaTeX wrapper entirely
    stem17 = stem17.replace(/<span class="ql-formula" data-value="\\frac\{8cx \+ 7\}\{5\} = 4x - 7">.*?﻿<\/span>/g, '<span class="ql-formula" data-value="\\frac{8cx + 7}{5} = 2x - 7"></span>');
    
    // Set correctAnswer to the HTML of 5/4, which is wrongAnswer[2]
    const correct17 = q17.wrongAnswer[2];
    
    console.log("Fixing Q17... Sending update");
    const res17 = await updateQuestion(q17Id, {
        question: stem17,
        correctAnswer: correct17
    });
    console.log("Q17 update response:", res17);
}

fix();
