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
    
    // --- FIX Q18 ---
    const q18Id = '6a53ce624d554e04aa1bf83e';
    const q18 = d.chapter.questions.find(x => x._id === q18Id);
    let stem18 = q18.question;
    
    // Replace "3x - 7" with "3x - 4"
    stem18 = stem18.replace(/data-value="f\(x\) = 3x - 7"/g, 'data-value="f(x) = 3x - 4"');
    // Also clear the KaTeX inner HTML to let frontend render it cleanly
    stem18 = stem18.replace(/<span class="ql-formula" data-value="f\(x\) = 3x - 7">.*?﻿<\/span>/g, '<span class="ql-formula" data-value="f(x) = 3x - 4"></span>');
    
    console.log("Fixing Q18... Sending update");
    const res18 = await updateQuestion(q18Id, { question: stem18 });
    console.log("Q18 update response:", res18);
    
    // --- FIX Q21 ---
    const q21Id = '6a53d0854d554e04aa1bf853';
    
    // We are COMPLETELY replacing Q21's text because it's missing entirely!
    const stem21 = '<p>In the given equation, <span class="ql-formula" data-value="p"></span> and <span class="ql-formula" data-value="w"></span> are integer constants. The equation has exactly one real solution. Which is NOT a possible value of <span class="ql-formula" data-value="w"></span>?</p><p><span class="ql-formula" data-value="4x^2 - px + w = -85"></span></p>';
    
    console.log("Fixing Q21... Sending update");
    const res21 = await updateQuestion(q21Id, { question: stem21 });
    console.log("Q21 update response:", res21);
}

fix();
