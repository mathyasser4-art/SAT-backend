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
    const qId = '6a52d4d14d554e04aa1bf38c'; // Q1 ID
    const q = d.chapter.questions.find(x => x._id === qId);
    let stem = q.question;
    
    // Original stem contains:
    // f(x) = 231.20^x
    // We will replace it with:
    // f(x) = 23(1.20)^{\frac{x}{8}}
    
    // The exact data-value is "f(x) = 231.20^x"
    // The exact annotation is "f(x) = 231.20^x"
    stem = stem.replace(/data-value="f\(x\) = 231\.20\^x"/g, 'data-value="f(x) = 23(1.20)^{\\frac{x}{8}}"');
    stem = stem.replace(/<annotation encoding="application\/x-tex">f\(x\) = 231\.20\^x<\/annotation>/g, '<annotation encoding="application/x-tex">f(x) = 23(1.20)^{\\frac{x}{8}}</annotation>');
    
    // Replace the MathML <math>...</math> and HTML
    // Actually, to make it perfectly rendered, it's easier to just replace the entire span with the new data-value and let the frontend render it from data-value if it's missing KaTeX, OR just build a basic KaTeX block. Since the frontend dynamically handles empty spans perfectly (as proven earlier!), I can just strip the inner content and let the frontend render it.
    
    const newSpan = `<span class="ql-formula" data-value="f(x) = 23(1.20)^{\\frac{x}{8}}"></span>`;
    
    // Regex to match the entire formula span
    stem = stem.replace(/<span class="ql-formula" data-value="f\(x\) = 231\.20\^x">.*?<\/span><\/span><\/span><\/span>﻿<\/span>/, newSpan);
    // Alternatively, a safer regex:
    stem = stem.replace(/<span class="ql-formula" data-value="f\(x\) = 231\.20\^x">.*?﻿<\/span>/, newSpan);
    
    console.log("Fixed stem:", stem.substring(0, 150));
    
    console.log("Sending update...");
    const res = await updateQuestion(qId, { question: stem });
    console.log("Update response:", res);
}
fix();
