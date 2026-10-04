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
    const d = JSON.parse(fs.readFileSync('scratch_may_2026_int1_m1.json', 'utf8'));
    const qId = '6a50c6414d554e04aa1bebb9';
    const q = d.chapter.questions.find(x => x._id === qId);
    let stem = q.question;
    
    // "the graph of the equation<span class=\"ql-formula\" data-value=\"xy\">...</span> <span class=\"ql-formula\" data-value=\"(x - 6)^2"
    // Replace it:
    stem = stem.replace(/the graph of the equation<span class="ql-formula" data-value="xy">.*?<\/span>﻿<\/span> <span/, 'the graph of the equation <span');
    stem = stem.replace(/the graph of the equation<span class="ql-formula" data-value="xy">.*?<\/span> <span/, 'the graph of the equation <span');
    
    console.log("Sending update...");
    const res = await updateQuestion(qId, { question: stem });
    console.log("Update response:", res);
}
fix();
