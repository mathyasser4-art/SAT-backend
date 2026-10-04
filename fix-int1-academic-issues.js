const https = require('https');

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

function getQuestionDetails(questionId) {
    return new Promise((resolve, reject) => {
        https.get(`${API_BASE}/question/getQuestionDetails/${questionId}`, res => {
            let b = '';
            res.on('data', c => b += c);
            res.on('end', () => resolve(JSON.parse(b)));
        }).on('error', reject);
    });
}

async function fix() {
    console.log('1. Fixing M1 Q8: adding missing equation (x + 4)(x - 6) = 0 to stem...');
    const q8Stem = '<p><span class="ql-formula" data-value="(x + 4)(x - 6) = 0">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mo stretchy="false">(</mo><mi>x</mi><mo>+</mo><mn>4</mn><mo stretchy="false">)</mo><mo stretchy="false">(</mo><mi>x</mi><mo>−</mo><mn>6</mn><mo stretchy="false">)</mo><mo>=</mo><mn>0</mn></mrow><annotation encoding="application/x-tex">(x + 4)(x - 6) = 0</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 1em; vertical-align: -0.25em;"></span><span class="mopen">(</span><span class="mord mathnormal">x</span><span class="mspace" style="margin-right: 0.2222em;"></span><span class="mbin">+</span><span class="mspace" style="margin-right: 0.2222em;"></span></span><span class="base"><span class="strut" style="height: 1em; vertical-align: -0.25em;"></span><span class="mord">4</span><span class="mclose">)</span><span class="mopen">(</span><span class="mord mathnormal">x</span><span class="mspace" style="margin-right: 0.2222em;"></span><span class="mbin">−</span><span class="mspace" style="margin-right: 0.2222em;"></span></span><span class="base"><span class="strut" style="height: 1em; vertical-align: -0.25em;"></span><span class="mord">6</span><span class="mclose">)</span><span class="mspace" style="margin-right: 0.2778em;"></span><span class="mrel">=</span><span class="mspace" style="margin-right: 0.2778em;"></span></span><span class="base"><span class="strut" style="height: 0.6444em;"></span><span class="mord">0</span></span></span></span></span>﻿</span></p><p>What are all possible solutions to the given equation?</p>';
    const resQ8 = await updateQuestion('6a5b2865c3d08d90637d2fcf', { question: q8Stem });
    console.log('M1 Q8 Updated:', resQ8);

    console.log('2. Fixing M1 Q11: cleaning up "Men\'s Hight" typo and RTL direction...');
    const q11Details = await getQuestionDetails('6a5b29edc3d08d90637d2fdd');
    let q11Stem = q11Details.question.question;
    q11Stem = q11Stem.replace('style="direction: rtl;"', '').replace("Men's Hight", "Men's Height");
    const resQ11 = await updateQuestion('6a5b29edc3d08d90637d2fdd', { question: q11Stem });
    console.log('M1 Q11 Updated:', resQ11);
}

fix();
