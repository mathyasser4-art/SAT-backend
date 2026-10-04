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
    console.log('1. Fixing M1 Q5 (replacing corrupted Choice D with 3)...');
    const choiceD3 = '<p><span class="ql-formula" data-value="3">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mn>3</mn></mrow><annotation encoding="application/x-tex">3</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.6444em;"></span><span class="mord">3</span></span></span></span></span>﻿</span> </p>';
    
    const q5Res = await getQuestionDetails('6a54bc9f4d554e04aa1bfe65');
    const q5 = q5Res.question;
    q5.wrongAnswer[3] = choiceD3;
    const updateQ5 = await updateQuestion('6a54bc9f4d554e04aa1bfe65', { wrongAnswer: q5.wrongAnswer });
    console.log('M1 Q5 Updated:', updateQ5);

    console.log('2. Fixing M2 Q15 (adding missing second equation to stem)...');
    const q15Res = await getQuestionDetails('6a741074fb6980734c71c238');
    const q15 = q15Res.question;
    
    const secondEq = '<p><span class="ql-formula" data-value="y = mx + \\frac{b}{3}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>y</mi><mo>=</mo><mi>m</mi><mi>x</mi><mo>+</mo><mfrac><mi>b</mi><mn>3</mn></mfrac></mrow><annotation encoding="application/x-tex">y = mx + \\frac{b}{3}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.625em; vertical-align: -0.1944em;"></span><span class="mord mathnormal" style="margin-right: 0.0359em;">y</span><span class="mspace" style="margin-right: 0.2778em;"></span><span class="mrel">=</span><span class="mspace" style="margin-right: 0.2778em;"></span></span><span class="base"><span class="strut" style="height: 0.6667em; vertical-align: -0.0833em;"></span><span class="mord mathnormal">m</span><span class="mord mathnormal">x</span><span class="mspace" style="margin-right: 0.2222em;"></span><span class="mbin">+</span><span class="mspace" style="margin-right: 0.2222em;"></span></span><span class="base"><span class="strut" style="height: 1.1901em; vertical-align: -0.345em;"></span><span class="mord"><span class="mopen nulldelimiter"></span><span class="mfrac"><span class="vlist-t vlist-t2"><span class="vlist-r"><span class="vlist" style="height: 0.8451em;"><span class="" style="top: -2.655em;"><span class="pstrut" style="height: 3em;"></span><span class="sizing reset-size6 size3 mtight"><span class="mord mtight"><span class="mord mtight">3</span></span></span></span><span class="" style="top: -3.23em;"><span class="pstrut" style="height: 3em;"></span><span class="frac-line" style="border-bottom-width: 0.04em;"></span></span><span class="" style="top: -3.394em;"><span class="pstrut" style="height: 3em;"></span><span class="sizing reset-size6 size3 mtight"><span class="mord mtight"><span class="mord mathnormal mtight">b</span></span></span></span></span><span class="vlist-s">​</span></span><span class="vlist-r"><span class="vlist" style="height: 0.345em;"><span class=""></span></span></span></span></span><span class="mclose nulldelimiter"></span></span></span></span></span></span>﻿</span></p>';

    const newStem = q15.question.replace('</p><p>In the given', '</p>' + secondEq + '<p>In the given');
    const updateQ15 = await updateQuestion('6a741074fb6980734c71c238', { question: newStem });
    console.log('M2 Q15 Updated:', updateQ15);
}

fix();
