const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const TARGET_ID = '6aa2c24dec7ba02921a43504'; // Linear inequalities Hard Q2

function request(url, options = {}, body = null) {
    return new Promise((resolve, reject) => {
        const u = new URL(url);
        const reqOptions = {
            hostname: u.hostname,
            path: u.pathname + u.search,
            method: options.method || 'GET',
            headers: options.headers || {}
        };

        const req = https.request(reqOptions, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(data);
                    resolve({ status: res.statusCode, body: parsed });
                } catch (e) {
                    resolve({ status: res.statusCode, raw: data });
                }
            });
        });

        req.on('error', reject);
        if (body) {
            req.write(typeof body === 'string' ? body : JSON.stringify(body));
        }
        req.end();
    });
}

// Clean Quill + KaTeX representation for Choice A: w - 5 > 20
const CLEAN_CHOICE_A = `<p><span class="ql-formula" data-value="w - 5 &gt; 20">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>w</mi><mo>−</mo><mn>5</mn><mo>&gt;</mo><mn>20</mn></mrow><annotation encoding="application/x-tex">w - 5 &gt; 20</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.6667em; vertical-align: -0.0833em;"></span><span class="mord mathnormal" style="margin-right: 0.0269em;">w</span><span class="mspace" style="margin-right: 0.2222em;"></span><span class="mbin">−</span><span class="mspace" style="margin-right: 0.2222em;"></span></span><span class="base"><span class="strut" style="height: 0.6835em; vertical-align: -0.0391em;"></span><span class="mord">5</span><span class="mspace" style="margin-right: 0.2778em;"></span><span class="mrel">&gt;</span><span class="mspace" style="margin-right: 0.2778em;"></span></span><span class="base"><span class="strut" style="height: 0.6444em;"></span><span class="mord">20</span></span></span></span></span>﻿</span></p>`;

async function fixChoiceA() {
    console.log('Fetching live question details...');
    const getRes = await request(`${API_BASE}/question/getQuestionDetails/${TARGET_ID}`);
    if (!getRes.body || getRes.body.message !== 'success') {
        console.error('Failed to get question:', getRes);
        return;
    }

    const q = getRes.body.question;
    console.log('Current Choice A:');
    console.log(q.wrongAnswer[0]);

    const updatedWrongAnswer = [...q.wrongAnswer];
    updatedWrongAnswer[0] = CLEAN_CHOICE_A;

    console.log('\nUpdating Choice A on live production database via API...');
    const updateRes = await request(`${API_BASE}/question/updateQuestion/${TARGET_ID}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' }
    }, {
        wrongAnswer: updatedWrongAnswer
    });

    console.log('Update response:', updateRes.body);

    console.log('\nVerifying update...');
    const verifyRes = await request(`${API_BASE}/question/getQuestionDetails/${TARGET_ID}`);
    const verifiedQ = verifyRes.body.question;
    console.log('New Choice A on live server:');
    console.log(verifiedQ.wrongAnswer[0]);
}

fixChoiceA().catch(console.error);
