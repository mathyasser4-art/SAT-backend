const https = require('https');

const TARGET_ID = '6aa2c24dec7ba02921a43504';

async function testSubmit() {
    return new Promise((resolve, reject) => {
        const req = https.request(`https://sat-backend-production.up.railway.app/question/checkTheAnswer/${TARGET_ID}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve(JSON.parse(data)));
        });
        req.on('error', reject);
        req.write(JSON.stringify({
            questionAnswer: `<p><span class="ql-formula" data-value="w + 5 &gt; 20">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>w</mi><mo>+</mo><mn>5</mn><mo>&gt;</mo><mn>20</mn></mrow><annotation encoding="application/x-tex">w + 5 &gt; 20</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.6667em; vertical-align: -0.0833em;"></span><span class="mord mathnormal" style="margin-right: 0.0269em;">w</span><span class="mspace" style="margin-right: 0.2222em;"></span><span class="mbin">+</span><span class="mspace" style="margin-right: 0.2222em;"></span></span><span class="base"><span class="strut" style="height: 0.6835em; vertical-align: -0.0391em;"></span><span class="mord">5</span><span class="mspace" style="margin-right: 0.2778em;"></span><span class="mrel">&gt;</span><span class="mspace" style="margin-right: 0.2778em;"></span></span><span class="base"><span class="strut" style="height: 0.6444em;"></span><span class="mord">20</span></span></span></span></span>﻿</span></p>`
        }));
        req.end();
    });
}

testSubmit().then(res => console.log('Grade result:', res.message)).catch(console.error);
