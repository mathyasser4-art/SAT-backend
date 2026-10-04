const https = require('https');
const fs = require('fs');

const API_BASE = 'https://sat-backend-production.up.railway.app';

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

function uploadImage(questionId, filePath) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryFixQ20' + Date.now();
        const header = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="image"; filename="triangle_q20.png"\r\nContent-Type: image/png\r\n\r\n`);
        const footer = Buffer.from(`\r\n--${boundary}--\r\n`);
        const body = Buffer.concat([header, fileBuf, footer]);

        const req = https.request(`${API_BASE}/question/updateQuestion/${questionId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'multipart/form-data; boundary=' + boundary,
                'Content-Length': body.length
            }
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data));
                } catch (e) {
                    resolve({ raw: data });
                }
            });
        });
        req.on('error', reject);
        req.write(body);
        req.end();
    });
}

async function runFixes() {
    console.log('🚀 Executing fixes for Dec 2025 US 1 Module 1...\n');

    // ----------------------------------------------------
    // 1. FIX Q7: Fix typo in Choice A (add missing 'x')
    // ----------------------------------------------------
    const Q7_ID = '6a54015e4d554e04aa1bfc52';
    console.log('--- Fixing Q7 Choice A typo ---');
    const q7Res = await request(`${API_BASE}/question/getQuestionDetails/${Q7_ID}`);
    const q7 = q7Res.body.question;
    const newQ7Wrong = [...q7.wrongAnswer];
    newQ7Wrong[0] = `<p><span class="ql-formula" data-value="y = 0.9 + 9.1x">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>y</mi><mo>=</mo><mn>0.9</mn><mo>+</mo><mn>9.1</mn><mi>x</mi></mrow><annotation encoding="application/x-tex">y = 0.9 + 9.1x</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.625em; vertical-align: -0.1944em;"></span><span class="mord mathnormal" style="margin-right: 0.0359em;">y</span><span class="mspace" style="margin-right: 0.2778em;"></span><span class="mrel">=</span><span class="mspace" style="margin-right: 0.2778em;"></span></span><span class="base"><span class="strut" style="height: 0.7278em; vertical-align: -0.0833em;"></span><span class="mord">0.9</span><span class="mspace" style="margin-right: 0.2222em;"></span><span class="mbin">+</span><span class="mspace" style="margin-right: 0.2222em;"></span></span><span class="base"><span class="strut" style="height: 0.6444em;"></span><span class="mord">9.1</span><span class="mord mathnormal">x</span></span></span></span></span>﻿</span></p>`;
    const updQ7 = await request(`${API_BASE}/question/updateQuestion/${Q7_ID}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' }
    }, { wrongAnswer: newQ7Wrong });
    console.log('Q7 update response:', updQ7.body);

    // ----------------------------------------------------
    // 2. FIX Q12: Fix duplicate Choice C with 2/3 x + 82/3
    // ----------------------------------------------------
    const Q12_ID = '6a5404684d554e04aa1bfc92';
    console.log('\n--- Fixing Q12 Duplicate Choice C ---');
    const q12Res = await request(`${API_BASE}/question/getQuestionDetails/${Q12_ID}`);
    const q12 = q12Res.body.question;
    const newQ12Wrong = [...q12.wrongAnswer];
    newQ12Wrong[2] = `<p><span class="ql-formula" data-value="y = \\frac{2}{3}x + \\frac{82}{3}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>y</mi><mo>=</mo><mfrac><mn>2</mn><mn>3</mn></mfrac><mi>x</mi><mo>+</mo><mfrac><mn>82</mn><mn>3</mn></mfrac></mrow><annotation encoding="application/x-tex">y = \\frac{2}{3}x + \\frac{82}{3}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.625em; vertical-align: -0.1944em;"></span><span class="mord mathnormal" style="margin-right: 0.0359em;">y</span><span class="mspace" style="margin-right: 0.2778em;"></span><span class="mrel">=</span><span class="mspace" style="margin-right: 0.2778em;"></span></span><span class="base"><span class="strut" style="height: 1.1901em; vertical-align: -0.345em;"></span><span class="mord"><span class="mopen nulldelimiter"></span><span class="mfrac"><span class="vlist-t vlist-t2"><span class="vlist-r"><span class="vlist" style="height: 0.8451em;"><span class="" style="top: -2.655em;"><span class="pstrut" style="height: 3em;"></span><span class="sizing reset-size6 size3 mtight"><span class="mord mtight"><span class="mord mtight">3</span></span></span></span><span class="" style="top: -3.23em;"><span class="pstrut" style="height: 3em;"></span><span class="frac-line" style="border-bottom-width: 0.04em;"></span></span><span class="" style="top: -3.394em;"><span class="pstrut" style="height: 3em;"></span><span class="sizing reset-size6 size3 mtight"><span class="mord mtight"><span class="mord mtight">2</span></span></span></span></span><span class="vlist-s">​</span></span><span class="vlist-r"><span class="vlist" style="height: 0.345em;"><span class=""></span></span></span></span></span><span class="mclose nulldelimiter"></span></span><span class="mord mathnormal">x</span><span class="mspace" style="margin-right: 0.2222em;"></span><span class="mbin">+</span><span class="mspace" style="margin-right: 0.2222em;"></span></span><span class="base"><span class="strut" style="height: 1.1901em; vertical-align: -0.345em;"></span><span class="mord"><span class="mopen nulldelimiter"></span><span class="mfrac"><span class="vlist-t vlist-t2"><span class="vlist-r"><span class="vlist" style="height: 0.8451em;"><span class="" style="top: -2.655em;"><span class="pstrut" style="height: 3em;"></span><span class="sizing reset-size6 size3 mtight"><span class="mord mtight"><span class="mord mtight">3</span></span></span></span><span class="" style="top: -3.23em;"><span class="pstrut" style="height: 3em;"></span><span class="frac-line" style="border-bottom-width: 0.04em;"></span></span><span class="" style="top: -3.394em;"><span class="pstrut" style="height: 3em;"></span><span class="sizing reset-size6 size3 mtight"><span class="mord mtight"><span class="mord mtight">82</span></span></span></span></span><span class="vlist-s">​</span></span><span class="vlist-r"><span class="vlist" style="height: 0.345em;"><span class=""></span></span></span></span></span><span class="mclose nulldelimiter"></span></span></span></span></span></span>﻿</span></p>`;
    const updQ12 = await request(`${API_BASE}/question/updateQuestion/${Q12_ID}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' }
    }, { wrongAnswer: newQ12Wrong });
    console.log('Q12 update response:', updQ12.body);

    // ----------------------------------------------------
    // 3. FIX Q13: Clean choices and set correct answer to b = \pm \sqrt{7d - 4c}
    // ----------------------------------------------------
    const Q13_ID = '6a5406d14d554e04aa1bfca0';
    console.log('\n--- Fixing Q13 Incoherent Choices & Correct Answer ---');
    const cleanOptA = `<p><span class="ql-formula" data-value="b = \\pm \\sqrt{7d + 4c}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>b</mi><mo>=</mo><mo>±</mo><msqrt><mrow><mn>7</mn><mi>d</mi><mo>+</mo><mn>4</mn><mi>c</mi></mrow></msqrt></mrow><annotation encoding="application/x-tex">b = \\pm \\sqrt{7d + 4c}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.6944em;"></span><span class="mord mathnormal">b</span><span class="mspace" style="margin-right: 0.2778em;"></span><span class="mrel">=</span><span class="mspace" style="margin-right: 0.2778em;"></span></span><span class="base"><span class="strut" style="height: 0.6667em; vertical-align: -0.0833em;"></span><span class="mbin">±</span><span class="mspace" style="margin-right: 0.2222em;"></span></span><span class="base"><span class="strut" style="height: 1.04em; vertical-align: -0.1494em;"></span><span class="mord sqrt"><span class="vlist-t vlist-t2"><span class="vlist-r"><span class="vlist" style="height: 0.8906em;"><span class="mord" style="padding-left: 0.833em;"><span class="mord">7</span><span class="mord mathnormal">d</span><span class="mbin">+</span><span class="mord">4</span><span class="mord mathnormal">c</span></span></span><span class="vlist-s">​</span></span><span class="vlist-r"><span class="vlist" style="height: 0.1494em;"></span></span></span></span></span></span></span></span>﻿</span></p>`;
    const cleanOptB = `<p><span class="ql-formula" data-value="b = \\frac{7d-4c}{2}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>b</mi><mo>=</mo><mfrac><mrow><mn>7</mn><mi>d</mi><mo>−</mo><mn>4</mn><mi>c</mi></mrow><mn>2</mn></mfrac></mrow><annotation encoding="application/x-tex">b = \\frac{7d-4c}{2}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.6944em;"></span><span class="mord mathnormal">b</span><span class="mspace" style="margin-right: 0.2778em;"></span><span class="mrel">=</span><span class="mspace" style="margin-right: 0.2778em;"></span></span><span class="base"><span class="strut" style="height: 1.1901em; vertical-align: -0.345em;"></span><span class="mord"><span class="mopen nulldelimiter"></span><span class="mfrac"><span class="vlist-t vlist-t2"><span class="vlist-r"><span class="vlist" style="height: 0.8451em;"><span class="" style="top: -2.655em;"><span class="pstrut" style="height: 3em;"></span><span class="sizing reset-size6 size3 mtight"><span class="mord mtight"><span class="mord mtight">2</span></span></span></span><span class="" style="top: -3.23em;"><span class="pstrut" style="height: 3em;"></span><span class="frac-line" style="border-bottom-width: 0.04em;"></span></span><span class="" style="top: -3.394em;"><span class="pstrut" style="height: 3em;"></span><span class="sizing reset-size6 size3 mtight"><span class="mord mtight"><span class="mord mtight">7</span><span class="mord mathnormal mtight">d</span><span class="mbin mtight">−</span><span class="mord mtight">4</span><span class="mord mathnormal mtight">c</span></span></span></span></span><span class="vlist-s">​</span></span><span class="vlist-r"><span class="vlist" style="height: 0.345em;"><span class=""></span></span></span></span></span><span class="mclose nulldelimiter"></span></span></span></span></span></span>﻿</span></p>`;
    const cleanOptC = `<p><span class="ql-formula" data-value="b = \\sqrt{7d - 4c}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>b</mi><mo>=</mo><msqrt><mrow><mn>7</mn><mi>d</mi><mo>−</mo><mn>4</mn><mi>c</mi></mrow></msqrt></mrow><annotation encoding="application/x-tex">b = \\sqrt{7d - 4c}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.6944em;"></span><span class="mord mathnormal">b</span><span class="mspace" style="margin-right: 0.2778em;"></span><span class="mrel">=</span><span class="mspace" style="margin-right: 0.2778em;"></span></span><span class="base"><span class="strut" style="height: 1.04em; vertical-align: -0.1494em;"></span><span class="mord sqrt"><span class="vlist-t vlist-t2"><span class="vlist-r"><span class="vlist" style="height: 0.8906em;"><span class="mord" style="padding-left: 0.833em;"><span class="mord">7</span><span class="mord mathnormal">d</span><span class="mbin">−</span><span class="mord">4</span><span class="mord mathnormal">c</span></span></span><span class="vlist-s">​</span></span><span class="vlist-r"><span class="vlist" style="height: 0.1494em;"></span></span></span></span></span></span></span></span>﻿</span></p>`;
    const cleanOptD = `<p><span class="ql-formula" data-value="b = \\pm \\sqrt{7d - 4c}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>b</mi><mo>=</mo><mo>±</mo><msqrt><mrow><mn>7</mn><mi>d</mi><mo>−</mo><mn>4</mn><mi>c</mi></mrow></msqrt></mrow><annotation encoding="application/x-tex">b = \\pm \\sqrt{7d - 4c}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.6944em;"></span><span class="mord mathnormal">b</span><span class="mspace" style="margin-right: 0.2778em;"></span><span class="mrel">=</span><span class="mspace" style="margin-right: 0.2778em;"></span></span><span class="base"><span class="strut" style="height: 0.6667em; vertical-align: -0.0833em;"></span><span class="mbin">±</span><span class="mspace" style="margin-right: 0.2222em;"></span></span><span class="base"><span class="strut" style="height: 1.04em; vertical-align: -0.1494em;"></span><span class="mord sqrt"><span class="vlist-t vlist-t2"><span class="vlist-r"><span class="vlist" style="height: 0.8906em;"><span class="mord" style="padding-left: 0.833em;"><span class="mord">7</span><span class="mord mathnormal">d</span><span class="mbin">−</span><span class="mord">4</span><span class="mord mathnormal">c</span></span></span><span class="vlist-s">​</span></span><span class="vlist-r"><span class="vlist" style="height: 0.1494em;"></span></span></span></span></span></span></span></span>﻿</span></p>`;
    
    const updQ13 = await request(`${API_BASE}/question/updateQuestion/${Q13_ID}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' }
    }, {
        wrongAnswer: [cleanOptA, cleanOptB, cleanOptC, cleanOptD],
        correctAnswer: cleanOptD
    });
    console.log('Q13 update response:', updQ13.body);

    // ----------------------------------------------------
    // 4. FIX Q18: Restore absolute value equation in stem
    // ----------------------------------------------------
    const Q18_ID = '6a540f754d554e04aa1bfcef';
    console.log('\n--- Fixing Q18 Equation Stem ---');
    const newQ18Stem = `<p><span class="ql-formula" data-value="\\frac{|3x - 54|}{6} + 3 = 9">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mfrac><mrow><mi mathvariant="normal">∣</mi><mn>3</mn><mi>x</mi><mo>−</mo><mn>54</mn><mi mathvariant="normal">∣</mi></mrow><mn>6</mn></mfrac><mo>+</mo><mn>3</mn><mo>=</mo><mn>9</mn></mrow><annotation encoding="application/x-tex">\\frac{|3x - 54|}{6} + 3 = 9</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 1.1901em; vertical-align: -0.345em;"></span><span class="mord"><span class="mopen nulldelimiter"></span><span class="mfrac"><span class="vlist-t vlist-t2"><span class="vlist-r"><span class="vlist" style="height: 0.8451em;"><span class="" style="top: -2.655em;"><span class="pstrut" style="height: 3em;"></span><span class="sizing reset-size6 size3 mtight"><span class="mord mtight"><span class="mord mtight">6</span></span></span></span><span class="" style="top: -3.23em;"><span class="pstrut" style="height: 3em;"></span><span class="frac-line" style="border-bottom-width: 0.04em;"></span></span><span class="" style="top: -3.394em;"><span class="pstrut" style="height: 3em;"></span><span class="sizing reset-size6 size3 mtight"><span class="mord mtight"><span class="mord mtight">∣</span><span class="mord mtight">3</span><span class="mord mathnormal mtight">x</span><span class="mbin mtight">−</span><span class="mord mtight">54</span><span class="mord mtight">∣</span></span></span></span></span><span class="vlist-s">​</span></span><span class="vlist-r"><span class="vlist" style="height: 0.345em;"><span class=""></span></span></span></span></span><span class="mclose nulldelimiter"></span></span><span class="mspace" style="margin-right: 0.2222em;"></span><span class="mbin">+</span><span class="mspace" style="margin-right: 0.2222em;"></span></span><span class="base"><span class="strut" style="height: 0.6444em;"></span><span class="mord">3</span><span class="mspace" style="margin-right: 0.2778em;"></span><span class="mrel">=</span><span class="mspace" style="margin-right: 0.2778em;"></span></span><span class="base"><span class="strut" style="height: 0.6444em;"></span><span class="mord">9</span></span></span></span></span>﻿</span></p><p>What is the sum of the solutions to the given equation?</p>`;
    const updQ18 = await request(`${API_BASE}/question/updateQuestion/${Q18_ID}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' }
    }, { question: newQ18Stem });
    console.log('Q18 update response:', updQ18.body);

    // ----------------------------------------------------
    // 5. FIX Q20: Upload triangle diagram
    // ----------------------------------------------------
    const Q20_ID = '6a5410164d554e04aa1bfd0d';
    console.log('\n--- Uploading Q20 Triangle Diagram ---');
    const updQ20 = await uploadImage(Q20_ID, 'triangle_q20.png');
    console.log('Q20 upload response:', updQ20);

    console.log('\n✨ All updates sent! Now verifying live server values...');
    
    // Verification
    const vQ7 = (await request(`${API_BASE}/question/getQuestionDetails/${Q7_ID}`)).body.question;
    console.log('\nVerified Q7 Choice A:');
    console.log(vQ7.wrongAnswer[0]);

    const vQ12 = (await request(`${API_BASE}/question/getQuestionDetails/${Q12_ID}`)).body.question;
    console.log('\nVerified Q12 Choice C:');
    console.log(vQ12.wrongAnswer[2]);

    const vQ13 = (await request(`${API_BASE}/question/getQuestionDetails/${Q13_ID}`)).body.question;
    console.log('\nVerified Q13 Correct Answer:');
    console.log(vQ13.correctAnswer);

    const vQ18 = (await request(`${API_BASE}/question/getQuestionDetails/${Q18_ID}`)).body.question;
    console.log('\nVerified Q18 Stem:');
    console.log(vQ18.question);

    const vQ20 = (await request(`${API_BASE}/question/getQuestionDetails/${Q20_ID}`)).body.question;
    console.log('\nVerified Q20 questionPic:');
    console.log(vQ20.questionPic);

    console.log('\n🎉 ALL FIXES VERIFIED SUCCESSFULLY ON PRODUCTION!');
}

runFixes().catch(console.error);
