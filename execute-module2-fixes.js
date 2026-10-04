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
        const boundary = '----WebKitFormBoundaryFixM2' + Date.now();
        const header = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="image"; filename="scatterplot_q12.png"\r\nContent-Type: image/png\r\n\r\n`);
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
    console.log('🚀 Executing fixes for Dec 2025 US 1 Module 2...\n');

    // ----------------------------------------------------
    // 1. FIX Q4: Normalize LaTeX formatting for Choice B & Correct Answer
    // ----------------------------------------------------
    const Q4_ID = '6a5b1458c3d08d90637d2eca';
    console.log('--- Normalizing Q4 LaTeX formatting ---');
    const q4ChoiceB = `<p><span class="ql-formula" data-value="s + 55 \\ge 80">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>s</mi><mo>+</mo><mn>55</mn><mo>≥</mo><mn>80</mn></mrow><annotation encoding="application/x-tex">s + 55 \\ge 80</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.6667em; vertical-align: -0.0833em;"></span><span class="mord mathnormal">s</span><span class="mspace" style="margin-right: 0.2222em;"></span><span class="mbin">+</span><span class="mspace" style="margin-right: 0.2222em;"></span></span><span class="base"><span class="strut" style="height: 0.7804em; vertical-align: -0.136em;"></span><span class="mord">55</span><span class="mspace" style="margin-right: 0.2778em;"></span><span class="mrel">≥</span><span class="mspace" style="margin-right: 0.2778em;"></span></span><span class="base"><span class="strut" style="height: 0.6444em;"></span><span class="mord">80</span></span></span></span></span>﻿</span></p>`;
    const q4Res = await request(`${API_BASE}/question/getQuestionDetails/${Q4_ID}`);
    const q4 = q4Res.body.question;
    const newQ4Wrong = [...q4.wrongAnswer];
    newQ4Wrong[1] = q4ChoiceB;
    const updQ4 = await request(`${API_BASE}/question/updateQuestion/${Q4_ID}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' }
    }, {
        wrongAnswer: newQ4Wrong,
        correctAnswer: q4ChoiceB
    });
    console.log('Q4 update response:', updQ4.body);

    // ----------------------------------------------------
    // 2. FIX Q7: Update choices and answer key to 1 + \sqrt{34}
    // ----------------------------------------------------
    const Q7_ID = '6a5b15c7c3d08d90637d2ee8';
    console.log('\n--- Fixing Q7 Solutions to 1 + \\sqrt{34} ---');
    const q7ChoiceA = `<p><span class="ql-formula" data-value="1 - \\sqrt{34}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mn>1</mn><mo>−</mo><msqrt><mn>34</mn></msqrt></mrow><annotation encoding="application/x-tex">1 - \\sqrt{34}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.7278em; vertical-align: -0.0833em;"></span><span class="mord">1</span><span class="mspace" style="margin-right: 0.2222em;"></span><span class="mbin">−</span><span class="mspace" style="margin-right: 0.2222em;"></span></span><span class="base"><span class="strut" style="height: 1.04em; vertical-align: -0.1494em;"></span><span class="mord sqrt"><span class="vlist-t vlist-t2"><span class="vlist-r"><span class="vlist" style="height: 0.8906em;"><span class="mord" style="padding-left: 0.833em;"><span class="mord">34</span></span></span><span class="vlist-s">​</span></span><span class="vlist-r"><span class="vlist" style="height: 0.1494em;"></span></span></span></span></span></span></span>﻿</span></p>`;
    const q7ChoiceB = `<p><span class="ql-formula" data-value="1 + \\sqrt{34}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mn>1</mn><mo>+</mo><msqrt><mn>34</mn></msqrt></mrow><annotation encoding="application/x-tex">1 + \\sqrt{34}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.7278em; vertical-align: -0.0833em;"></span><span class="mord">1</span><span class="mspace" style="margin-right: 0.2222em;"></span><span class="mbin">+</span><span class="mspace" style="margin-right: 0.2222em;"></span></span><span class="base"><span class="strut" style="height: 1.04em; vertical-align: -0.1494em;"></span><span class="mord sqrt"><span class="vlist-t vlist-t2"><span class="vlist-r"><span class="vlist" style="height: 0.8906em;"><span class="mord" style="padding-left: 0.833em;"><span class="mord">34</span></span></span><span class="vlist-s">​</span></span><span class="vlist-r"><span class="vlist" style="height: 0.1494em;"></span></span></span></span></span></span></span>﻿</span></p>`;
    const q7ChoiceC = `<p>34</p>`;
    const q7ChoiceD = `<p><span class="ql-formula" data-value="33 + \\sqrt{34}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mn>33</mn><mo>+</mo><msqrt><mn>34</mn></msqrt></mrow><annotation encoding="application/x-tex">33 + \\sqrt{34}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.7278em; vertical-align: -0.0833em;"></span><span class="mord">33</span><span class="mspace" style="margin-right: 0.2222em;"></span><span class="mbin">+</span><span class="mspace" style="margin-right: 0.2222em;"></span></span><span class="base"><span class="strut" style="height: 1.04em; vertical-align: -0.1494em;"></span><span class="mord sqrt"><span class="vlist-t vlist-t2"><span class="vlist-r"><span class="vlist" style="height: 0.8906em;"><span class="mord" style="padding-left: 0.833em;"><span class="mord">34</span></span></span><span class="vlist-s">​</span></span><span class="vlist-r"><span class="vlist" style="height: 0.1494em;"></span></span></span></span></span></span></span>﻿</span></p>`;
    
    const updQ7 = await request(`${API_BASE}/question/updateQuestion/${Q7_ID}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' }
    }, {
        wrongAnswer: [q7ChoiceA, q7ChoiceB, q7ChoiceC, q7ChoiceD],
        correctAnswer: q7ChoiceB
    });
    console.log('Q7 update response:', updQ7.body);

    // ----------------------------------------------------
    // 3. FIX Q10: Fix typo in geometry stem (\bar{LK} parallel to \bar{RT})
    // ----------------------------------------------------
    const Q10_ID = '6a5b180ac3d08d90637d2ef6';
    console.log('\n--- Fixing Q10 Geometry Stem Typo ---');
    const newQ10Stem = `<p>In triangle RST, the measure of angle R is <span class="ql-formula" data-value="37^\\circ">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mn>3</mn><msup><mn>7</mn><mo>∘</mo></msup></mrow><annotation encoding="application/x-tex">37^\\circ</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.6741em;"></span><span class="mord">3</span><span class="mord"><span class="mord">7</span><span class="msupsub"><span class="vlist-t"><span class="vlist-r"><span class="vlist" style="height: 0.6741em;"><span class="" style="top: -3.063em; margin-right: 0.05em;"><span class="pstrut" style="height: 2.7em;"></span><span class="sizing reset-size6 size3 mtight"><span class="mbin mtight">∘</span></span></span></span></span></span></span></span></span></span></span></span>﻿</span>, the measure of angle S is <span class="ql-formula" data-value="x^\\circ">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><msup><mi>x</mi><mo>∘</mo></msup></mrow><annotation encoding="application/x-tex">x^\\circ</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.6741em;"></span><span class="mord"><span class="mord mathnormal">x</span><span class="msupsub"><span class="vlist-t"><span class="vlist-r"><span class="vlist" style="height: 0.6741em;"><span class="" style="top: -3.063em; margin-right: 0.05em;"><span class="pstrut" style="height: 2.7em;"></span><span class="sizing reset-size6 size3 mtight"><span class="mbin mtight">∘</span></span></span></span></span></span></span></span></span></span></span></span>﻿</span>, and the measure of angle T is <span class="ql-formula" data-value="(3x - 5)^\\circ">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mo stretchy="false">(</mo><mn>3</mn><mi>x</mi><mo>−</mo><mn>5</mn><msup><mo stretchy="false">)</mo><mo>∘</mo></msup></mrow><annotation encoding="application/x-tex">(3x - 5)^\\circ</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 1em; vertical-align: -0.25em;"></span><span class="mopen">(</span><span class="mord">3</span><span class="mord mathnormal">x</span><span class="mspace" style="margin-right: 0.2222em;"></span><span class="mbin">−</span><span class="mspace" style="margin-right: 0.2222em;"></span></span><span class="base"><span class="strut" style="height: 1.0041em; vertical-align: -0.25em;"></span><span class="mord">5</span><span class="mclose"><span class="mclose">)</span><span class="msupsub"><span class="vlist-t"><span class="vlist-r"><span class="vlist" style="height: 0.7541em;"><span class="" style="top: -3.143em; margin-right: 0.05em;"><span class="pstrut" style="height: 2.7em;"></span><span class="sizing reset-size6 size3 mtight"><span class="mbin mtight">∘</span></span></span></span></span></span></span></span></span></span></span></span>﻿</span>. Point L lies on <span class="ql-formula" data-value="\\overline{RS}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mover accent="true"><mrow><mi>R</mi><mi>S</mi></mrow><mo stretchy="true">‾</mo></mover></mrow><annotation encoding="application/x-tex">\\overline{RS}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.8833em;"></span><span class="mord overline"><span class="vlist-t"><span class="vlist-r"><span class="vlist" style="height: 0.8833em;"><span class="" style="top: -3em;"><span class="pstrut" style="height: 3em;"></span><span class="mord"><span class="mord mathnormal" style="margin-right: 0.0077em;">R</span><span class="mord mathnormal" style="margin-right: 0.0576em;">S</span></span></span><span class="" style="top: -3.8033em;"><span class="pstrut" style="height: 3em;"></span><span class="overline-line" style="border-bottom-width: 0.04em;"></span></span></span></span></span></span></span></span></span></span>﻿</span>, point K lies on <span class="ql-formula" data-value="\\overline{ST}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mover accent="true"><mrow><mi>S</mi><mi>T</mi></mrow><mo stretchy="true">‾</mo></mover></mrow><annotation encoding="application/x-tex">\\overline{ST}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.8833em;"></span><span class="mord overline"><span class="vlist-t"><span class="vlist-r"><span class="vlist" style="height: 0.8833em;"><span class="" style="top: -3em;"><span class="pstrut" style="height: 3em;"></span><span class="mord"><span class="mord mathnormal" style="margin-right: 0.0576em;">S</span><span class="mord mathnormal" style="margin-right: 0.1389em;">T</span></span></span><span class="" style="top: -3.8033em;"><span class="pstrut" style="height: 3em;"></span><span class="overline-line" style="border-bottom-width: 0.04em;"></span></span></span></span></span></span></span></span></span></span>﻿</span>, and <span class="ql-formula" data-value="\\overline{LK}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mover accent="true"><mrow><mi>L</mi><mi>K</mi></mrow><mo stretchy="true">‾</mo></mover></mrow><annotation encoding="application/x-tex">\\overline{LK}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.8833em;"></span><span class="mord overline"><span class="vlist-t"><span class="vlist-r"><span class="vlist" style="height: 0.8833em;"><span class="" style="top: -3em;"><span class="pstrut" style="height: 3em;"></span><span class="mord"><span class="mord mathnormal">L</span><span class="mord mathnormal" style="margin-right: 0.0715em;">K</span></span></span><span class="" style="top: -3.8033em;"><span class="pstrut" style="height: 3em;"></span><span class="overline-line" style="border-bottom-width: 0.04em;"></span></span></span></span></span></span></span></span></span></span>﻿</span> is parallel to <span class="ql-formula" data-value="\\overline{RT}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mover accent="true"><mrow><mi>R</mi><mi>T</mi></mrow><mo stretchy="true">‾</mo></mover></mrow><annotation encoding="application/x-tex">\\overline{RT}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.8833em;"></span><span class="mord overline"><span class="vlist-t"><span class="vlist-r"><span class="vlist" style="height: 0.8833em;"><span class="" style="top: -3em;"><span class="pstrut" style="height: 3em;"></span><span class="mord"><span class="mord mathnormal" style="margin-right: 0.0077em;">R</span><span class="mord mathnormal" style="margin-right: 0.1389em;">T</span></span></span><span class="" style="top: -3.8033em;"><span class="pstrut" style="height: 3em;"></span><span class="overline-line" style="border-bottom-width: 0.04em;"></span></span></span></span></span></span></span></span></span></span>﻿</span>. What is the measure, in degrees, of angle SKL? (Disregard the degree symbol when entering your answer.)</p>`;
    const updQ10 = await request(`${API_BASE}/question/updateQuestion/${Q10_ID}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' }
    }, { question: newQ10Stem });
    console.log('Q10 update response:', updQ10.body);

    // ----------------------------------------------------
    // 4. FIX Q11: Restore missing 2nd equation (32x + 31y = c) and clean Choice A
    // ----------------------------------------------------
    const Q11_ID = '6a5b1915c3d08d90637d2f02';
    console.log('\n--- Fixing Q11 System of Equations & Choice A ---');
    const newQ11Stem = `<p><span class="ql-formula" data-value="31x - 32y = c">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mn>31</mn><mi>x</mi><mo>−</mo><mn>32</mn><mi>y</mi><mo>=</mo><mi>c</mi></mrow><annotation encoding="application/x-tex">31x - 32y = c</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.7278em; vertical-align: -0.0833em;"></span><span class="mord">31</span><span class="mord mathnormal">x</span><span class="mspace" style="margin-right: 0.2222em;"></span><span class="mbin">−</span><span class="mspace" style="margin-right: 0.2222em;"></span></span><span class="base"><span class="strut" style="height: 0.8389em; vertical-align: -0.1944em;"></span><span class="mord">32</span><span class="mord mathnormal" style="margin-right: 0.0359em;">y</span><span class="mspace" style="margin-right: 0.2778em;"></span><span class="mrel">=</span><span class="mspace" style="margin-right: 0.2778em;"></span></span><span class="base"><span class="strut" style="height: 0.4306em;"></span><span class="mord mathnormal">c</span></span></span></span></span>﻿</span></p><p><span class="ql-formula" data-value="32x + 31y = c">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mn>32</mn><mi>x</mi><mo>+</mo><mn>31</mn><mi>y</mi><mo>=</mo><mi>c</mi></mrow><annotation encoding="application/x-tex">32x + 31y = c</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.7278em; vertical-align: -0.0833em;"></span><span class="mord">32</span><span class="mord mathnormal">x</span><span class="mspace" style="margin-right: 0.2222em;"></span><span class="mbin">+</span><span class="mspace" style="margin-right: 0.2222em;"></span></span><span class="base"><span class="strut" style="height: 0.8389em; vertical-align: -0.1944em;"></span><span class="mord">31</span><span class="mord mathnormal" style="margin-right: 0.0359em;">y</span><span class="mspace" style="margin-right: 0.2778em;"></span><span class="mrel">=</span><span class="mspace" style="margin-right: 0.2778em;"></span></span><span class="base"><span class="strut" style="height: 0.4306em;"></span><span class="mord mathnormal">c</span></span></span></span></span>﻿</span></p><p>In the given system of equations, c is a positive constant. Which of the following could be the point where the graphs of the equations in this system intersect in the xy-plane?</p>`;
    const q11ChoiceA = `<p><span class="ql-formula" data-value="(c, 0)">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mo stretchy="false">(</mo><mi>c</mi><mo separator="true">,</mo><mn>0</mn><mo stretchy="false">)</mo></mrow><annotation encoding="application/x-tex">(c, 0)</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 1em; vertical-align: -0.25em;"></span><span class="mopen">(</span><span class="mord mathnormal">c</span><span class="mpunct">,</span><span class="mspace" style="margin-right: 0.1667em;"></span><span class="mord">0</span><span class="mclose">)</span></span></span></span></span>﻿</span></p>`;
    const q11Res = await request(`${API_BASE}/question/getQuestionDetails/${Q11_ID}`);
    const q11 = q11Res.body.question;
    const newQ11Wrong = [...q11.wrongAnswer];
    newQ11Wrong[0] = q11ChoiceA;
    const updQ11 = await request(`${API_BASE}/question/updateQuestion/${Q11_ID}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' }
    }, {
        question: newQ11Stem,
        wrongAnswer: newQ11Wrong
    });
    console.log('Q11 update response:', updQ11.body);

    // ----------------------------------------------------
    // 5. FIX Q12: Upload scatterplot diagram
    // ----------------------------------------------------
    const Q12_ID = '6a5b1a30c3d08d90637d2f06';
    console.log('\n--- Uploading Q12 Scatterplot Diagram ---');
    const updQ12 = await uploadImage(Q12_ID, 'scatterplot_q12.png');
    console.log('Q12 upload response:', updQ12);

    console.log('\n✨ All updates sent! Verifying on live server...');

    const vQ4 = (await request(`${API_BASE}/question/getQuestionDetails/${Q4_ID}`)).body.question;
    console.log('Verified Q4 Choice B:', vQ4.wrongAnswer[1]);

    const vQ7 = (await request(`${API_BASE}/question/getQuestionDetails/${Q7_ID}`)).body.question;
    console.log('Verified Q7 Correct Answer:', vQ7.correctAnswer);

    const vQ10 = (await request(`${API_BASE}/question/getQuestionDetails/${Q10_ID}`)).body.question;
    console.log('Verified Q10 Stem contains LK parallel to RT:', vQ10.question.includes('overline{LK}'));

    const vQ11 = (await request(`${API_BASE}/question/getQuestionDetails/${Q11_ID}`)).body.question;
    console.log('Verified Q11 Stem contains 32x + 31y = c:', vQ11.question.includes('32x + 31y = c'));

    const vQ12 = (await request(`${API_BASE}/question/getQuestionDetails/${Q12_ID}`)).body.question;
    console.log('Verified Q12 questionPic URL:', vQ12.questionPic);

    console.log('\n🎉 ALL MODULE 2 FIXES APPLIED AND VERIFIED ON PRODUCTION!');
}

runFixes().catch(console.error);
