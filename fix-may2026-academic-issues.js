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

async function fix() {
    console.log('1. Fixing M1 Q8 (stem completion)...');
    const q8Stem = '<p>The area of triangle <span class="ql-formula" data-value="ABC">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>A</mi><mi>B</mi><mi>C</mi></mrow><annotation encoding="application/x-tex">ABC</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.6833em;"></span><span class="mord mathnormal">A</span><span class="mord mathnormal" style="margin-right: 0.0502em;">B</span><span class="mord mathnormal" style="margin-right: 0.0715em;">C</span></span></span></span></span>﻿</span> is <span class="ql-formula" data-value="220">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mn>220</mn></mrow><annotation encoding="application/x-tex">220</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.6444em;"></span><span class="mord">220</span></span></span></span></span>﻿</span> square centimeters. What is the height <span class="ql-formula" data-value="h">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>h</mi></mrow><annotation encoding="application/x-tex">h</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.6944em;"></span><span class="mord mathnormal">h</span></span></span></span></span>﻿</span>, in centimeters, of this triangle?</p>';
    const resQ8 = await updateQuestion('6a50be684d554e04aa1beb79', { question: q8Stem });
    console.log('M1 Q8 Updated:', resQ8);

    console.log('2. Fixing M2 Q9 (grammatical and currency cleanup)...');
    const q9Stem = '<p>A carnival receives 10 dollars for each adult admission ticket sold and 5 dollars for each child admission ticket sold. On a particular day, the carnival received a total of 4,100 dollars from selling adult and child admission tickets. If 220 adult admission tickets were sold on that day, how many child admission tickets were sold?</p>';
    const resQ9 = await updateQuestion('6a5202d34d554e04aa1bf0ea', { question: q9Stem });
    console.log('M2 Q9 Updated:', resQ9);

    console.log('3. Fixing M2 Q13 (removing duplicate formula span)...');
    const q13Stem = '<p>The function <span class="ql-formula" data-value="k">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>k</mi></mrow><annotation encoding="application/x-tex">k</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.6944em;"></span><span class="mord mathnormal" style="margin-right: 0.0315em;">k</span></span></span></span></span>﻿</span> is defined by <span class="ql-formula" data-value="k(s) = \\sqrt{s + 110}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>k</mi><mo stretchy="false">(</mo><mi>s</mi><mo stretchy="false">)</mo><mo>=</mo><msqrt><mrow><mi>s</mi><mo>+</mo><mn>110</mn></mrow></msqrt></mrow><annotation encoding="application/x-tex">k(s) = \\sqrt{s + 110}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 1em; vertical-align: -0.25em;"></span><span class="mord mathnormal" style="margin-right: 0.0315em;">k</span><span class="mopen">(</span><span class="mord mathnormal">s</span><span class="mclose">)</span><span class="mspace" style="margin-right: 0.2778em;"></span><span class="mrel">=</span><span class="mspace" style="margin-right: 0.2778em;"></span></span><span class="base"><span class="strut" style="height: 1.04em; vertical-align: -0.1328em;"></span><span class="mord sqrt"><span class="vlist-t vlist-t2"><span class="vlist-r"><span class="vlist" style="height: 0.9072em;"><span class="svg-align" style="top: -3em;"><span class="pstrut" style="height: 3em;"></span><span class="mord" style="padding-left: 0.833em;"><span class="mord mathnormal">s</span><span class="mspace" style="margin-right: 0.2222em;"></span><span class="mbin">+</span><span class="mspace" style="margin-right: 0.2222em;"></span><span class="mord">110</span></span></span><span class="" style="top: -2.8672em;"><span class="pstrut" style="height: 3em;"></span><span class="hide-tail" style="min-width: 0.853em; height: 1.08em;"><svg width="400em" height="1.08em" viewBox="0 0 400000 1080" preserveAspectRatio="xMinYMin slice"><path d="M95,702 c-2.7,0,-7.17,-2.7,-13.5,-8c-5.8,-5.3,-9.5,-10,-9.5,-14 c0,-2,0.3,-3.3,1,-4c1.3,-2.7,23.83,-20.7,67.5,-54 c44.2,-33.3,65.8,-50.3,66.5,-51c1.3,-1.3,3,-2,5,-2c4.7,0,8.7,3.3,12,10 s173,378,173,378c0.7,0,35.3,-71,104,-213c68.7,-142,137.5,-285,206.5,-429 c69,-144,104.5,-217.7,106.5,-221 l0 -0 c5.3,-9.3,12,-14,20,-14 H400000v40H845.2724 s-225.272,467,-225.272,467s-235,486,-235,486c-2.7,4.7,-9,7,-19,7 c-6,0,-10,-1,-12,-3s-194,-422,-194,-422s-65,47,-65,47z M834 80h400000v40h-400000z"></path></svg></span></span></span><span class="vlist-s">​</span></span><span class="vlist-r"><span class="vlist" style="height: 0.1328em;"><span class=""></span></span></span></span></span></span></span></span></span>﻿</span>. If <span class="ql-formula" data-value="k(53p) = p">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>k</mi><mo stretchy="false">(</mo><mn>53</mn><mi>p</mi><mo stretchy="false">)</mo><mo>=</mo><mi>p</mi></mrow><annotation encoding="application/x-tex\">k(53p) = p</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 1em; vertical-align: -0.25em;"></span><span class="mord mathnormal" style="margin-right: 0.0315em;">k</span><span class="mopen">(</span><span class="mord">53</span><span class="mord mathnormal">p</span><span class="mclose">)</span><span class="mspace" style="margin-right: 0.2778em;"></span><span class="mrel">=</span><span class="mspace" style="margin-right: 0.2778em;"></span></span><span class="base"><span class="strut" style="height: 0.625em; vertical-align: -0.1944em;"></span><span class="mord mathnormal">p</span></span></span></span></span>﻿</span>, where <span class="ql-formula" data-value="p">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>p</mi></mrow><annotation encoding="application/x-tex\">p</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.625em; vertical-align: -0.1944em;"></span><span class="mord mathnormal">p</span></span></span></span></span>﻿</span> is a constant, what is the value of <span class="ql-formula" data-value="p">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>p</mi></mrow><annotation encoding="application/x-tex\">p</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.625em; vertical-align: -0.1944em;"></span><span class="mord mathnormal">p</span></span></span></span></span>﻿</span>?</p>';
    const resQ13 = await updateQuestion('6a52fce74d554e04aa1bf4e2', { question: q13Stem });
    console.log('M2 Q13 Updated:', resQ13);

    console.log('4. Fixing M2 Q14 (cleaning up percentage formatting and text)...');
    const q14Stem = '<p>A computer program models the population of a certain insect in an environment where the insect has no natural predators. According to the model, the estimated total mass of the population of insects at the end of every 5-week period is 158% greater than the estimated total mass of the population of insects at the end of the previous 5-week period. The estimated total mass of the population of insects at the end of 15 weeks is 627.7 grams. Which equation best represents this model, where <span class="ql-formula" data-value="M">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>M</mi></mrow><annotation encoding="application/x-tex\">M</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.6833em;"></span><span class="mord mathnormal" style="margin-right: 0.109em;">M</span></span></span></span></span>﻿</span> is the estimated total mass, in grams, of the population of insects at the end of <span class="ql-formula" data-value="t">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>t</mi></mrow><annotation encoding="application/x-tex\">t</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.6151em;"></span><span class="mord mathnormal">t</span></span></span></span></span>﻿</span> weeks?</p>';
    const resQ14 = await updateQuestion('6a52fed04d554e04aa1bf4e8', { question: q14Stem });
    console.log('M2 Q14 Updated:', resQ14);
}

fix();
