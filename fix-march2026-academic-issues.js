const https = require('https');

const API_BASE = 'https://sat-backend-production.up.railway.app';

function updateQuestion(questionId, payloadObj) {
    return new Promise((resolve, reject) => {
        const payload = JSON.stringify(payloadObj);
        const req = https.request(`${API_BASE}/question/updateQuestion/${questionId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload)
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
        req.write(payload);
        req.end();
    });
}

async function run() {
    console.log('🚀 Fixing academic issues for March 2026 US 1...\n');

    // 1. M1 Q5 (6a5191724d554e04aa1bec70)
    console.log('1. Fixing M1 Q5 (function definition and notation)...');
    const m1q5Res = await updateQuestion('6a5191724d554e04aa1bec70', {
        question: '<p>The function <span class="ql-formula" data-value="h"></span> is defined by <span class="ql-formula" data-value="h(x) = 8x"></span>. What is the value of <span class="ql-formula" data-value="h(x)"></span> when <span class="ql-formula" data-value="x = 48"></span>?</p>'
    });
    console.log('   M1 Q5 Updated:', m1q5Res);

    // 2. M2 Q13 (6a5263144d554e04aa1bf1bc)
    console.log('2. Fixing M2 Q13 (currency phrasing)...');
    const m2q13Res = await updateQuestion('6a5263144d554e04aa1bf1bc', {
        question: '<p><span class="ql-formula" data-value="7x + 12y = 180"></span></p><p>The equation gives the possible combinations of the number of mugs, <span class="ql-formula" data-value="x"></span>, and the number of plates, <span class="ql-formula" data-value="y"></span>, in a collection that is worth a total of 180 dollars. If there are 8 plates in the collection, how many mugs are in the collection?</p>'
    });
    console.log('   M2 Q13 Updated:', m2q13Res);

    // 3. M2 Q21 (6a526b154d554e04aa1bf247)
    console.log('3. Fixing M2 Q21 (clarifying multiplication in choices)...');
    const m2q21Res = await updateQuestion('6a526b154d554e04aa1bf247', {
        wrongAnswer: [
            '<p><span class="ql-formula" data-value="\\frac{9\\pi}{11} \\times 90 \\times 2"></span></p>',
            '<p><span class="ql-formula" data-value="\\frac{9\\pi}{11} \\times 180 \\times 2"></span></p>',
            '<p><span class="ql-formula" data-value="\\frac{\\pi}{11} \\times 90 \\times 2"></span></p>',
            '<p><span class="ql-formula" data-value="\\frac{\\pi}{11} \\times 180 \\times 2"></span></p>'
        ],
        correctAnswer: '<p><span class="ql-formula" data-value="\\frac{\\pi}{11} \\times 180 \\times 2"></span></p>'
    });
    console.log('   M2 Q21 Updated:', m2q21Res);

    console.log('\nAcademic fixes successfully applied.');
}

run().catch(console.error);
