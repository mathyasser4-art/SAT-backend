const https = require('https');
const fs = require('fs');

const API_BASE = 'https://sat-backend-production.up.railway.app';

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryMarch2026' + Date.now();
        const header = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="image"; filename="${filename}"\r\nContent-Type: image/png\r\n\r\n`);
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

function updateQuestionJson(questionId, payloadObj) {
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
    console.log('🚀 Uploading 11 light mode images for March 2026 US 1...\n');

    const tasks = [
        { mod: 'M1', qNum: 1,  id: '6a518ce14d554e04aa1bec40', file: 'mar26_us1_m1_q1_light.png' },
        { mod: 'M1', qNum: 2,  id: '6a518f184d554e04aa1bec48', file: 'mar26_us1_m1_q2_light.png' },
        { mod: 'M1', qNum: 4,  id: '6a5190c54d554e04aa1bec66', file: 'mar26_us1_m1_q4_light.png' },
        { mod: 'M1', qNum: 8,  id: '6a51955e4d554e04aa1becca', file: 'mar26_us1_m1_q8_light.png' },
        { mod: 'M1', qNum: 13, id: '6a519f4a4d554e04aa1bed8e', file: 'mar26_us1_m1_q13_light.png' },
        { mod: 'M1', qNum: 18, id: '6a51ad784d554e04aa1bee5d', file: 'mar26_us1_m1_q18_light.png' },
        { mod: 'M1', qNum: 20, id: '6a51ae874d554e04aa1bee71', file: 'mar26_us1_m1_q20_light.png' },
        { mod: 'M2', qNum: 6,  id: '6a525c754d554e04aa1bf157', file: 'mar26_us1_m2_q6_light.png' },
        { mod: 'M2', qNum: 10, id: '6a525fdc4d554e04aa1bf191', file: 'mar26_us1_m2_q10_light.png' },
        { mod: 'M2', qNum: 14, id: '6a5263854d554e04aa1bf1cc', file: 'mar26_us1_m2_q14_light.png' },
        { mod: 'M2', qNum: 19, id: '6a52681a4d554e04aa1bf22b', file: 'mar26_us1_m2_q19_light.png' }
    ];

    for (const t of tasks) {
        process.stdout.write(`Uploading ${t.mod} Q${t.qNum} (${t.id})... `);
        const upRes = await uploadImage(t.id, t.file, t.file);
        console.log(upRes.message || upRes);
    }

    // Clean up M2 Q19 choices to clean A, B, C, D text matching the 4-panel image
    console.log('\nNormalizing M2 Q19 choices to text A, B, C, D...');
    const m2q19Fix = await updateQuestionJson('6a52681a4d554e04aa1bf22b', {
        wrongAnswer: ['<p>A</p>', '<p>B</p>', '<p>C</p>', '<p>D</p>'],
        correctAnswer: '<p>C</p>'
    });
    console.log('M2 Q19 choices normalized:', m2q19Fix.message || m2q19Fix);

    console.log('\nAll 11 images uploaded and configured successfully!');
}

run().catch(console.error);
