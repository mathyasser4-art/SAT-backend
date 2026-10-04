const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryLightINT1' + Date.now();
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

function getQuestionDetails(questionId) {
    return new Promise((resolve, reject) => {
        https.get(`${API_BASE}/question/getQuestionDetails/${questionId}`, res => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve(JSON.parse(data)));
        }).on('error', reject);
    });
}

async function run() {
    console.log('🚀 Uploading light mode images for Dec 2025 INT 1...\n');

    const tasks = [
        { qNum: 13, id: '6a5b2ab6c3d08d90637d2ff5', file: 'int1_m1_q13_light.png' },
        { qNum: 14, id: '6a5b2b11c3d08d90637d2ffb', file: 'int1_m1_q14_light.png' }
    ];

    const results = [];

    for (const t of tasks) {
        console.log(`Uploading M1 Q${t.qNum} (${t.id})...`);
        const upRes = await uploadImage(t.id, t.file, t.file);
        console.log(`  Upload response:`, upRes);

        const verify = await getQuestionDetails(t.id);
        const newUrl = verify.question?.questionPic;
        console.log(`  Verified new URL: ${newUrl}\n`);
        results.push({ qNum: t.qNum, id: t.id, newUrl });
    }

    fs.writeFileSync('int1_uploaded_images.json', JSON.stringify(results, null, 2));
    console.log('✅ Done! Saved results to int1_uploaded_images.json');
}

run().catch(console.error);
