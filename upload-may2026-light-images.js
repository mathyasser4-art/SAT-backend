const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryMay2026' + Date.now();
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
    console.log('🚀 Uploading light mode images for May 2026 INT 1...\n');

    const tasks = [
        { mod: 'M1', qNum: 7,  id: '6a4dc0448a8c6f71bf226290', file: 'may26_m1_q7_light.png' },
        { mod: 'M1', qNum: 8,  id: '6a50be684d554e04aa1beb79', file: 'may26_m1_q8_light.png' },
        { mod: 'M1', qNum: 9,  id: '6a50c0a84d554e04aa1beb95', file: 'may26_m1_q9_light.png' },
        { mod: 'M1', qNum: 18, id: '6a50cf0a4d554e04aa1bebf3', file: 'may26_m1_q18_light.png' },
        { mod: 'M2', qNum: 17, id: '6a5303c24d554e04aa1bf50c', file: 'may26_m2_q17_light.png' }
    ];

    const results = [];

    for (const t of tasks) {
        console.log(`Uploading ${t.mod} Q${t.qNum} (${t.id})...`);
        const upRes = await uploadImage(t.id, t.file, t.file);
        console.log(`  Upload response:`, upRes.message || upRes);

        const details = await getQuestionDetails(t.id);
        const newUrl = details.question ? details.question.image : 'unknown';
        console.log(`  New Cloudinary URL: ${newUrl}\n`);

        results.push({
            mod: t.mod,
            qNum: t.qNum,
            id: t.id,
            newUrl: newUrl
        });
    }

    console.log('Done uploading all 5 images!');
    fs.writeFileSync('may2026_image_upload_results.json', JSON.stringify(results, null, 2));
}

run().catch(console.error);
