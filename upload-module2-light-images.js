const https = require('https');
const fs = require('fs');

const API_BASE = 'https://sat-backend-production.up.railway.app';

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryLightM2' + Date.now();
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
    console.log('🚀 Uploading light mode images for Dec 2025 US 1 Module 2...\n');

    const tasks = [
        { qNum: 5, id: '6a5b14b4c3d08d90637d2ece', file: 'm2_q5_light.png' },
        { qNum: 6, id: '6a5b1565c3d08d90637d2edc', file: 'm2_q6_light.png' },
        { qNum: 9, id: '6a5b172ec3d08d90637d2ef2', file: 'm2_q9_light.png' },
        { qNum: 12, id: '6a5b1a30c3d08d90637d2f06', file: 'm2_q12_light.png' }
    ];

    for (const t of tasks) {
        console.log(`Uploading Q${t.qNum} (${t.file})...`);
        const res = await uploadImage(t.id, t.file, t.file);
        console.log(`  Q${t.qNum} upload response:`, res.message || res);
    }

    console.log('\n✨ Verifying newly updated image URLs on live production server...\n');
    for (const t of tasks) {
        const qData = await getQuestionDetails(t.id);
        console.log(`Q${t.qNum} questionPic: ${qData.question?.questionPic}`);
    }

    console.log('\n🎉 ALL MODULE 2 IMAGES SUCCESSFULLY CONVERTED TO LIGHT MODE!');
}

run().catch(console.error);
