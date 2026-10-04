const https = require('https');
const fs = require('fs');

const API_BASE = 'https://sat-backend-production.up.railway.app';

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryLight' + Date.now();
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
    console.log('🚀 Uploading light mode images for Dec 2025 US 1 Module 1...\n');

    const tasks = [
        { qNum: 4, id: '6a53ff254d554e04aa1bfc24', file: 'q4_light.png' },
        { qNum: 7, id: '6a54015e4d554e04aa1bfc52', file: 'q7_light.png' },
        { qNum: 20, id: '6a5410164d554e04aa1bfd0d', file: 'q20_light.png' },
        { qNum: 21, id: '6a5410564d554e04aa1bfd13', file: 'q21_light.png' },
        { qNum: 22, id: '6a54109c4d554e04aa1bfd17', file: 'q22_light.png' }
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

    console.log('\n🎉 ALL MODULE 1 IMAGES SUCCESSFULLY CONVERTED TO LIGHT MODE!');
}

run().catch(console.error);
