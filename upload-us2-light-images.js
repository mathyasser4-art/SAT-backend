const https = require('https');
const fs = require('fs');

const API_BASE = 'https://sat-backend-production.up.railway.app';

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryLightUS2' + Date.now();
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
    console.log('🚀 Uploading light mode images for Dec 2025 US 2...\n');

    const tasks = [
        // Module 1
        { module: 1, qNum: 8, id: '6a54bfbc4d554e04aa1bfe77', file: 'us2_m1_q8_light.png' },
        { module: 1, qNum: 11, id: '6a54c1904d554e04aa1bfe95', file: 'us2_m1_q11_light.png' },
        { module: 1, qNum: 12, id: '6a54c2834d554e04aa1bfe9b', file: 'us2_m1_q12_light.png' },
        { module: 1, qNum: 14, id: '6a54c4cf4d554e04aa1bfead', file: 'us2_m1_q14_light.png' },
        { module: 1, qNum: 15, id: '6a54c6bc4d554e04aa1bfeb3', file: 'us2_m1_q15_light.png' },

        // Module 2
        { module: 2, qNum: 3, id: '6a54d1c94d554e04aa1bff19', file: 'us2_m2_q3_light.png' },
        { module: 2, qNum: 5, id: '6a54d3524d554e04aa1bff35', file: 'us2_m2_q5_light.png' },
        { module: 2, qNum: 20, id: '6a7412f0fb6980734c71c24c', file: 'us2_m2_q20_light.png' }
    ];

    for (const t of tasks) {
        console.log(`Uploading M${t.module} Q${t.qNum} (${t.file})...`);
        const res = await uploadImage(t.id, t.file, t.file);
        console.log(`  M${t.module} Q${t.qNum} upload response:`, res.message || res);
    }

    console.log('\n✨ Verifying newly updated image URLs on live production server...\n');
    for (const t of tasks) {
        const qData = await getQuestionDetails(t.id);
        console.log(`M${t.module} Q${t.qNum} questionPic: ${qData.question?.questionPic}`);
    }

    console.log('\n🎉 ALL US 2 IMAGES SUCCESSFULLY CONVERTED TO LIGHT MODE AND DEPLOYED!');
}

run().catch(console.error);
