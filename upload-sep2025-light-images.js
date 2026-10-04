const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'sep2025_light_images');

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundarySep2025Int1' + Date.now();
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

async function run() {
    console.log('🚀 Uploading 4 light mode diagrams for September 2025 INT 1...\n');

    const tasks = [
        { mod: 'M1', qNum: 2,  id: '6a685934c3d08d90637d3b6f', file: path.join(imgDir, 'm1_q2_light.png') },
        { mod: 'M1', qNum: 16, id: '6a686698c3d08d90637d3bd2', file: path.join(imgDir, 'm1_q16_light.png') },
        { mod: 'M1', qNum: 20, id: '6a686b1cc3d08d90637d3bf0', file: path.join(imgDir, 'm1_q20_light.png') },
        { mod: 'M2', qNum: 22, id: '6a688e61c3d08d90637d3c96', file: path.join(imgDir, 'm2_q22_light.png') }
    ];

    for (const t of tasks) {
        process.stdout.write(`Uploading ${t.mod} Q${t.qNum} (${t.id})... `);
        const upRes = await uploadImage(t.id, t.file, path.basename(t.file));
        console.log(upRes.message === 'success' ? '✅ Success' : JSON.stringify(upRes));
    }

    console.log('\nVerifying live Cloudinary URLs on Railway...');
    for (const t of tasks) {
        const checkRes = await new Promise(resolve => {
            https.get(`${API_BASE}/question/getQuestionDetails/${t.id}`, res => {
                let d = '';
                res.on('data', c => d += c);
                res.on('end', () => resolve(JSON.parse(d)));
            });
        });
        const q = checkRes.question;
        const picUrl = typeof q.questionPic === 'string' ? q.questionPic : q.questionPic?.secure_url;
        console.log(`  ${t.mod} Q${t.qNum}: ${picUrl}`);
    }

    console.log('\n🎉 Finished uploading all light mode images for September 2025 INT 1.');
}

run().catch(console.error);
