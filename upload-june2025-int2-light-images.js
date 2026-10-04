const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'june2025_int2_images');

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryJune2025INT2' + Date.now();
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
    console.log('🚀 Uploading light mode images for June 2025 INT 2...\n');

    const tasks = [
        { mod: 'M1', qNum: 1,  id: '6a6d4cc114cab24f9785a82f', file: path.join(imgDir, 'm1_q1_light.png') },
        { mod: 'M1', qNum: 18, id: '6a6d603714cab24f9785a8d6', file: path.join(imgDir, 'm1_q18_light.png') },
        { mod: 'M2', qNum: 7,  id: '6a6d630a07c5da645a88ca60', file: path.join(imgDir, 'm2_q7_light.png') },
        { mod: 'M2', qNum: 9,  id: '6a6d638807c5da645a88ca7f', file: path.join(imgDir, 'm2_q9_light.png') },
        { mod: 'M2', qNum: 13, id: '6a6d644707c5da645a88ca9a', file: path.join(imgDir, 'm2_q13_light.png') },
        { mod: 'M2', qNum: 15, id: '6a6d64ee07c5da645a88caa2', file: path.join(imgDir, 'm2_q15_light.png') }
    ];

    for (const t of tasks) {
        process.stdout.write(`Uploading ${t.mod} Q${t.qNum} (${t.id})... `);
        try {
            const upRes = await uploadImage(t.id, t.file, path.basename(t.file));
            const newUrl = upRes.question?.questionPic || upRes.data?.questionPic;
            console.log(upRes.message === 'success' ? `✅ Success -> ${newUrl}` : JSON.stringify(upRes));
        } catch (err) {
            console.log(`❌ Error:`, err.message);
        }
    }

    console.log('\n🎉 Finished uploading all light images for June 2025 INT 2.');
}

run();
