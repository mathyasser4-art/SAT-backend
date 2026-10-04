const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'march2025_int2_light_images');

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryMarch2025INT2' + Date.now();
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
    console.log('🚀 Uploading light mode images for March 2025 INT 2...\n');

    const tasks = [
        { mod: 'M1', qNum: 2,  id: '6aa46bddec7ba02921a43ddd', file: path.join(imgDir, 'm1_q2_light.png') },
        { mod: 'M1', qNum: 3,  id: '6aa46ca9ec7ba02921a43de1', file: path.join(imgDir, 'm1_q3_light.png') },
        { mod: 'M1', qNum: 8,  id: '6aa46dd4ec7ba02921a43df8', file: path.join(imgDir, 'm1_q8_light.png') },
        { mod: 'M1', qNum: 20, id: '6aa471cfec7ba02921a43e4d', file: path.join(imgDir, 'm1_q20_light.png') },
        { mod: 'M2', qNum: 1,  id: '6aa4739cec7ba02921a43e64', file: path.join(imgDir, 'm2_q1_light.png') },
        { mod: 'M2', qNum: 4,  id: '6aa47536ec7ba02921a43e83', file: path.join(imgDir, 'm2_q4_light.png') },
        { mod: 'M2', qNum: 12, id: '6aa47822ec7ba02921a43ece', file: path.join(imgDir, 'm2_q12_light.png') },
        { mod: 'M2', qNum: 16, id: '6aa4799eec7ba02921a43ee1', file: path.join(imgDir, 'm2_q16_light.png') }
    ];

    for (const t of tasks) {
        process.stdout.write(`Uploading ${t.mod} Q${t.qNum} (${t.id})... `);
        const res = await uploadImage(t.id, t.file, path.basename(t.file));
        const newUrl = res.updatedQuestion?.question_pic || res.updatedQuestion?.questionPic || res.question_pic || res.questionPic;
        console.log(`✅ Success! New URL: ${newUrl || JSON.stringify(res)}`);
    }

    console.log('\n🎉 All 8 March 2025 INT 2 light mode images uploaded successfully!');
}

run().catch(console.error);
