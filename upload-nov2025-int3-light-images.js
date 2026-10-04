const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'nov2025_int3_images');

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryNov2025INT3' + Date.now();
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
    console.log('🚀 Uploading 5 light mode images for November 2025 INT 3...\n');

    const tasks = [
        { mod: 'M1', qNum: 5,  id: '6a6232d6c3d08d90637d34db', file: path.join(imgDir, 'm1_q5_light.png') },
        { mod: 'M1', qNum: 10, id: '6a623445c3d08d90637d34f7', file: path.join(imgDir, 'm1_q10_light.png') },
        { mod: 'M1', qNum: 11, id: '6a623489c3d08d90637d34fb', file: path.join(imgDir, 'm1_q11_light.png') },
        { mod: 'M1', qNum: 13, id: '6a62352dc3d08d90637d3503', file: path.join(imgDir, 'm1_q13_light.png') },
        { mod: 'M2', qNum: 4,  id: '6a624414c3d08d90637d359a', file: path.join(imgDir, 'm2_q4_light.png') }
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

    console.log('\n🎉 Finished uploading all light-mode images for November 2025 INT 3.');
}

run();
