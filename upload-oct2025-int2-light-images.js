const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'oct2025_int2_images');

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryOct2025INT2' + Date.now();
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
    console.log('🚀 Uploading 6 light mode images for October 2025 INT 2...\n');

    const tasks = [
        { mod: 'M1', qNum: 12, id: '6a627762c3d08d90637d370c', file: path.join(imgDir, 'm1_q12_light.png') },
        { mod: 'M2', qNum: 3,  id: '6a628d9fc3d08d90637d37be', file: path.join(imgDir, 'm2_q3_light.png') },
        { mod: 'M2', qNum: 5,  id: '6a628f63c3d08d90637d37d2', file: path.join(imgDir, 'm2_q5_light.png') },
        { mod: 'M2', qNum: 13, id: '6a6297e0c3d08d90637d3840', file: path.join(imgDir, 'm2_q13_light.png') },
        { mod: 'M2', qNum: 18, id: '6a629d10c3d08d90637d386c', file: path.join(imgDir, 'm2_q18_light.png') },
        { mod: 'M2', qNum: 19, id: '6a6638f3c3d08d90637d38a1', file: path.join(imgDir, 'm2_q19_light.png') }
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

    console.log('\n🎉 Finished uploading all light-mode images for October 2025 INT 2.');
}

run();
