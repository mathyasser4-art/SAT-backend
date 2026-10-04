const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'march2026_int2_images');

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryMarch2026INT2' + Date.now();
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
    console.log('🚀 Uploading 7 light mode images for March 2026 INT 2...\n');

    const tasks = [
        { mod: 'M1', qNum: 1,  id: '6a53d3684d554e04aa1bf8f5', file: path.join(imgDir, 'm1_q1_light.png') },
        { mod: 'M1', qNum: 14, id: '6a53db974d554e04aa1bf978', file: path.join(imgDir, 'm1_q14_light.png') },
        { mod: 'M1', qNum: 21, id: '6a53dfe84d554e04aa1bf9be', file: path.join(imgDir, 'm1_q21_light.png') },
        { mod: 'M2', qNum: 2,  id: '6a53e4a44d554e04aa1bf9f2', file: path.join(imgDir, 'm2_q2_light.png') },
        { mod: 'M2', qNum: 4,  id: '6a53e61d4d554e04aa1bfa12', file: path.join(imgDir, 'm2_q4_light.png') },
        { mod: 'M2', qNum: 6,  id: '6a53e79d4d554e04aa1bfa20', file: path.join(imgDir, 'm2_q6_light.png') },
        { mod: 'M2', qNum: 10, id: '6a53f44b4d554e04aa1bfa5f', file: path.join(imgDir, 'm2_q10_light.png') }
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

    console.log('\n🎉 Finished uploading all light-mode images for March 2026 INT 2.');
}

run();
