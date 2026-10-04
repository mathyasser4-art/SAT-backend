const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'june2025_int1_images');

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryJune2025INT1' + Date.now();
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
    console.log('🚀 Uploading light mode images for June 2025 INT 1...\n');

    const tasks = [
        { mod: 'M1', qNum: 1,  id: '6a6d2afe14cab24f9785a717', file: path.join(imgDir, 'm1_q1_light.png') },
        { mod: 'M1', qNum: 7,  id: '6a6d2e8e14cab24f9785a737', file: path.join(imgDir, 'm1_q7_light.png') },
        { mod: 'M1', qNum: 18, id: '6a6d3d3a14cab24f9785a767', file: path.join(imgDir, 'm1_q18_light.png') },
        { mod: 'M2', qNum: 5,  id: '6a6d407414cab24f9785a7a0', file: path.join(imgDir, 'm2_q5_light.png') },
        { mod: 'M2', qNum: 7,  id: '6a6d413514cab24f9785a7b0', file: path.join(imgDir, 'm2_q7_light.png') }
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

    console.log('\n🎉 Finished uploading all light images for June 2025 INT 1.');
}

run();
