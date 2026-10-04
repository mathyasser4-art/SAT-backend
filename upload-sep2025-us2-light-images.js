const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'sep2025_us2_images');

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundarySep2025US2' + Date.now();
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
    console.log('🚀 Uploading light mode images for September 2025 US 2...\n');

    const tasks = [
        { mod: 'M1', qNum: 2,  id: '6a6b67aec3d08d90637d3e40', file: path.join(imgDir, 'm1_q2_light.png') },
        { mod: 'M1', qNum: 4,  id: '6a6b68cac3d08d90637d3e58', file: path.join(imgDir, 'm1_q4_light.png') },
        { mod: 'M1', qNum: 5,  id: '6a6b690ec3d08d90637d3e5e', file: path.join(imgDir, 'm1_q5_light.png') },
        { mod: 'M1', qNum: 10, id: '6a6b6a42c3d08d90637d3e76', file: path.join(imgDir, 'm1_q10_light.png') },
        { mod: 'M1', qNum: 12, id: '6a6b6ad8c3d08d90637d3e7e', file: path.join(imgDir, 'm1_q12_light.png') }
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

    console.log('\n🎉 Finished uploading all light images for September 2025 US 2.');
}

run();
