const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'march2025_int1_light_images');

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryMarch2025INT1' + Date.now();
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
    console.log('🚀 Uploading light mode images for March 2025 INT 1...\n');

    const tasks = [
        { mod: 'M1', qNum: 1,  id: '6aa0f3fbdf63ca493d4799fd', file: path.join(imgDir, 'm1_q1_light.png') },
        { mod: 'M1', qNum: 8,  id: '6aa0f6dedf63ca493d479a29', file: path.join(imgDir, 'm1_q8_light.png') },
        { mod: 'M1', qNum: 21, id: '6aa10008febc2d2509387a81', file: path.join(imgDir, 'm1_q21_light.png') },
        { mod: 'M2', qNum: 17, id: '6aa11e8aec7ba02921a31b82', file: path.join(imgDir, 'm2_q17_light.png') },
        { mod: 'M2', qNum: 18, id: '6aa11f14ec7ba02921a31b86', file: path.join(imgDir, 'm2_q18_light.png') }
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

    console.log('\n🎉 All March 2025 INT 1 light mode images uploaded!');
}

run().catch(console.error);
