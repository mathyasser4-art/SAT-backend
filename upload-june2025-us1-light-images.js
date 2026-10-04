const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'june2025_us1_images');

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryJune2025US1' + Date.now();
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
    console.log('🚀 Uploading light mode images for June 2025 US 1...\n');

    const tasks = [
        { mod: 'M1', qNum: 15, id: '6a6e0849f37fd34c9d2ad097', file: path.join(imgDir, 'm1_q15_light.png') },
        { mod: 'M1', qNum: 17, id: '6a6e0982f37fd34c9d2ad0b2', file: path.join(imgDir, 'm1_q17_light.png') },
        { mod: 'M1', qNum: 19, id: '6a6e0a33f37fd34c9d2ad0ba', file: path.join(imgDir, 'm1_q19_light.png') },
        { mod: 'M1', qNum: 22, id: '6a6e0f02f37fd34c9d2ad0d4', file: path.join(imgDir, 'm1_q22_light.png') },
        { mod: 'M2', qNum: 1,  id: '6a6e0f88f37fd34c9d2ad0f5', file: path.join(imgDir, 'm2_q1_light.png') },
        { mod: 'M2', qNum: 2,  id: '6a6e101bf37fd34c9d2ad105', file: path.join(imgDir, 'm2_q2_light.png') },
        { mod: 'M2', qNum: 6,  id: '6a6e1127f37fd34c9d2ad11d', file: path.join(imgDir, 'm2_q6_light.png') },
        { mod: 'M2', qNum: 10, id: '6a6e13fd808167941fdca6dd', file: path.join(imgDir, 'm2_q10_light.png') },
        { mod: 'M2', qNum: 17, id: '6a6e1d73808167941fdca7b5', file: path.join(imgDir, 'm2_q17_light.png') }
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

    console.log('\n🎉 Finished uploading all 9 light mode images for June 2025 US 1!');
}

run().catch(console.error);
