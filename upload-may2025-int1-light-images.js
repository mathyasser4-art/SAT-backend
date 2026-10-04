const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'may2025_int1_images');

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryMay2025INT1' + Date.now();
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
    console.log('🚀 Uploading light mode images for May 2025 INT 1...\n');

    const tasks = [
        { mod: 'M1', qNum: 9,  id: '6a9851e3e57881aee77ea9cd', file: path.join(imgDir, 'm1_q9_light.png') },
        { mod: 'M1', qNum: 15, id: '6a98567ce57881aee77eafc1', file: path.join(imgDir, 'm1_q15_light.png') },
        { mod: 'M1', qNum: 16, id: '6a9af216838c4fe747f6d9b5', file: path.join(imgDir, 'm1_q16_light.png') },
        { mod: 'M1', qNum: 18, id: '6a9af4bf838c4fe747f6e2e8', file: path.join(imgDir, 'm1_q18_light.png') },
        { mod: 'M2', qNum: 2,  id: '6a9afb07838c4fe747f6f030', file: path.join(imgDir, 'm2_q2_light.png') },
        { mod: 'M2', qNum: 3,  id: '6a9afb97838c4fe747f6f04c', file: path.join(imgDir, 'm2_q3_light.png') },
        { mod: 'M2', qNum: 4,  id: '6a9afd77838c4fe747f6f052', file: path.join(imgDir, 'm2_q4_light.png') },
        { mod: 'M2', qNum: 10, id: '6a9b007c838c4fe747f6f1ef', file: path.join(imgDir, 'm2_q10_light.png') }
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

    console.log('\n🎉 Finished uploading all 8 light mode images for May 2025 INT 1!');
}

run().catch(console.error);
