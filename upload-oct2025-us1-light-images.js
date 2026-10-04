const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'oct2025_us1_images');

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryOct2025US1' + Date.now();
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
    console.log('🚀 Uploading 6 light mode images for October 2025 US 1...\n');

    const tasks = [
        { mod: 'M1', qNum: 6,  id: '6a665b96c3d08d90637d3a26', file: path.join(imgDir, 'm1_q6_light.png') },
        { mod: 'M1', qNum: 15, id: '6a665e3dc3d08d90637d3a4e', file: path.join(imgDir, 'm1_q15_light.png') },
        { mod: 'M1', qNum: 18, id: '6a665f19c3d08d90637d3a62', file: path.join(imgDir, 'm1_q18_light.png') },
        { mod: 'M1', qNum: 21, id: '6a6660f6c3d08d90637d3a70', file: path.join(imgDir, 'm1_q21_light.png') },
        { mod: 'M2', qNum: 3,  id: '6a667416c3d08d90637d3a96', file: path.join(imgDir, 'm2_q3_light.png') },
        { mod: 'M2', qNum: 6,  id: '6a66749ac3d08d90637d3aa2', file: path.join(imgDir, 'm2_q6_light.png') }
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

    console.log('\n🎉 Finished uploading all light images for October 2025 US 1.');
}

run();
