const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'nov2025_int1_images');

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryNov2025INT1' + Date.now();
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
    console.log('🚀 Uploading 6 light mode images for November 2025 INT 1...\n');

    const tasks = [
        { mod: 'M1', qNum: 2,  id: '6a5b47c0c3d08d90637d315a', file: path.join(imgDir, 'm1_q2_light.png') },
        { mod: 'M1', qNum: 11, id: '6a5b4acac3d08d90637d319b', file: path.join(imgDir, 'm1_q11_light.png') },
        { mod: 'M1', qNum: 14, id: '6a5b50adc3d08d90637d31a9', file: path.join(imgDir, 'm1_q14_light.png') },
        { mod: 'M1', qNum: 20, id: '6a5b52bcc3d08d90637d31d1', file: path.join(imgDir, 'm1_q20_light.png') },
        { mod: 'M2', qNum: 2,  id: '6a5b54fdc3d08d90637d31f5', file: path.join(imgDir, 'm2_q2_light.png') },
        { mod: 'M2', qNum: 4,  id: '6a5b55c7c3d08d90637d3222', file: path.join(imgDir, 'm2_q4_light.png') }
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

    console.log('\n🎉 Finished uploading all light-mode images for November 2025 INT 1.');
}

run();
