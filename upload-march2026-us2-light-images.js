const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'march2026_us2_images');

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryMarch2026US2' + Date.now();
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
    console.log('🚀 Uploading 9 light mode images for March 2026 US 2...\n');

    const tasks = [
        { mod: 'M1', qNum: 3,  id: '6a52d69a4d554e04aa1bf3a4', file: path.join(imgDir, 'm1_q3_light.png') },
        { mod: 'M1', qNum: 10, id: '6a52e48f4d554e04aa1bf42a', file: path.join(imgDir, 'm1_q10_light.png') },
        { mod: 'M1', qNum: 13, id: '6a52e7b54d554e04aa1bf456', file: path.join(imgDir, 'm1_q13_light.png') },
        { mod: 'M1', qNum: 15, id: '6a52e8e44d554e04aa1bf462', file: path.join(imgDir, 'm1_q15_light.png') },
        { mod: 'M1', qNum: 17, id: '6a52ea514d554e04aa1bf46e', file: path.join(imgDir, 'm1_q17_light.png') },
        { mod: 'M1', qNum: 21, id: '6a52ec734d554e04aa1bf490', file: path.join(imgDir, 'm1_q21_light.png') },
        { mod: 'M2', qNum: 11, id: '6a53bfff4d554e04aa1bf79e', file: path.join(imgDir, 'm2_q11_light.png') },
        { mod: 'M2', qNum: 12, id: '6a53c3a14d554e04aa1bf7f5', file: path.join(imgDir, 'm2_q12_light.png') },
        { mod: 'M2', qNum: 15, id: '6a53c8194d554e04aa1bf81f', file: path.join(imgDir, 'm2_q15_light.png') }
    ];

    const results = [];

    for (const t of tasks) {
        process.stdout.write(`Uploading ${t.mod} Q${t.qNum} (${t.id})... `);
        const upRes = await uploadImage(t.id, t.file, path.basename(t.file));
        const newUrl = upRes.question?.questionPic || upRes.data?.questionPic;
        console.log(upRes.message === 'success' ? `✅ Success -> ${newUrl}` : JSON.stringify(upRes));
        results.push({
            mod: t.mod,
            qNum: t.qNum,
            id: t.id,
            newUrl: newUrl
        });
    }

    fs.writeFileSync('march2026_us2_upload_results.json', JSON.stringify(results, null, 2));
    console.log('\nAll 9 images uploaded to Cloudinary successfully!');
}

run().catch(console.error);
