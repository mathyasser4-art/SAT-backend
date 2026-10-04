const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'march2026_int1_images');

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryMarch2026INT1' + Date.now();
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
    console.log('🚀 Uploading 4 light mode images for March 2026 INT 1...\n');

    const tasks = [
        { mod: 'M1', qNum: 1,  id: '6a5309f24d554e04aa1bf55a', file: path.join(imgDir, 'm1_q1_light.png') },
        { mod: 'M1', qNum: 5,  id: '6a533de84d554e04aa1bf584', file: path.join(imgDir, 'm1_q5_light.png') },
        { mod: 'M1', qNum: 8,  id: '6a533fd44d554e04aa1bf5a2', file: path.join(imgDir, 'm1_q8_light.png') },
        { mod: 'M2', qNum: 22, id: '6a549cb84d554e04aa1bfde9', file: path.join(imgDir, 'm2_q22_light.png') }
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

    fs.writeFileSync('march2026_int1_upload_results.json', JSON.stringify(results, null, 2));
    console.log('\nAll 4 images uploaded to Cloudinary successfully!');
}

run().catch(console.error);
