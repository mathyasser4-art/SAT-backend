const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'march2025_int3_light_images');

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryMarch2025INT3' + Date.now();
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
    console.log('🚀 Uploading light mode images for March 2025 INT 3...\n');

    const tasks = [
        { mod: 'M1', qNum: 2,  id: '6aa47cdbec7ba02921a43f3c', file: path.join(imgDir, 'm1_q2_light.png') },
        { mod: 'M1', qNum: 10, id: '6aa47ec1ec7ba02921a43f5c', file: path.join(imgDir, 'm1_q10_light.png') },
        { mod: 'M1', qNum: 11, id: '6aa47fc5ec7ba02921a43f60', file: path.join(imgDir, 'm1_q11_light.png') },
        { mod: 'M1', qNum: 16, id: '6aa48173ec7ba02921a43f7a', file: path.join(imgDir, 'm1_q16_light.png') },
        { mod: 'M1', qNum: 19, id: '6aa48223ec7ba02921a43f89', file: path.join(imgDir, 'm1_q19_light.png') },
        { mod: 'M2', qNum: 10, id: '6aa48996ec7ba02921a4402a', file: path.join(imgDir, 'm2_q10_light.png') },
        { mod: 'M2', qNum: 12, id: '6aa48a93ec7ba02921a44046', file: path.join(imgDir, 'm2_q12_light.png') },
        { mod: 'M2', qNum: 15, id: '6aa48ca2ec7ba02921a4405e', file: path.join(imgDir, 'm2_q15_light.png') }
    ];

    for (const t of tasks) {
        process.stdout.write(`Uploading ${t.mod} Q${t.qNum} (${t.id})... `);
        const res = await uploadImage(t.id, t.file, path.basename(t.file));
        const newUrl = res.updatedQuestion?.question_pic || res.updatedQuestion?.questionPic || res.question_pic || res.questionPic;
        console.log(`✅ Success! New URL: ${newUrl || JSON.stringify(res)}`);
    }

    console.log('\n🎉 All 8 March 2025 INT 3 light mode images uploaded successfully!');
}

run().catch(console.error);
