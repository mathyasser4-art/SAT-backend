const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'dec2024_int1_light_images');

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryDec2024INT1' + Date.now();
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
    console.log('🚀 Uploading light mode images for December 2024 INT 1...\n');

    const tasks = [
        { mod: 'M1', qNum: 1,  id: '6aa58665ec7ba02921a44445', file: path.join(imgDir, 'M1_Q1_6aa58665ec7ba02921a44445.png') },
        { mod: 'M1', qNum: 3,  id: '6aa5874bec7ba02921a4444d', file: path.join(imgDir, 'M1_Q3_6aa5874bec7ba02921a4444d.png') },
        { mod: 'M1', qNum: 6,  id: '6aa5896aec7ba02921a44460', file: path.join(imgDir, 'M1_Q6_6aa5896aec7ba02921a44460.png') },
        { mod: 'M1', qNum: 8,  id: '6aa58a32ec7ba02921a44468', file: path.join(imgDir, 'M1_Q8_6aa58a32ec7ba02921a44468.png') },
        { mod: 'M1', qNum: 10, id: '6aa58ad8ec7ba02921a44470', file: path.join(imgDir, 'M1_Q10_6aa58ad8ec7ba02921a44470.png') },
        { mod: 'M1', qNum: 11, id: '6aa58b67ec7ba02921a44474', file: path.join(imgDir, 'M1_Q11_6aa58b67ec7ba02921a44474.png') },
        { mod: 'M2', qNum: 1,  id: '6aa599feec7ba02921a444c7', file: path.join(imgDir, 'M2_Q1_6aa599feec7ba02921a444c7.png') },
        { mod: 'M2', qNum: 7,  id: '6aa59bd3ec7ba02921a444df', file: path.join(imgDir, 'M2_Q7_6aa59bd3ec7ba02921a444df.png') },
        { mod: 'M2', qNum: 9,  id: '6aa59cadec7ba02921a444e7', file: path.join(imgDir, 'M2_Q9_6aa59cadec7ba02921a444e7.png') },
        { mod: 'M2', qNum: 16, id: '6aa5aeb1ec7ba02921a44518', file: path.join(imgDir, 'M2_Q16_6aa5aeb1ec7ba02921a44518.png') },
        { mod: 'M2', qNum: 22, id: '6aa5b103ec7ba02921a44616', file: path.join(imgDir, 'M2_Q22_6aa5b103ec7ba02921a44616.png') }
    ];

    for (const t of tasks) {
        process.stdout.write(`Uploading ${t.mod} Q${t.qNum} (${t.id})... `);
        const res = await uploadImage(t.id, t.file, path.basename(t.file));
        const newUrl = res.updatedQuestion?.question_pic || res.updatedQuestion?.questionPic || res.question_pic || res.questionPic || res.pic?.url;
        console.log(`✅ Success! New URL: ${newUrl || JSON.stringify(res)}`);
    }

    console.log('\n🎉 All 11 December 2024 INT 1 light mode images uploaded successfully!');
}

run().catch(console.error);
