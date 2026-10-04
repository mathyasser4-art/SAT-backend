const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'oct2025_int2_images');

function uploadImage(questionId, filePath, filename) {
    return new Promise((resolve, reject) => {
        const fileBuf = fs.readFileSync(filePath);
        const boundary = '----WebKitFormBoundaryOct2025Final' + Date.now();
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

function updateQuestionJson(questionId, payloadObj) {
    return new Promise((resolve, reject) => {
        const payload = JSON.stringify(payloadObj);
        const req = https.request(`${API_BASE}/question/updateQuestion/${questionId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload)
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
        req.write(payload);
        req.end();
    });
}

function f(formula) {
    return `<span class="ql-formula" data-value="${formula}"></span>`;
}

async function run() {
    console.log('🚀 Uploading light mode images for M1 Q21 and M2 Q14...\n');

    // 1. Upload M1 Q21
    const m1q21File = path.join(imgDir, 'm1_q21_light.png');
    console.log('Uploading M1 Q21 (6a6285b1c3d08d90637d374e)...');
    const upM1 = await uploadImage('6a6285b1c3d08d90637d374e', m1q21File, 'm1_q21_light.png');
    console.log('M1 Q21 image upload result:', upM1.message === 'success' ? '✅' : JSON.stringify(upM1));

    // Clean stem (remove old inline dark img)
    const cleanStemM1Q21 = `<p>The scatterplot shows the relationship between two variables, ${f('x')} and ${f('y')}. A line of best fit for the data is also shown.</p><p>For how many of the ${f('9')} data points is the actual ${f('y')}-value greater than the ${f('y')}-value predicted by the line of best fit?</p>`;
    const stemResM1 = await updateQuestionJson('6a6285b1c3d08d90637d374e', { question: cleanStemM1Q21 });
    console.log('M1 Q21 stem clean result:', stemResM1.message === 'success' ? '✅' : JSON.stringify(stemResM1));

    // 2. Upload M2 Q14
    const m2q14File = path.join(imgDir, 'm2_q14_light.png');
    console.log('\nUploading M2 Q14 (6a629918c3d08d90637d384a)...');
    const upM2 = await uploadImage('6a629918c3d08d90637d384a', m2q14File, 'm2_q14_light.png');
    console.log('M2 Q14 image upload result:', upM2.message === 'success' ? '✅' : JSON.stringify(upM2));

    // Clean stem (remove old inline dark img)
    const cleanStemM2Q14 = `<p>At a nature preserve, a wildlife biologist counted bald eagles from an observation deck at the same time each day for ${f('21')} days. The table summarizes the resulting data set, data set A.</p><p>The data value ${f('19')} was recorded in error and is removed from data set A to create data set B, which consists of the remaining ${f('20')} data values. Which statement best compares the median of data set A and the median of data set B?</p>`;
    const stemResM2 = await updateQuestionJson('6a629918c3d08d90637d384a', { question: cleanStemM2Q14 });
    console.log('M2 Q14 stem clean result:', stemResM2.message === 'success' ? '✅' : JSON.stringify(stemResM2));

    console.log('\nFinished uploading and cleaning images for October 2025 INT 2!');
}

run();
