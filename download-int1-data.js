const https = require('https');
const fs = require('fs');

const API_BASE = 'https://sat-backend-production.up.railway.app';

function fetchJson(url) {
    return new Promise((resolve, reject) => {
        https.get(url, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data));
                } catch (e) {
                    reject(new Error(`Failed parsing JSON from ${url}: ${e.message}`));
                }
            });
        }).on('error', reject);
    });
}

async function run() {
    console.log('Downloading Dec 2025 INT 1 Module 1...');
    const m1 = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/6a5b2215c3d08d90637d2f83`);
    fs.writeFileSync('scratch_dec_2025_int1_m1.json', JSON.stringify(m1, null, 2));
    console.log(`Saved scratch_dec_2025_int1_m1.json (${m1.chapter?.questions?.length || 0} questions)`);

    console.log('Downloading Dec 2025 INT 1 Module 2...');
    const m2 = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/6a5b221ac3d08d90637d2f89`);
    fs.writeFileSync('scratch_dec_2025_int1_m2.json', JSON.stringify(m2, null, 2));
    console.log(`Saved scratch_dec_2025_int1_m2.json (${m2.chapter?.questions?.length || 0} questions)`);
}

run().catch(console.error);
