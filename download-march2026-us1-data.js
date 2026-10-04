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
    console.log('Downloading March 2026 US 1 Module 1...');
    const m1 = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/6a4c4cbc8a8c6f71bf226125`);
    fs.writeFileSync('scratch_march_2026_us1_m1.json', JSON.stringify(m1, null, 2));
    console.log(`Saved scratch_march_2026_us1_m1.json (${m1.chapter?.questions?.length || 0} questions)`);

    console.log('Downloading March 2026 US 1 Module 2...');
    const m2 = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/6a4c4cc58a8c6f71bf22612b`);
    fs.writeFileSync('scratch_march_2026_us1_m2.json', JSON.stringify(m2, null, 2));
    console.log(`Saved scratch_march_2026_us1_m2.json (${m2.chapter?.questions?.length || 0} questions)`);
}

run().catch(console.error);
