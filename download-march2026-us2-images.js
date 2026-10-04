const https = require('https');
const fs = require('fs');
const path = require('path');

const dir = path.join(__dirname, 'march2026_us2_images');
if (!fs.existsSync(dir)) fs.mkdirSync(dir);

const imgs = JSON.parse(fs.readFileSync('march2026_us2_images_to_convert.json', 'utf8'));

function download(url, dest) {
    return new Promise((resolve, reject) => {
        const file = fs.createWriteStream(dest);
        https.get(url, res => {
            res.pipe(file);
            file.on('finish', () => file.close(resolve));
        }).on('error', err => {
            fs.unlink(dest, () => reject(err));
        });
    });
}

async function run() {
    console.log('Downloading original images for March 2026 US 2...');
    for (const item of imgs.m1) {
        const ext = path.extname(item.pic) || '.png';
        const filename = `m1_q${item.qNum}_${item.id}_dark${ext}`;
        const dest = path.join(dir, filename);
        console.log(`Downloading M1 Q${item.qNum}...`);
        await download(item.pic, dest);
    }
    for (const item of imgs.m2) {
        const ext = path.extname(item.pic) || '.png';
        const filename = `m2_q${item.qNum}_${item.id}_dark${ext}`;
        const dest = path.join(dir, filename);
        console.log(`Downloading M2 Q${item.qNum}...`);
        await download(item.pic, dest);
    }
    console.log('All 9 images downloaded.');
}

run().catch(console.error);
