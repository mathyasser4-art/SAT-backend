const https = require('https');
const fs = require('fs');
const path = require('path');

const dir = path.join(__dirname, 'march2026_int2_images');
if (!fs.existsSync(dir)) fs.mkdirSync(dir);

const list = [
  { name: 'm1_q1_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783878503/questionPic/wzllracus1exzbvwtag4.png' },
  { name: 'm1_q14_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783880598/questionPic/epzt93hb9xnjw06f52eh.png' },
  { name: 'm1_q21_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783881703/questionPic/vc31wt82hpsdjwkrhynb.png' },
  { name: 'm2_q2_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783882916/questionPic/ddfkdhhqjd5mrnjon6vo.png' },
  { name: 'm2_q4_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783883292/questionPic/fcjli3w4zij8inbylrzo.png' },
  { name: 'm2_q6_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783883677/questionPic/fwwkt2etaqv7unkl1rp0.png' },
  { name: 'm2_q10_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783886922/questionPic/uoxtrjfkfdvvzug6iqq5.png' },
];

function download(item) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(path.join(dir, item.name));
    https.get(item.url, res => {
      res.pipe(file);
      file.on('finish', () => {
        file.close(() => resolve(item.name));
      });
    }).on('error', reject);
  });
}

async function run() {
  for (const item of list) {
    process.stdout.write(`Downloading ${item.name}... `);
    await download(item);
    console.log('Done.');
  }
}

run().catch(console.error);
