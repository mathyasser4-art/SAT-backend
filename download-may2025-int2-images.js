const https = require('https');
const fs = require('fs');
const path = require('path');

const images = [
  { name: 'm1_q18_sxrbhjkjullrnzrlgmcg.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788559809/questionPic/sxrbhjkjullrnzrlgmcg.png' },
  { name: 'm2_q2_eyuw1rlzlgkwlymqb63l.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788561379/questionPic/eyuw1rlzlgkwlymqb63l.png' },
  { name: 'm2_q17_keiuh4dyusetat3nohh6.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788611689/questionPic/keiuh4dyusetat3nohh6.png' },
  { name: 'm2_q20_vvgncsl9rmw41suxbq1w.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788612113/questionPic/vvgncsl9rmw41suxbq1w.png' }
];

const dir = path.join(__dirname, 'may2025_int2_raw_images');
if (!fs.existsSync(dir)) fs.mkdirSync(dir);

async function download(item) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(path.join(dir, item.name));
    https.get(item.url, res => {
      res.pipe(file);
      file.on('finish', () => {
        file.close();
        console.log(`Downloaded ${item.name}`);
        resolve();
      });
    }).on('error', err => {
      fs.unlink(path.join(dir, item.name), () => {});
      reject(err);
    });
  });
}

async function run() {
  for (const img of images) {
    await download(img);
  }
  console.log('All images downloaded successfully.');
}

run().catch(console.error);
