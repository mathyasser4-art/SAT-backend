const https = require('https');
const fs = require('fs');
const path = require('path');

const images = [
  { name: 'm1_q17_u0p0teudamaxci4rfkbf.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788616735/questionPic/u0p0teudamaxci4rfkbf.png' },
  { name: 'm1_q18_zzryslmcxpxyrdy8kuvg.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788616828/questionPic/zzryslmcxpxyrdy8kuvg.png' },
  { name: 'm2_q2_bsoehtkqyd2m1ra66oju.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788928397/questionPic/bsoehtkqyd2m1ra66oju.png' }
];

const dir = path.join(__dirname, 'may2025_int3_raw_images');
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
