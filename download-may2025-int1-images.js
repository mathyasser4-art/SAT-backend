const https = require('https');
const fs = require('fs');
const path = require('path');

const images = [
  { name: 'm1_q9.png',  url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788367331/questionPic/mjmn593whueucnxrqg6o.png' },
  { name: 'm1_q15.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788368507/questionPic/hfet4leb4kuolawajcjz.png' },
  { name: 'm1_q16.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788539413/questionPic/io7prk0yeuskbxmpslov.png' },
  { name: 'm1_q18.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788540095/questionPic/syiyahwsa84o9znum3fr.png' },
  { name: 'm2_q2.png',  url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788541703/questionPic/ubpbr1zz432knbhw0l1q.png' },
  { name: 'm2_q3.png',  url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788541847/questionPic/ijmngpyqv8lpnz2ecuwy.png' },
  { name: 'm2_q4.png',  url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788542326/questionPic/vo2zovvbvrvshekajjkb.png' },
  { name: 'm2_q10.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788543099/questionPic/zdpnpyr7owtor1dqjlzb.png' }
];

const dir = path.join(__dirname, 'raw_may2025_int1_images');
if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

async function download(item) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(path.join(dir, item.name));
    https.get(item.url, res => {
      res.pipe(file);
      file.on('finish', () => {
        file.close(() => {
          console.log(`Downloaded ${item.name}`);
          resolve();
        });
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
  console.log('All images downloaded!');
}

run().catch(console.error);
