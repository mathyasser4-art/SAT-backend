const https = require('https');
const fs = require('fs');
const path = require('path');

const dir = path.join(__dirname, 'march2026_int1_images');
if (!fs.existsSync(dir)) fs.mkdirSync(dir);

const list = [
  { name: 'm1_q1_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783826929/questionPic/tfq1glw74hsyujy7fwkg.png' },
  { name: 'm1_q5_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783840232/questionPic/kv3ag2nro3oukfadqqgg.png' },
  { name: 'm1_q8_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783840724/questionPic/tdh3w0b3mdvldmgttbq3.png' },
  { name: 'm2_q7_c1.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783846027/quill-images/qbyahqvmfubga1pxtjv1.png' },
  { name: 'm2_q7_c2.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783846075/quill-images/zqsjfdjxhkgsxmfb139i.png' },
  { name: 'm2_q7_c3.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783846104/quill-images/prtxg6bm0ribprhmt8p5.png' },
  { name: 'm2_q7_c4.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783846128/quill-images/ei8lnfeb5gw1hyasprys.png' },
  { name: 'm2_q22_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1783930040/questionPic/nccoqnkptn46ahlmjwj9.png' },
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
