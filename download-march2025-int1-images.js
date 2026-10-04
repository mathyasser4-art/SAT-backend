const https = require('https');
const fs = require('fs');
const path = require('path');

const images = [
  { name: 'm1_q1_ngiozpqngfku6ky8qaxt.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788933114/questionPic/ngiozpqngfku6ky8qaxt.png' },
  { name: 'm1_q8_itdj2n54221a8qmxhxaa.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788934025/questionPic/itdj2n54221a8qmxhxaa.png' },
  { name: 'm1_q21_nbrft9ha0k138d8wdq7w.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788936199/questionPic/nbrft9ha0k138d8wdq7w.png' },
  { name: 'm2_q17_yptizzuhemndsmdas0jo.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788944505/questionPic/yptizzuhemndsmdas0jo.png' },
  { name: 'm2_q18_zd8auxwu8lziyb0vtoxr.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1788944473/questionPic/zd8auxwu8lziyb0vtoxr.png' }
];

const dir = path.join(__dirname, 'march2025_int1_raw_images');
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
