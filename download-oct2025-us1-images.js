const https = require('https');
const fs = require('fs');
const path = require('path');

const imgDir = path.join(__dirname, 'oct2025_us1_images');
if (!fs.existsSync(imgDir)) {
  fs.mkdirSync(imgDir, { recursive: true });
}

const images = [
  { mod: 'm1', qNum: 6,  id: '6a665b96c3d08d90637d3a26', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785093014/questionPic/klimoj4q6gntad172bud.png' },
  { mod: 'm1', qNum: 15, id: '6a665e3dc3d08d90637d3a4e', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785093692/questionPic/ytv0pgot0adl6n72hj49.png' },
  { mod: 'm1', qNum: 16, id: '6a665e73c3d08d90637d3a52', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785093747/questionPic/bv7poqgpec5dg9xyizms.png' },
  { mod: 'm1', qNum: 18, id: '6a665f19c3d08d90637d3a62', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785093913/questionPic/zttomfrgsz3vaudhayzi.png' },
  { mod: 'm1', qNum: 21, id: '6a6660f6c3d08d90637d3a70', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785094389/questionPic/c09rw9tsicya59xgnqwk.png' },
  { mod: 'm2', qNum: 3,  id: '6a667416c3d08d90637d3a96', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785099284/questionPic/hu8ctgjrzzgny0iuujko.png' },
  { mod: 'm2', qNum: 6,  id: '6a66749ac3d08d90637d3aa2', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785099417/questionPic/jd8et8dywl6af1adlbuj.png' }
];

function download(url, dest) {
  return new Promise((resolve, reject) => {
    https.get(url, res => {
      const fileStream = fs.createWriteStream(dest);
      res.pipe(fileStream);
      fileStream.on('finish', () => {
        fileStream.close();
        resolve();
      });
    }).on('error', reject);
  });
}

async function run() {
  for (const item of images) {
    const filename = `${item.mod}_q${item.qNum}_orig.png`;
    const dest = path.join(imgDir, filename);
    process.stdout.write(`Downloading ${filename}... `);
    await download(item.url, dest);
    console.log('✅');
  }
}

run().catch(console.error);
