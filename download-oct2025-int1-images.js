const https = require('https');
const fs = require('fs');
const path = require('path');

const imgDir = path.join(__dirname, 'oct2025_int1_images');
if (!fs.existsSync(imgDir)) {
  fs.mkdirSync(imgDir, { recursive: true });
}

const images = [
  { mod: 'm1', qNum: 7,  id: '6a624efbc3d08d90637d3667', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1784827643/questionPic/cpkn0dlphde4owxbvjdz.png' },
  { mod: 'm1', qNum: 12, id: '6a663e59c3d08d90637d3904', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785085529/questionPic/xtnuzasm7c8hquvlyzf1.png' },
  { mod: 'm2', qNum: 3,  id: '6a6644f2c3d08d90637d3955', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785087218/questionPic/le3afvp6harxkjms439p.png' },
  { mod: 'm2', qNum: 20, id: '6a665878c3d08d90637d39d1', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785092216/questionPic/jwcys2uygrzkxdzcf4rm.png' },
  { mod: 'm2', qNum: 21, id: '6a6658e9c3d08d90637d39d5', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785092329/questionPic/phjivilm2c0pekwukahe.png' }
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
