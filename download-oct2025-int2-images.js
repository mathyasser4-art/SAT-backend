const https = require('https');
const fs = require('fs');
const path = require('path');

const imgDir = path.join(__dirname, 'oct2025_int2_images');
if (!fs.existsSync(imgDir)) {
  fs.mkdirSync(imgDir, { recursive: true });
}

const images = [
  { mod: 'm1', qNum: 12, id: '6a627762c3d08d90637d370c', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1784837985/questionPic/f7ophwrepuppr9xecvgs.png' },
  { mod: 'm2', qNum: 3,  id: '6a628d9fc3d08d90637d37be', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1784843679/questionPic/tekjxl2gspghwxwsddwj.png' },
  { mod: 'm2', qNum: 5,  id: '6a628f63c3d08d90637d37d2', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1784844130/questionPic/chs3qe8zkdqe0oawsizq.png' },
  { mod: 'm2', qNum: 13, id: '6a6297e0c3d08d90637d3840', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1784846303/questionPic/klxcbgrdrqeprwcjw09d.png' },
  { mod: 'm2', qNum: 18, id: '6a629d10c3d08d90637d386c', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1784847631/questionPic/aa6nefpswcpkprtqxezf.png' },
  { mod: 'm2', qNum: 19, id: '6a6638f3c3d08d90637d38a1', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785085371/questionPic/nfqyotomeeuyft9tnlkf.png' }
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
