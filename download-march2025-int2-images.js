const https = require('https');
const fs = require('fs');
const path = require('path');

const images = [
  { mod: 'm1', num: 2, id: '6aa46bddec7ba02921a43ddd', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1789160412/questionPic/ozt48yybgxnlqxjngvyr.png' },
  { mod: 'm1', num: 3, id: '6aa46ca9ec7ba02921a43de1', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1789160616/questionPic/ynt2su5cvae19pal8v1g.png' },
  { mod: 'm1', num: 8, id: '6aa46dd4ec7ba02921a43df8', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1789160915/questionPic/ozsgwdvgt3evjvzvrkoh.png' },
  { mod: 'm1', num: 20, id: '6aa471cfec7ba02921a43e4d', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1789161934/questionPic/np88nosim1tptwtninsl.png' },
  { mod: 'm2', num: 1, id: '6aa4739cec7ba02921a43e64', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1789162626/questionPic/iranolanmsst7y9am6ir.png' },
  { mod: 'm2', num: 4, id: '6aa47536ec7ba02921a43e83', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1789162805/questionPic/iblq2pnj8amr5xzfvxb4.png' },
  { mod: 'm2', num: 12, id: '6aa47822ec7ba02921a43ece', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1789163554/questionPic/ic5ncyfjzplbkozu6blc.png' },
  { mod: 'm2', num: 16, id: '6aa4799eec7ba02921a43ee1', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1789163933/questionPic/hkhoba0wexglpvgnvx1l.png' }
];

const dir = path.join(__dirname, 'march2025_int2_raw_images');
if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

async function download(item) {
  const filename = `${item.mod}_q${item.num}_${item.id}.png`;
  const filePath = path.join(dir, filename);
  const file = fs.createWriteStream(filePath);
  return new Promise((resolve, reject) => {
    https.get(item.url, res => {
      res.pipe(file);
      file.on('finish', () => {
        file.close();
        console.log(`Downloaded ${filename}`);
        resolve();
      });
    }).on('error', err => {
      fs.unlink(filePath, () => {});
      reject(err);
    });
  });
}

async function run() {
  for (const item of images) {
    await download(item);
  }
  console.log('All 8 raw images downloaded successfully!');
}

run();
