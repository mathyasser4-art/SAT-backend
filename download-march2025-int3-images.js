const https = require('https');
const fs = require('fs');
const path = require('path');

const images = [
  { mod: 'm1', num: 2, id: '6aa47cdbec7ba02921a43f3c', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1789164762/questionPic/aa0i8xzr0oaqfppkvrzx.png' },
  { mod: 'm1', num: 10, id: '6aa47ec1ec7ba02921a43f5c', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1789165248/questionPic/kv5h0v5xkii7e1e8zg4v.png' },
  { mod: 'm1', num: 11, id: '6aa47fc5ec7ba02921a43f60', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1789165509/questionPic/hkgn4pu40rzd7gke1q59.png' },
  { mod: 'm1', num: 16, id: '6aa48173ec7ba02921a43f7a', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1789165939/questionPic/lqmmfedho1mb6gfksgof.png' },
  { mod: 'm1', num: 19, id: '6aa48223ec7ba02921a43f89', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1789166114/questionPic/gelt2rap21o93u0791tp.png' },
  { mod: 'm2', num: 10, id: '6aa48996ec7ba02921a4402a', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1789168145/questionPic/otgt8kvpzi0fvsts9cxs.png' },
  { mod: 'm2', num: 12, id: '6aa48a93ec7ba02921a44046', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1789168274/questionPic/js9elhdlblasruiqihex.png' },
  { mod: 'm2', num: 15, id: '6aa48ca2ec7ba02921a4405e', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1789168802/questionPic/v1sjqhvjzcsidds6ao6k.png' }
];

const dir = path.join(__dirname, 'march2025_int3_raw_images');
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
  console.log('All 8 raw images downloaded successfully for March 2025 INT 3!');
}

run();
