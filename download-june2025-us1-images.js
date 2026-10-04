const https = require('https');
const fs = require('fs');
const path = require('path');

const images = [
  { name: 'm1_q15.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785595976/questionPic/klgm6ttyfnb0qw6nuaw4.png' },
  { name: 'm1_q17.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785596290/questionPic/s82r4ihpji2qajxom5wn.png' },
  { name: 'm1_q19.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785596466/questionPic/s37cn7gifnhinm9euz2w.png' },
  { name: 'm1_q22.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785597698/questionPic/dl8o7g2qlblledfw1eyk.png' },
  { name: 'm2_q1.png',  url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785597831/questionPic/exnxosaeayhuuuu9ne4n.png' },
  { name: 'm2_q2.png',  url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785597979/questionPic/n8kmuzebtwksvglbdncl.png' },
  { name: 'm2_q6.png',  url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785598247/questionPic/yn7ykhrhhaiehjagzemc.png' },
  { name: 'm2_q10.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785598972/questionPic/bs2hgv0oqgfdyksid1gg.png' },
  { name: 'm2_q17.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785601394/questionPic/dqjha0noenxf0biqll4t.png' }
];

const dir = path.join(__dirname, 'raw_june2025_us1_images');
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
