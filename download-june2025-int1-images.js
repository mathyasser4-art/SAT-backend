const https = require('https');
const fs = require('fs');

const urls = [
  { name: 'june2025_m1_q1_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785539325/questionPic/jlul5miqrzcrfsqu3wrc.png' },
  { name: 'june2025_m1_q7_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785540237/questionPic/rpfo5ijmhoneehzlejdu.png' },
  { name: 'june2025_m1_q18_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785543994/questionPic/hh3ykgtmnrjfeid1lipv.png' },
  { name: 'june2025_m2_q5_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785544819/questionPic/neikbrox3p0autq7njgz.png' },
  { name: 'june2025_m2_q7_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785545012/questionPic/ug1p8m48mrgwqlrscq3l.png' }
];

let completed = 0;
urls.forEach(u => {
  https.get(u.url, res => {
    const f = fs.createWriteStream(u.name);
    res.pipe(f);
    f.on('finish', () => {
      console.log('Downloaded', u.name);
      completed++;
      if (completed === urls.length) console.log('All 5 downloaded!');
    });
  });
});
