const https = require('https');
const fs = require('fs');

const urls = [
  { name: 'june2_m1_q1_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785547969/questionPic/itswtyjm1hcgxtgoywja.png' },
  { name: 'june2_m1_q18_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785552951/questionPic/rzzzlmegvvmjmypxd06i.png' },
  { name: 'june2_m2_q7_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785553674/questionPic/cnxc6lx4t1u3t4am1cdi.png' },
  { name: 'june2_m2_q9_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785553800/questionPic/sj9s1ohmid4uyv7ddocn.png' },
  { name: 'june2_m2_q13_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785553991/questionPic/hhetccts6sxyc6nruot8.png' },
  { name: 'june2_m2_q15_orig.png', url: 'https://res.cloudinary.com/drxqzhgce/image/upload/v1785554157/questionPic/golgh1bse1li9tuuvapb.png' }
];

let completed = 0;
urls.forEach(u => {
  https.get(u.url, res => {
    const f = fs.createWriteStream(u.name);
    res.pipe(f);
    f.on('finish', () => {
      console.log('Downloaded', u.name);
      completed++;
      if (completed === urls.length) console.log('All 6 downloaded!');
    });
  });
});
