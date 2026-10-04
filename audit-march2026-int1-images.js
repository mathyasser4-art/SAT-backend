const fs = require('fs');

const m1 = JSON.parse(fs.readFileSync('scratch_march_2026_int1_m1.json', 'utf8')).chapter.questions;
const m2 = JSON.parse(fs.readFileSync('scratch_march_2026_int1_m2.json', 'utf8')).chapter.questions;

function findImages(questions, modName) {
  questions.forEach((q, idx) => {
    const qNum = idx + 1;
    const str = JSON.stringify(q);
    const regex = /https:\/\/res\.cloudinary\.com[^"]+?\.(?:png|jpg|jpeg|webp)/g;
    const urls = [];
    let match;
    while ((match = regex.exec(str)) !== null) {
      urls.push(match[0]);
    }
    const unique = [...new Set(urls)];
    if (unique.length > 0) {
      console.log(`${modName} Q${qNum} (${q._id}):`);
      unique.forEach(u => console.log('   ' + u));
    }
  });
}

findImages(m1, 'M1');
findImages(m2, 'M2');
