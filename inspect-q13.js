const fs = require('fs');
const data = JSON.parse(fs.readFileSync('scratch_dec_2025_us1_m1.json', 'utf8'));
const q13 = data.chapter.questions[12];

console.log('=== Q13 RAW QUESTION ===');
console.log(q13.question);

console.log('\n=== Q13 STEM FORMULAS ===');
const re = /data-value="([^"]+)"/g;
let m;
while ((m = re.exec(q13.question)) !== null) {
  console.log('Stem formula:', m[1]);
}

console.log('\n=== Q13 OPTIONS ===');
q13.wrongAnswer.forEach((w, i) => {
  console.log(`Option ${i}:`);
  let wm;
  const re2 = /data-value="([^"]+)"/g;
  while ((wm = re2.exec(w)) !== null) {
    console.log('  Formula:', wm[1]);
  }
});
