const fs = require('fs');
const d = JSON.parse(fs.readFileSync('scratch_march_2026_us2_m2.json', 'utf8'));

const q17 = d.chapter.questions.find(x => x._id === '6a53cdfc4d554e04aa1bf832');
console.log("Q17 wrongAnswer:\n", q17.wrongAnswer);
