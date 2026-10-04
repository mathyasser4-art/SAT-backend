const https = require('https');
const fs = require('fs');

const d = JSON.parse(fs.readFileSync('scratch_march_2026_us2_m1.json', 'utf8'));

const q7 = d.chapter.questions.find(x => x._id === '6a52e25a4d554e04aa1bf40c');
console.log("Q7 STEM:\n", q7.question);

const q9 = d.chapter.questions.find(x => x._id === '6a52e3b64d554e04aa1bf41e');
console.log("Q9 STEM:\n", q9.question);
