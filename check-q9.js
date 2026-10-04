const fs = require('fs');
const d = JSON.parse(fs.readFileSync('scratch_march_2026_us2_m1.json', 'utf8'));
const q = d.chapter.questions.find(q=>q._id==='6a52e3b64d554e04aa1bf41e');
const matches = q.question.match(/data-value="([^"]+)"/g);
console.log(matches);
