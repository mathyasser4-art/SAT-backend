const fs = require('fs');
const m1 = JSON.parse(fs.readFileSync('scratch_march_2026_us2_m1.json', 'utf8')).chapter.questions;
const m2 = JSON.parse(fs.readFileSync('scratch_march_2026_us2_m2.json', 'utf8')).chapter.questions;

let out = '';

function inspectQ(modName, qNum, q) {
  out += `\n==================== ${modName} Q${qNum} (${q._id}) ====================\n`;
  out += `TYPE: ${q.typeOfAnswer}\n`;
  out += `STEM:\n${q.question}\n`;
  out += `CORRECT ANSWER: ${q.correctAnswer}\n`;
  out += `WRONG ANSWERS: ${JSON.stringify(q.wrongAnswer, null, 2)}\n`;
  out += `ESSAY ANSWERS: ${JSON.stringify(q.answer, null, 2)}\n`;
  out += `QUESTION PIC: ${q.questionPic}\n`;
}

// Let's inspect all questions that looked strange
inspectQ('M1', 1, m1[0]);
inspectQ('M1', 7, m1[6]);
inspectQ('M1', 8, m1[7]);
inspectQ('M1', 9, m1[8]);
inspectQ('M1', 14, m1[13]);
inspectQ('M1', 19, m1[18]);
inspectQ('M2', 6, m2[5]);
inspectQ('M2', 8, m2[7]);
inspectQ('M2', 9, m2[8]);
inspectQ('M2', 10, m2[9]);
inspectQ('M2', 16, m2[15]);
inspectQ('M2', 17, m2[16]);
inspectQ('M2', 18, m2[17]);
inspectQ('M2', 21, m2[20]);

fs.writeFileSync('inspect_march2026_us2.txt', out, 'utf8');
console.log('Saved inspect_march2026_us2.txt');
