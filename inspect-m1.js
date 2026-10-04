const fs = require('fs');

const data = JSON.parse(fs.readFileSync('scratch_dec_2025_us1_m1.json', 'utf8'));
const qs = data.chapter.questions;

let out = 'Total Questions: ' + qs.length + '\n';

qs.forEach((q, idx) => {
    out += '\n================== Q' + (idx + 1) + ' (ID: ' + q._id + ') [' + q.typeOfAnswer + '] ==================\n';
    out += 'Stem:\n' + q.question + '\n';
    if (q.answers && q.answers.length > 0) {
        out += 'Options:\n';
        q.answers.forEach((a, aIdx) => {
            const letter = String.fromCharCode(65 + aIdx);
            out += '  ' + letter + '. [isCorrect: ' + a.isCorrect + '] ' + a.answer + '\n';
        });
    }
    out += 'answer: ' + q.answer + '\n';
    out += 'correctAnswer: ' + q.correctAnswer + '\n';
    if (q.explanation) out += 'Explanation: ' + q.explanation + '\n';
    if (q.image) out += 'Image: ' + q.image + '\n';
});

fs.writeFileSync('inspect-m1-output.txt', out, 'utf8');
console.log('Written to inspect-m1-output.txt');

