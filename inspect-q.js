const fs = require('fs');
const path = require('path');
const scratchDir = 'C:\\Users\\hp\\.gemini\\antigravity-ide\\brain\\871fe295-f0e4-4d4a-bbff-9bb437dccbc9\\scratch';
const data = JSON.parse(fs.readFileSync(path.join(scratchDir, 'basics_classified_questions.json'), 'utf8'));

let matches = [];
data.forEach(subject => {
  subject.units?.forEach(unit => {
    unit.chapters?.forEach(chap => {
      chap.lessons?.forEach(les => {
        ['easy', 'medium', 'hard'].forEach(diff => {
          (les[diff] || []).forEach((q, idx) => {
            const txt = (q.questionText || '') + ' ' + JSON.stringify(q.wrongAnswer || []);
            if (txt.includes('Adam') || txt.includes('20-minute walk')) {
              matches.push({
                subject: subject.subjectName,
                unit: unit.unitName,
                chapter: chap.chapterName,
                lesson: les.lessonName,
                diff,
                index: idx + 1,
                id: q._id || q.id,
                questionText: q.questionText,
                wrongAnswer: q.wrongAnswer,
                correctAnswer: q.correctAnswer
              });
            }
          });
        });
      });
    });
  });
});

console.log(JSON.stringify(matches, null, 2));
