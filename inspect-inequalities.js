const fs = require('fs');
const path = require('path');
const scratchDir = 'C:\\Users\\hp\\.gemini\\antigravity-ide\\brain\\871fe295-f0e4-4d4a-bbff-9bb437dccbc9\\scratch';
const data = JSON.parse(fs.readFileSync(path.join(scratchDir, 'basics_classified_questions.json'), 'utf8'));

data.forEach(subject => {
  subject.units?.forEach(unit => {
    unit.chapters?.forEach(chap => {
      if (chap.chapterName?.toLowerCase().includes('inequalities')) {
        console.log(`Found chapter: ${subject.subjectName} > ${unit.unitName} > ${chap.chapterName}`);
        (chap.questions || []).forEach((q, idx) => {
          if (idx === 1) { // Q2
            console.log('Q2:');
            console.log('Question:', q.question);
            console.log('WrongAnswer:', JSON.stringify(q.wrongAnswer, null, 2));
            console.log('CorrectAnswer:', q.correctAnswer);
          }
        });
      }
    });
  });
});
