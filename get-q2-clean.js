const fs = require('fs');
const path = require('path');
const scratchDir = 'C:\\Users\\hp\\.gemini\\antigravity-ide\\brain\\871fe295-f0e4-4d4a-bbff-9bb437dccbc9\\scratch';
const data = JSON.parse(fs.readFileSync(path.join(scratchDir, 'basics_classified_questions.json'), 'utf8'));

data.forEach(subject => {
  subject.units?.forEach(unit => {
    unit.chapters?.forEach(chap => {
      if (chap.chapterName === 'Hard' && unit.unitName?.includes('Linear inequalities in one or two variables')) {
        const q = chap.questions[1];
        console.log('ID:', q._id);
        console.log('Question:', q.question);
        console.log('Choices:');
        q.wrongAnswer.forEach((c, idx) => {
          console.log(`Choice ${idx} [${String.fromCharCode(65+idx)}]:`, c);
        });
        console.log('CorrectAnswer:', q.correctAnswer);
        console.log('Explanation:', q.explanation);
      }
    });
  });
});
