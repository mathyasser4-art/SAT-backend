const fs = require('fs');
const path = require('path');
const scratchDir = 'C:\\Users\\hp\\.gemini\\antigravity-ide\\brain\\871fe295-f0e4-4d4a-bbff-9bb437dccbc9\\scratch';
const data = JSON.parse(fs.readFileSync(path.join(scratchDir, 'basics_classified_questions.json'), 'utf8'));

data.forEach(subject => {
  subject.units?.forEach(unit => {
    unit.chapters?.forEach(chap => {
      console.log(`${subject.subjectName} > ${unit.unitName} > ${chap.chapterName} (questions: ${chap.questions?.length || 0})`);
    });
  });
});
