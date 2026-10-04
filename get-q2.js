const fs = require('fs');
const path = require('path');
const scratchDir = 'C:\\Users\\hp\\.gemini\\antigravity-ide\\brain\\871fe295-f0e4-4d4a-bbff-9bb437dccbc9\\scratch';
const data = JSON.parse(fs.readFileSync(path.join(scratchDir, 'basics_classified_questions.json'), 'utf8'));

data.forEach(subject => {
  subject.units?.forEach(unit => {
    unit.chapters?.forEach(chap => {
      if (chap.chapterName === 'Hard' && unit.unitName?.includes('Linear inequalities in one or two variables')) {
        console.log(`FOUND: ${subject.subjectName} > ${unit.unitName} > ${chap.chapterName}`);
        const q = chap.questions[1]; // Q2
        console.log('Q2 Object:');
        console.log(JSON.stringify(q, null, 2));
      }
    });
  });
});
