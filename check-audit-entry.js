const fs = require('fs');
const path = require('path');
const scratchDir = 'C:\\Users\\hp\\.gemini\\antigravity-ide\\brain\\871fe295-f0e4-4d4a-bbff-9bb437dccbc9\\scratch';
const audit = JSON.parse(fs.readFileSync(path.join(scratchDir, 'corrected_audit.json'), 'utf8'));

const dupes = audit.filter(x => (x.issues || []).some(iss => iss.type === 'DUPLICATE CHOICES'));
console.log('Total DUPLICATE CHOICES:', dupes.length);
dupes.forEach(d => {
  console.log(`- ${d.lesson} (${d.difficulty}) Q${d.questionNumber} ID:${d.questionId}`);
  console.log('  Issues:', JSON.stringify(d.issues));
  console.log('  WrongAnswer:', JSON.stringify(d.wrongAnswer));
  console.log('  CorrectAnswer:', JSON.stringify(d.correctAnswer));
});
