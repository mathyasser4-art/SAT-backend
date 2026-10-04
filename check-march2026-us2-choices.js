const fs = require('fs');

['scratch_march_2026_us2_m1.json', 'scratch_march_2026_us2_m2.json'].forEach(file => {
  console.log('=== Checking', file, '===');
  const d = JSON.parse(fs.readFileSync(file, 'utf8'));
  let issues = 0;
  d.chapter.questions.forEach((q, i) => {
    if (q.typeOfAnswer === 'MCQ') {
      const waCount = (q.wrongAnswer || []).length;
      const hasDuplicate = (q.wrongAnswer || []).some(w => w === q.correctAnswer);
      if (waCount !== 3 || hasDuplicate) {
        issues++;
        console.log('Q' + (i+1) + ' (' + q._id + '): wrongAnswer has ' + waCount + ' items. Duplicate of correctAnswer: ' + hasDuplicate);
      }
    }
  });
  console.log('Total MCQ issues in ' + file + ': ' + issues + '\n');
});
