const fs = require('fs');
const exams = JSON.parse(fs.readFileSync('./real_exams_by_exam.json', 'utf8'));
console.log('Total exams:', exams.length);
exams.forEach((e, i) => {
  const m1 = e.chapters?.[0]?.chapterId || 'N/A';
  const m2 = e.chapters?.[1]?.chapterId || 'N/A';
  console.log(`${i + 1}. ${e.examName} (${e.examId}) | M1: ${m1} | M2: ${m2}`);
});
