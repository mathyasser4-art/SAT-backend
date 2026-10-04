const fs = require('fs');
const data = JSON.parse(fs.readFileSync('scratch_dec_2025_us1_m1.json', 'utf8'));
const qs = data.chapter.questions;

qs.forEach((q, i) => {
  const hasPic = !!q.questionPic;
  const mentionsVisual = /(figure|graph|scatterplot|shown|triangle|shaded region)/i.test(q.question);
  console.log('Q' + (i+1) + ': mentionsVisual=' + mentionsVisual + ', questionPic=' + (q.questionPic || 'NONE'));
});

