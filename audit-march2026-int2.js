const fs = require('fs');

const m1 = JSON.parse(fs.readFileSync('scratch_march_2026_int2_m1.json', 'utf8')).chapter.questions;
const m2 = JSON.parse(fs.readFileSync('scratch_march_2026_int2_m2.json', 'utf8')).chapter.questions;

function stripHtml(s) {
  if (!s) return '';
  s = s.replace(/<span class="ql-formula" data-value="([^"]+)">.*?<\/span>/gs, '$$$1$$');
  s = s.replace(/<[^>]+>/g, ' ');
  return s.replace(/&nbsp;/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim();
}

console.log('=== March 2026 · INT 2 Images ===');
[...m1.map((q, i) => ({ mod: 'M1', qNum: i+1, q })), ...m2.map((q, i) => ({ mod: 'M2', qNum: i+1, q }))].forEach(({ mod, qNum, q }) => {
  const str = JSON.stringify(q);
  const regex = /https:\/\/res\.cloudinary\.com[^"]+?\.(?:png|jpg|jpeg|webp)/g;
  const urls = [];
  let match;
  while ((match = regex.exec(str)) !== null) {
    urls.push(match[0]);
  }
  const unique = [...new Set(urls)];
  if (unique.length > 0 || q.questionPic) {
    console.log(`${mod} Q${qNum} (${q._id}):`);
    if (q.questionPic) console.log(`   questionPic: ${q.questionPic}`);
    unique.forEach(u => {
      if (u !== q.questionPic) console.log(`   inline: ${u}`);
    });
  }
});

function dumpModule(questions, modName, outFile) {
  let text = `====================================================\n`;
  text += `MARCH 2026 · INT 2 — ${modName} (${questions.length} QUESTIONS)\n`;
  text += `====================================================\n\n`;

  questions.forEach((q, idx) => {
    const num = idx + 1;
    text += `----------------------------------------------------\n`;
    text += `QUESTION ${num} | ID: ${q._id} | TYPE: ${q.typeOfAnswer}\n`;
    if (q.questionPic) text += `IMAGE: ${q.questionPic}\n`;
    text += `STEM:\n${stripHtml(q.question)}\n\n`;

    if (q.typeOfAnswer === 'MCQ') {
      text += `CORRECT ANSWER:\n${stripHtml(q.correctAnswer)}\n\n`;
      text += `WRONG ANSWERS (${(q.wrongAnswer || []).length}):\n`;
      (q.wrongAnswer || []).forEach((w, wIdx) => {
        text += `  [${wIdx + 1}] ${stripHtml(w)}\n`;
      });
    } else {
      text += `CORRECT GRID-IN / ESSAY ANSWER:\n${JSON.stringify(q.answer)}\n`;
    }
    text += `\n`;
  });

  fs.writeFileSync(outFile, text, 'utf8');
  console.log(`Saved ${outFile}`);
}

dumpModule(m1, 'MODULE 1', 'clean_march2026_int2_m1_detailed.txt');
dumpModule(m2, 'MODULE 2', 'clean_march2026_int2_m2_detailed.txt');
