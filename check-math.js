const fs = require('fs');
const d = JSON.parse(fs.readFileSync('scratch_march_2026_us1_m1.json', 'utf8'));
d.chapter.questions.forEach(q => {
    const matches = q.question.match(/<span class="ql-formula"[^>]*>.*?<\/span>/g);
    if (matches) {
        matches.forEach(m => {
            if (m.indexOf('katex') === -1) {
                console.log(`Question ID: ${q._id}, Formula: ${m}`);
            }
        });
    }
});
