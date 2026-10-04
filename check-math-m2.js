const fs = require('fs');
const d = JSON.parse(fs.readFileSync('scratch_march_2026_us1_m2.json', 'utf8'));
d.chapter.questions.forEach(q => {
    // Check in question stem
    let matches = q.question.match(/<span class="ql-formula"[^>]*>.*?<\/span>/g);
    if (matches) {
        matches.forEach(m => {
            if (m.indexOf('katex') === -1) {
                console.log(`Stem empty formula in Question ID: ${q._id}, Formula: ${m}`);
            }
        });
    }
    // Check in choices
    if (q.wrongAnswer) {
        q.wrongAnswer.forEach(ans => {
            let ansMatches = ans.match(/<span class="ql-formula"[^>]*>.*?<\/span>/g);
            if (ansMatches) {
                ansMatches.forEach(m => {
                    if (m.indexOf('katex') === -1) {
                        console.log(`Choice empty formula in Question ID: ${q._id}, Formula: ${m}`);
                    }
                });
            }
        });
    }
});
