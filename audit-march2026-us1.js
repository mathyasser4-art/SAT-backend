const fs = require('fs');

function cleanHtml(html) {
    if (!html) return '';
    return html
        .replace(/<span class="ql-formula" data-value="([^"]+)">.*?<\/span>/g, '$1')
        .replace(/<span class="ql-formula" data-value="([^"]+)">/g, '$1')
        .replace(/<[^>]+>/g, ' ')
        .replace(/&nbsp;/g, ' ')
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/\s+/g, ' ')
        .trim();
}

function auditModule(filePath, modName, outFilePath) {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const questions = data.chapter?.questions || [];
    let out = [];

    out.push('='.repeat(80));
    out.push(`MARCH 2026 · US 1 · ${modName.toUpperCase()} - AUDIT & REVISION`);
    out.push(`Total Questions: ${questions.length}`);
    out.push('='.repeat(80) + '\n');

    questions.forEach((q, idx) => {
        const qNum = idx + 1;
        out.push('-'.repeat(80));
        out.push(`QUESTION ${qNum} | Type: ${q.typeOfAnswer} | ID: ${q._id}`);
        out.push('-'.repeat(80));

        const cleanStem = cleanHtml(q.question);
        out.push(`STEM:\n${cleanStem}\n`);

        if (q.questionPic) {
            out.push(`QUESTION PIC: ${q.questionPic}\n`);
        }

        if (q.typeOfAnswer === 'MCQ') {
            out.push(`CHOICES (${q.wrongAnswer?.length || 0}):`);
            const correctClean = cleanHtml(q.correctAnswer);
            (q.wrongAnswer || []).forEach((c, cIdx) => {
                const letter = String.fromCharCode(65 + cIdx);
                const choiceClean = cleanHtml(c);
                const isCorrect = choiceClean === correctClean;
                out.push(`  [${letter}] ${isCorrect ? '(CORRECT KEY) ' : ''}${choiceClean}`);
            });
            out.push(`\nCORRECT ANSWER FIELD:\n${correctClean}\n`);
        } else {
            out.push(`STUDENT-PRODUCED RESPONSE (GRID-IN / ESSAY):`);
            out.push(`ACCEPTED ANSWERS: ${JSON.stringify(q.answer || [])}\n`);
        }

        const expClean = cleanHtml(q.explanation);
        out.push(`EXPLANATION: ${expClean ? expClean : '[None provided]'}\n`);
    });

    fs.writeFileSync(outFilePath, out.join('\n'));
    console.log(`Saved audit: ${outFilePath}`);
}

auditModule('scratch_march_2026_us1_m1.json', 'Module 1', 'clean_march2026_us1_m1_detailed.txt');
auditModule('scratch_march_2026_us1_m2.json', 'Module 2', 'clean_march2026_us1_m2_detailed.txt');
