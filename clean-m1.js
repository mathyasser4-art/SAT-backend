const fs = require('fs');

const data = JSON.parse(fs.readFileSync('scratch_dec_2025_us1_m1.json', 'utf8'));
const qs = data.chapter.questions;

function simplifyHtml(str) {
    if (!str) return '';
    let s = String(str);
    // Extract KaTeX latex formula from data-value if present
    s = s.replace(/<span[^>]*class="ql-formula"[^>]*data-value="([^"]*)"[^>]*>.*?<\/span>[\uFEFF]?<\/span>/gs, '$1');
    s = s.replace(/<span class="katex">.*?<\/span><\/span>/gs, '');
    s = s.replace(/<\/p>/gi, '\n').replace(/<br\s*\/?>/gi, '\n');
    s = s.replace(/<[^>]+>/g, '');
    s = s.replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/\uFEFF/g, '');
    return s.replace(/[ \t]+/g, ' ').replace(/\n\s*\n/g, '\n').trim();
}

let out = `================================================================================\n`;
out += `DECEMBER 2025 · US 1 · MODULE 1 - AUDIT & REVISION\n`;
out += `Total Questions: ${qs.length}\n`;
out += `================================================================================\n\n`;

qs.forEach((q, idx) => {
    const qNum = idx + 1;
    out += `--------------------------------------------------------------------------------\n`;
    out += `QUESTION ${qNum} | Type: ${q.typeOfAnswer} | ID: ${q._id}\n`;
    out += `--------------------------------------------------------------------------------\n`;
    out += `STEM:\n${simplifyHtml(q.question)}\n\n`;
    
    // Check raw for corruption
    if ((q.question || '').includes('>p>>span') || (q.question || '').includes('>>math')) {
        out += `⚠️ CORRUPTED HTML DETECTED IN STEM!\n\n`;
    }

    if (q.image) {
        out += `IMAGE: ${q.image}\n\n`;
    }

    if (q.typeOfAnswer === 'MCQ') {
        const choices = q.wrongAnswer || [];
        out += `CHOICES (${choices.length}):\n`;
        choices.forEach((c, cIdx) => {
            const letter = String.fromCharCode(65 + cIdx);
            const isMatch = simplifyHtml(c) === simplifyHtml(q.correctAnswer);
            out += `  [${letter}] ${isMatch ? '(CORRECT KEY) ' : ''}${simplifyHtml(c)}\n`;
            if ((c || '').includes('>p>>span') || (c || '').includes('>>math')) {
                out += `      ⚠️ CORRUPTED HTML IN CHOICE ${letter}!\n`;
            }
        });
        out += `\nCORRECT ANSWER FIELD:\n${simplifyHtml(q.correctAnswer)}\n`;
    } else {
        out += `STUDENT-PRODUCED RESPONSE (GRID-IN / ESSAY):\n`;
        out += `ACCEPTED ANSWERS: ${JSON.stringify(q.answer)}\n`;
    }

    if (q.explanation && simplifyHtml(q.explanation)) {
        out += `\nEXPLANATION:\n${simplifyHtml(q.explanation)}\n`;
    } else {
        out += `\nEXPLANATION: [None provided]\n`;
    }

    out += `\n`;
});

fs.writeFileSync('clean_m1_detailed.txt', out, 'utf8');
console.log('Saved clean_m1_detailed.txt');
