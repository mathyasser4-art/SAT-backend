const fs = require('fs');

const data = JSON.parse(fs.readFileSync('scratch_dec_2025_us1_m2.json', 'utf8'));
const qs = data.chapter.questions;

function simplifyHtml(str) {
    if (!str) return '';
    let s = String(str);
    s = s.replace(/<span[^>]*class="ql-formula"[^>]*data-value="([^"]*)"[^>]*>.*?<\/span>[\uFEFF]?<\/span>/gs, '$1');
    s = s.replace(/<span class="katex">.*?<\/span><\/span>/gs, '');
    s = s.replace(/<\/p>/gi, '\n').replace(/<br\s*\/?>/gi, '\n');
    s = s.replace(/<[^>]+>/g, '');
    s = s.replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/\uFEFF/g, '');
    return s.replace(/[ \t]+/g, ' ').replace(/\n\s*\n/g, '\n').trim();
}

let out = `================================================================================\n`;
out += `DECEMBER 2025 · US 1 · MODULE 2 - AUDIT & REVISION\n`;
out += `Total Questions: ${qs.length}\n`;
out += `================================================================================\n\n`;

qs.forEach((q, idx) => {
    const qNum = idx + 1;
    out += `--------------------------------------------------------------------------------\n`;
    out += `QUESTION ${qNum} | Type: ${q.typeOfAnswer} | ID: ${q._id}\n`;
    out += `--------------------------------------------------------------------------------\n`;
    out += `STEM:\n${simplifyHtml(q.question)}\n\n`;
    
    // Check raw stem for corruption
    if ((q.question || '').includes('>p>>span') || (q.question || '').includes('>>math') || (q.question || '').includes('\uFFFD')) {
        out += `⚠️ CORRUPTED STRING / HTML DETECTED IN STEM!\n\n`;
    }

    if (q.questionPic) {
        out += `QUESTION PIC: ${q.questionPic}\n\n`;
    } else {
        const mentionsVisual = /(figure|graph|scatterplot|shown|triangle|shaded region|circle)/i.test(q.question || '');
        if (mentionsVisual) {
            out += `⚠️ VISUAL MENTIONED IN STEM BUT NO questionPic ATTACHED!\n\n`;
        }
    }

    if (q.typeOfAnswer === 'MCQ') {
        const choices = q.wrongAnswer || [];
        out += `CHOICES (${choices.length}):\n`;
        const seen = new Set();
        choices.forEach((c, cIdx) => {
            const letter = String.fromCharCode(65 + cIdx);
            const isMatch = simplifyHtml(c) === simplifyHtml(q.correctAnswer);
            const cleanC = simplifyHtml(c);
            out += `  [${letter}] ${isMatch ? '(CORRECT KEY) ' : ''}${cleanC}\n`;
            if ((c || '').includes('>p>>span') || (c || '').includes('>>math') || (c || '').includes('\uFFFD')) {
                out += `      ⚠️ CORRUPTED STRING / HTML IN CHOICE ${letter}!\n`;
            }
            if (seen.has(cleanC)) {
                out += `      ⚠️ DUPLICATE CHOICE DETECTED (${letter})!\n`;
            }
            seen.add(cleanC);
        });
        out += `\nCORRECT ANSWER FIELD:\n${simplifyHtml(q.correctAnswer)}\n`;
        
        const matchesAny = choices.some(c => simplifyHtml(c) === simplifyHtml(q.correctAnswer));
        if (!matchesAny) {
            out += `⚠️ CORRECT ANSWER DOES NOT MATCH ANY OF THE 4 CHOICES!\n`;
        }
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

fs.writeFileSync('clean_m2_detailed.txt', out, 'utf8');
console.log('Saved clean_m2_detailed.txt');
