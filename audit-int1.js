const fs = require('fs');

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

function auditModule(filename, moduleTitle, outFilename) {
    const data = JSON.parse(fs.readFileSync(filename, 'utf8'));
    const qs = data.chapter.questions;

    let out = `================================================================================\n`;
    out += `${moduleTitle} - AUDIT & REVISION\n`;
    out += `Total Questions: ${qs.length}\n`;
    out += `================================================================================\n\n`;

    const imagesToConvert = [];

    qs.forEach((q, idx) => {
        const qNum = idx + 1;
        out += `--------------------------------------------------------------------------------\n`;
        out += `QUESTION ${qNum} | Type: ${q.typeOfAnswer} | ID: ${q._id}\n`;
        out += `--------------------------------------------------------------------------------\n`;
        out += `STEM:\n${simplifyHtml(q.question)}\n\n`;
        
        // Corrupted HTML check
        if ((q.question || '').includes('>p>>span') || (q.question || '').includes('>>math') || (q.question || '').includes('\uFFFD')) {
            out += `⚠️ CORRUPTED STRING / HTML DETECTED IN STEM!\n`;
            out += `RAW STEM: ${q.question}\n\n`;
        }

        if (q.questionPic) {
            out += `QUESTION PIC: ${q.questionPic}\n\n`;
            imagesToConvert.push({ qNum, id: q._id, pic: q.questionPic });
        } else {
            const mentionsVisual = /(figure|graph|scatterplot|shown|triangle|shaded region|circle)/i.test(q.question || '');
            if (mentionsVisual) {
                out += `⚠️ VISUAL MENTIONED IN STEM BUT NO questionPic ATTACHED!\n\n`;
            }
        }

        if (q.typeOfAnswer === 'MCQ') {
            const choices = q.wrongAnswer || [];
            out += `CHOICES (${choices.length}):\n`;
            choices.forEach((c, cIdx) => {
                const letter = String.fromCharCode(65 + cIdx);
                const isCorrect = c === q.correctAnswer;
                out += `  [${letter}] ${isCorrect ? '(CORRECT KEY) ' : ''}${simplifyHtml(c)}\n`;
            });
            out += `\nCORRECT ANSWER FIELD:\n${simplifyHtml(q.correctAnswer)}\n\n`;
        } else {
            out += `STUDENT-PRODUCED RESPONSE (GRID-IN / ESSAY):\n`;
            out += `ACCEPTED ANSWERS: ${JSON.stringify(q.answer)}\n\n`;
        }

        out += `EXPLANATION: ${q.explanation ? simplifyHtml(q.explanation).substring(0, 100) + '...' : '[None provided]'}\n\n`;
    });

    fs.writeFileSync(outFilename, out);
    console.log(`Saved audit to ${outFilename}`);
    return imagesToConvert;
}

const m1Images = auditModule('scratch_dec_2025_int1_m1.json', 'DECEMBER 2025 · INT 1 · MODULE 1', 'clean_int1_m1_detailed.txt');
const m2Images = auditModule('scratch_dec_2025_int1_m2.json', 'DECEMBER 2025 · INT 1 · MODULE 2', 'clean_int1_m2_detailed.txt');

console.log('\n--- IMAGES IN MODULE 1 ---');
console.log(JSON.stringify(m1Images, null, 2));

console.log('\n--- IMAGES IN MODULE 2 ---');
console.log(JSON.stringify(m2Images, null, 2));
