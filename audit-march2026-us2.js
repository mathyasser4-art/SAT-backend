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
        }

        if (q.typeOfAnswer === 'MCQ') {
            const choices = [q.correctAnswer, ...(q.wrongAnswer || [])];
            out += `CHOICES (${choices.length}):\n`;
            const letters = ['A', 'B', 'C', 'D', 'E'];
            choices.forEach((c, cIdx) => {
                const isCorrect = (c === q.correctAnswer);
                out += `  [${letters[cIdx]}] ${isCorrect ? '(CORRECT KEY) ' : ''}${simplifyHtml(c)}\n`;
            });
            out += `\nCORRECT ANSWER FIELD:\n${simplifyHtml(q.correctAnswer)}\n\n`;
        } else {
            out += `STUDENT-PRODUCED RESPONSE (GRID-IN / ESSAY):\n`;
            out += `ACCEPTED ANSWERS: ${JSON.stringify(q.answer || [])}\n\n`;
        }

        if (q.explanation) {
            out += `EXPLANATION:\n${simplifyHtml(q.explanation)}\n\n`;
        } else {
            out += `EXPLANATION: [None provided]\n\n`;
        }
    });

    fs.writeFileSync(outFilename, out, 'utf8');
    console.log(`Generated audit for ${moduleTitle} -> ${outFilename}`);
    return imagesToConvert;
}

const m1Images = auditModule('scratch_march_2026_us2_m1.json', 'MARCH 2026 · US 2 · MODULE 1', 'clean_march2026_us2_m1_detailed.txt');
const m2Images = auditModule('scratch_march_2026_us2_m2.json', 'MARCH 2026 · US 2 · MODULE 2', 'clean_march2026_us2_m2_detailed.txt');

fs.writeFileSync('march2026_us2_images_to_convert.json', JSON.stringify({ m1: m1Images, m2: m2Images }, null, 2), 'utf8');
console.log(`Found ${m1Images.length} images in M1, ${m2Images.length} images in M2.`);
