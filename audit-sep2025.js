const fs = require('fs');

const stripHtml = (str) => {
    if (!str) return '';
    return str.replace(/<[^>]+>/g, '')
              .replace(/&nbsp;/g, ' ')
              .replace(/&amp;/g, '&')
              .replace(/&lt;/g, '<')
              .replace(/&gt;/g, '>')
              .replace(/﻿/g, '')
              .replace(/\s+/g, ' ')
              .trim();
};

function auditModule(jsonPath, modTitle, outPath) {
    const raw = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
    const questions = raw.chapter?.questions || [];
    
    let report = [];
    report.push(`================================================================================`);
    report.push(`${modTitle} - AUDIT & REVISION`);
    report.push(`Total Questions: ${questions.length}`);
    report.push(`================================================================================\n`);

    const imageQuestions = [];

    questions.forEach((q, idx) => {
        const qNum = idx + 1;
        const stemClean = stripHtml(q.questionText || q.question);
        const pic = typeof q.questionPic === 'string' ? q.questionPic : (q.questionPic?.secure_url || '');

        report.push(`--------------------------------------------------------------------------------`);
        report.push(`QUESTION ${qNum} | Type: ${q.typeOfAnswer} | ID: ${q._id}`);
        report.push(`--------------------------------------------------------------------------------`);
        report.push(`STEM:\n${stemClean}\n`);

        if (pic) {
            report.push(`QUESTION PIC: ${pic}\n`);
            imageQuestions.push({ qNum, id: q._id, pic, stem: stemClean.slice(0, 80) });
        }

        if (q.typeOfAnswer === 'MCQ') {
            const wrongAnswers = q.wrongAnswer || [];
            const allChoices = [q.correctAnswer, ...wrongAnswers];
            report.push(`CHOICES (${allChoices.length}):`);
            allChoices.forEach((c, cIdx) => {
                const isCorrect = c === q.correctAnswer;
                report.push(`  [${String.fromCharCode(65 + cIdx)}] ${isCorrect ? '(CORRECT KEY) ' : ''}${stripHtml(c)}`);
            });
            report.push(`\nCORRECT ANSWER FIELD:\n${stripHtml(q.correctAnswer)}\n`);
        } else {
            report.push(`STUDENT-PRODUCED RESPONSE (GRID-IN / ESSAY):`);
            report.push(`ACCEPTED ANSWERS: ${JSON.stringify(q.answer || [])}\n`);
        }

        if (q.explanation && q.explanation.trim()) {
            report.push(`EXPLANATION:\n${stripHtml(q.explanation)}\n`);
        } else {
            report.push(`EXPLANATION: [None provided]\n`);
        }
    });

    fs.writeFileSync(outPath, report.join('\n'));
    console.log(`Generated ${outPath} (${questions.length} questions, ${imageQuestions.length} with images)`);
    return imageQuestions;
}

console.log('Auditing September 2025 INT 1...');
const m1Images = auditModule('scratch_sep2025_int1_m1.json', 'SEPTEMBER 2025 · INT 1 · MODULE 1', 'clean_sep2025_int1_m1_detailed.txt');
const m2Images = auditModule('scratch_sep2025_int1_m2.json', 'SEPTEMBER 2025 · INT 1 · MODULE 2', 'clean_sep2025_int1_m2_detailed.txt');

console.log('\n--- Image Questions Summary ---');
console.log('Module 1 Images:', m1Images);
console.log('Module 2 Images:', m2Images);
