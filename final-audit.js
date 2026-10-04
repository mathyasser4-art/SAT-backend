const fs = require('fs');
const path = require('path');
const scratchDir = 'C:\\Users\\hp\\.gemini\\antigravity-ide\\brain\\871fe295-f0e4-4d4a-bbff-9bb437dccbc9\\scratch';
const data = JSON.parse(fs.readFileSync(path.join(scratchDir, 'basics_classified_questions.json'), 'utf8'));

const stripHtml = (str) => {
    if (!str) return '';
    return str.replace(/<[^>]+>/g, '')
              .replace(/&nbsp;/g, ' ')
              .replace(/&amp;/g, '&')
              .replace(/&lt;/g, '<')
              .replace(/&gt;/g, '>')
              .replace(/﻿/g, '')  // zero-width no-break space
              .trim();
};

let issues = [];
let totalQuestions = 0;
let mcqCount = 0;
let essayCount = 0;

data.forEach(subject => {
  if (!subject.units) return;
  subject.units.forEach(unit => {
    if (!unit.chapters) return;
    unit.chapters.forEach(chapter => {
      if (!chapter.questions) return;
      chapter.questions.forEach((q, qIndex) => {
        totalQuestions++;
        let qIssues = [];
        const qType = q.typeOfAnswer;
        
        if (qType === 'MCQ') {
          mcqCount++;
          const allChoices = q.wrongAnswer || [];
          const cleanChoices = allChoices.map(stripHtml);
          const cleanCorrect = stripHtml(q.correctAnswer);
          
          // Issue 1: Two options in the choices array are identical (students see duplicate choices)
          for (let i = 0; i < cleanChoices.length; i++) {
            for (let j = i + 1; j < cleanChoices.length; j++) {
              if (cleanChoices[i] === cleanChoices[j] && cleanChoices[i] !== '' && cleanChoices[i] !== '.') {
                qIssues.push(`DUPLICATE CHOICES: Option ${i+1} and Option ${j+1} are identical ("${cleanChoices[i].substring(0, 60)}")`);
              }
            }
          }
          
          // Issue 2: Correct answer is NOT among the choices (student can't select the right answer)
          if (cleanCorrect && !cleanChoices.includes(cleanCorrect)) {
            // Check with looser matching (sometimes KaTeX rendering adds extra chars)
            const looseMatch = cleanChoices.some(c => 
              c.includes(cleanCorrect) || cleanCorrect.includes(c)
            );
            if (!looseMatch && cleanCorrect.length > 1) {
              // Don't flag if it's a very short answer that might be substring noise
              qIssues.push(`CORRECT ANSWER NOT IN CHOICES: "${cleanCorrect.substring(0, 60)}" not found among the ${allChoices.length} options`);
            }
          }
          
          // Issue 3: Fewer than 4 choices
          if (allChoices.length < 4) {
            qIssues.push(`ONLY ${allChoices.length} CHOICES: MCQ should have 4 options but has ${allChoices.length}`);
          }
          
          // Issue 4: All choices are empty/blank/just dots
          const nonEmptyChoices = cleanChoices.filter(c => c && c !== '.' && c.length > 1);
          if (nonEmptyChoices.length === 0 && allChoices.length > 0) {
            qIssues.push(`ALL CHOICES BLANK: All ${allChoices.length} options are empty or just dots`);
          }
          
        } else if (qType === 'Essay') {
          essayCount++;
          // Essay questions: check if answer exists
          const essayAnswer = q.answer;
          if (!essayAnswer && essayAnswer !== 0) {
            qIssues.push(`MISSING ESSAY ANSWER: No answer provided for this fill-in question`);
          }
        }
        
        // Issue 5: Question text is empty
        const cleanQuestion = stripHtml(q.question);
        if (!cleanQuestion || cleanQuestion.length < 5) {
          qIssues.push(`EMPTY/SHORT QUESTION TEXT: Question text is "${cleanQuestion || '(empty)'}"`);
        }
        
        // Issue 6: LaTeX issues - check for broken \n in LaTeX commands
        const rawQ = q.question || '';
        const rawExpl = q.explanation || '';
        // Check if raw text has \\neq that might break (already fixed in renderer, but data might have other issues)
        
        // Issue 7: Question references an image but has no image URL
        if (cleanQuestion && (cleanQuestion.toLowerCase().includes('figure') || 
            cleanQuestion.toLowerCase().includes('graph shown') ||
            cleanQuestion.toLowerCase().includes('table shown') ||
            cleanQuestion.toLowerCase().includes('shown above') ||
            cleanQuestion.toLowerCase().includes('shown below')) && 
            !q.questionPic && !rawQ.includes('<img') && !rawQ.includes('data:image')) {
          qIssues.push(`POSSIBLE MISSING IMAGE: Question text references a figure/graph/table but no image is attached`);
        }

        if (qIssues.length > 0) {
          issues.push({
            subject: subject.subjectName,
            unit: unit.unitName,
            chapter: chapter.chapterName,
            questionNumber: qIndex + 1,
            questionId: q._id,
            questionType: qType,
            issues: qIssues
          });
        }
      });
    });
  });
});

// Generate summary
console.log('========================================');
console.log('  CORRECTED AUDIT REPORT');
console.log('========================================');
console.log(`Total questions scanned: ${totalQuestions}`);
console.log(`  MCQ questions: ${mcqCount}`);
console.log(`  Essay questions: ${essayCount}`);
console.log(`Questions with REAL issues: ${issues.length}`);
console.log('========================================\n');

// Group by issue type
const issueTypes = {};
issues.forEach(i => {
  i.issues.forEach(iss => {
    const type = iss.split(':')[0];
    issueTypes[type] = (issueTypes[type] || 0) + 1;
  });
});

console.log('Issue breakdown:');
Object.entries(issueTypes).sort((a,b) => b[1] - a[1]).forEach(([type, count]) => {
  console.log(`  ${type}: ${count}`);
});

console.log('\n========================================');
console.log('  DETAILED FINDINGS');
console.log('========================================\n');

// Group by subject > unit > chapter
const grouped = {};
issues.forEach(i => {
  const key = `${i.subject} > ${i.unit} > ${i.chapter}`;
  if (!grouped[key]) grouped[key] = [];
  grouped[key].push(i);
});

for (const [lesson, qs] of Object.entries(grouped)) {
  console.log(`\n--- ${lesson} ---`);
  qs.forEach(q => {
    console.log(`  Q${q.questionNumber} (${q.questionType}):`);
    q.issues.forEach(iss => console.log(`    ⚠️  ${iss}`));
  });
}

// Save to JSON for reference
fs.writeFileSync(path.join(scratchDir, 'corrected_audit.json'), JSON.stringify(issues, null, 2));
console.log('\n\nFull results saved to corrected_audit.json');
