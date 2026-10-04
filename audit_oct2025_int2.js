const fs = require('fs');
const https = require('https');

const API = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a626236c3d08d90637d367e';
const M2_ID = '6a626240c3d08d90637d3684';

function get(url) {
  return new Promise((res, rej) => {
    https.get(url, r => {
      let d = '';
      r.on('data', c => d += c);
      r.on('end', () => {
        try {
          res(JSON.parse(d));
        } catch (e) {
          rej(e);
        }
      });
    }).on('error', rej);
  });
}

function stripHtml(s) {
  if (!s) return '';
  return s.replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
}

async function main() {
  const m1Res = await get(`${API}/chapter/getChapterQuestion/${M1_ID}`);
  const m2Res = await get(`${API}/chapter/getChapterQuestion/${M2_ID}`);

  const m1 = m1Res.chapter.questions;
  const m2 = m2Res.chapter.questions;

  console.log(`Retrieved M1: ${m1.length} questions, M2: ${m2.length} questions.`);

  const report = { m1: [], m2: [] };

  function checkModule(qs, modKey, name) {
    console.log(`\n=================== ${name} ===================`);
    qs.forEach((q, idx) => {
      const qNum = idx + 1;
      const issues = [];

      // Check correctAnswer
      if (!q.correctAnswer || stripHtml(q.correctAnswer) === '') {
        issues.push('MISSING_CORRECT_ANSWER');
      }

      // Check MCQ structure
      if (q.typeOfAnswer === 'MCQ') {
        if (!Array.isArray(q.wrongAnswer)) {
          issues.push('WRONG_ANSWER_NOT_ARRAY');
        } else if (q.wrongAnswer.length !== 3) {
          issues.push(`WRONG_ANSWER_COUNT_${q.wrongAnswer.length}_EXPECTED_3`);
        } else {
          const allOptions = [q.correctAnswer, ...q.wrongAnswer].map(stripHtml);
          const uniqueOptions = new Set(allOptions);
          if (uniqueOptions.size !== allOptions.length) {
            issues.push(`DUPLICATE_CHOICES: ${JSON.stringify(allOptions)}`);
          }
        }
      }

      // Check encoding
      const fullText = (q.question || '') + (q.correctAnswer || '') + ((q.wrongAnswer || []).join(' '));
      if (/Â|â€”|â€“|&Acirc;|\u00C2/.test(fullText)) {
        issues.push('ENCODING_GLITCH_FOUND');
      }

      // Check explanation
      const hasExpl = Boolean(q.answerExplanation || q.explanation);
      if (!hasExpl) {
        issues.push('NO_EXPLANATION');
      }

      // Check image
      const hasPic = Boolean(q.questionPic && q.questionPic.startsWith('http'));

      const itemReport = {
        num: qNum,
        id: q._id,
        type: q.typeOfAnswer,
        stem: stripHtml(q.question),
        correct: stripHtml(q.correctAnswer),
        wrong: (q.wrongAnswer || []).map(stripHtml),
        hasPic,
        picUrl: q.questionPic || null,
        hasExpl,
        issues
      };

      report[modKey].push(itemReport);

      const status = issues.length === 0 ? '✅ OK' : `⚠️ ISSUES: ${issues.join(' | ')}`;
      console.log(`Q${qNum.toString().padStart(2, ' ')} (${q.typeOfAnswer.padEnd(4, ' ')}) [Pic: ${hasPic ? 'YES' : ' NO'}] [Expl: ${hasExpl ? 'YES' : ' NO'}] Correct: ${itemReport.correct.padEnd(10, ' ')} -> ${status}`);
    });
  }

  checkModule(m1, 'm1', 'OCTOBER 2025 INT 2 - MODULE 1');
  checkModule(m2, 'm2', 'OCTOBER 2025 INT 2 - MODULE 2');

  fs.writeFileSync('audit_oct2025_int2_report.json', JSON.stringify(report, null, 2));
  console.log('\nFull audit report saved to audit_oct2025_int2_report.json');
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
