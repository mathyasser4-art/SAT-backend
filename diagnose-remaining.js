const axios = require('axios');
const fs = require('fs');

const BASE_URL = 'https://sat-backend-production.up.railway.app';
const dir = JSON.parse(fs.readFileSync('all_real_exams_directory.json', 'utf8'));

function normalizeChoice(html) {
  if (!html) return '';
  let formulas = [];
  const formulaRegex = /data-value="([^"]*)"/g;
  let match;
  while ((match = formulaRegex.exec(html)) !== null) {
    formulas.push(match[1]);
  }
  const text = (html || '')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/[\s\u200B\u3164\uFEFF]+/g, ' ')
    .trim();

  if (formulas.length > 0 && !text) return formulas.join(' ').trim();
  if (formulas.length > 0) return (formulas.join(' ') + ' ' + text).trim();
  return text;
}

async function diagnose() {
  let issues = [];

  for (const exam of dir) {
    if (!exam.m1 || !exam.m2) continue;
    for (const [modKey, modLabel] of [['m1', 'Module 1'], ['m2', 'Module 2']]) {
      const mod = exam[modKey];
      if (!mod || !mod.id) continue;
      try {
        const res = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${mod.id}`);
        const questions = res.data.chapter?.questions || [];
        for (let i = 0; i < questions.length; i++) {
          const q = questions[i];
          if (q.typeOfAnswer !== 'MCQ') continue;
          const wrongs = q.wrongAnswer || [];
          if (wrongs.length !== 4) {
            const correctNorm = normalizeChoice(q.correctAnswer);
            const wrongNorms = wrongs.map(normalizeChoice);
            const correctInWrongs = wrongNorms.some(w => w === correctNorm);
            issues.push({
              exam: exam.name,
              module: modLabel,
              qNum: i + 1,
              id: q._id,
              choiceCount: wrongs.length,
              correctRaw: q.correctAnswer,
              wrongsRaw: wrongs,
              correctNorm,
              wrongNorms,
              correctInWrongs
            });
          }
        }
      } catch (err) {
        console.error(`Error fetching ${exam.name} ${modLabel}: ${err.message}`);
      }
    }
  }

  console.log('TOTAL ISSUES FOUND:', issues.length);
  const byCategory = {
    len3_correctNotInWrongs: issues.filter(x => x.choiceCount === 3 && !x.correctInWrongs),
    len3_correctInWrongs: issues.filter(x => x.choiceCount === 3 && x.correctInWrongs),
    otherLengths: issues.filter(x => x.choiceCount !== 3)
  };
  console.log('1. len=3 and correct answer NOT in wrongAnswer (can cleanly add correctAnswer to make 4 choices):', byCategory.len3_correctNotInWrongs.length);
  console.log('2. len=3 and correct answer ALREADY in wrongAnswer:', byCategory.len3_correctInWrongs.length);
  console.log('3. other lengths (e.g. 0, 1, 2, 5):', byCategory.otherLengths.length);

  if (byCategory.len3_correctInWrongs.length > 0) {
    console.log('\n--- Details of len=3 where correct is already in wrongAnswer ---');
    for (const item of byCategory.len3_correctInWrongs) {
      console.log(`${item.exam} ${item.module} Q${item.qNum} (${item.id})`);
      console.log('  correctNorm:', item.correctNorm);
      console.log('  wrongNorms:', item.wrongNorms);
      console.log('  correctRaw:', item.correctRaw);
      console.log('  wrongsRaw:', JSON.stringify(item.wrongsRaw));
    }
  }

  if (byCategory.otherLengths.length > 0) {
    console.log('\n--- Details of other lengths ---');
    for (const item of byCategory.otherLengths) {
      console.log(`${item.exam} ${item.module} Q${item.qNum} (${item.id}) count=${item.choiceCount}`);
      console.log('  correctRaw:', item.correctRaw);
      console.log('  wrongsRaw:', JSON.stringify(item.wrongsRaw));
    }
  }

  fs.writeFileSync('remaining_issues.json', JSON.stringify(issues, null, 2));
}

diagnose();
