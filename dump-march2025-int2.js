const https = require('https');
const fs = require('fs');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6aa120d2ec7ba02921a31dca';
const M2_ID = '6aa120d9ec7ba02921a31dd0';

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    https.get(url, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', reject);
  });
}

function stripHtml(s) {
  if (!s) return '';
  return s.replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
}

async function run() {
  console.log('Fetching March 2025 · INT 2...');
  const m1Res = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/${M1_ID}`);
  const m2Res = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/${M2_ID}`);

  fs.writeFileSync('scratch_march2025_int2_m1.json', JSON.stringify(m1Res, null, 2));
  fs.writeFileSync('scratch_march2025_int2_m2.json', JSON.stringify(m2Res, null, 2));

  function analyze(modName, res, outTxt) {
    const qs = res.chapter.questions;
    console.log(`\n=== ${modName} (${qs.length} questions) ===`);
    let pics = [];
    let report = `====================================================\n${modName.toUpperCase()} (${qs.length} QUESTIONS)\n====================================================\n\n`;

    qs.forEach((q, idx) => {
      report += `----------------------------------------------------\n`;
      report += `QUESTION ${idx + 1} | ID: ${q._id} | TYPE: ${q.type}\n`;
      if (q.question_pic) {
        report += `IMAGE: ${q.question_pic}\n`;
        pics.push({ num: idx + 1, id: q._id, url: q.question_pic });
      }
      report += `STEM:\n${stripHtml(q.question)}\n\n`;
      if (q.type === 'MCQ') {
        report += `CORRECT ANSWER:\n${stripHtml(q.answer)}\n\n`;
        report += `WRONG ANSWERS (${q.wrongAnswer ? q.wrongAnswer.length : 0}):\n`;
        if (q.wrongAnswer) {
          q.wrongAnswer.forEach((w, wIdx) => {
            report += `  [${wIdx + 1}] ${stripHtml(w)}\n`;
          });
        }
      } else {
        report += `CORRECT GRID-IN / ESSAY ANSWER:\n${JSON.stringify(q.answare || q.answers || q.answer)}\n`;
      }
      report += `\n`;
    });

    fs.writeFileSync(outTxt, report, 'utf8');
    console.log(`Saved detailed report to ${outTxt}`);
    console.log(`Questions with images (${pics.length}):`, pics);
    return pics;
  }

  const p1 = analyze('March 2025 · INT 2 — M1', m1Res, 'clean_march2025_int2_m1_detailed.txt');
  const p2 = analyze('March 2025 · INT 2 — M2', m2Res, 'clean_march2025_int2_m2_detailed.txt');

  fs.writeFileSync('march2025_int2_images.json', JSON.stringify({ m1: p1, m2: p2 }, null, 2));
}

run().catch(console.error);
