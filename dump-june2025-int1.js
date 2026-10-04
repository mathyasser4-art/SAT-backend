const https = require('https');
const fs = require('fs');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a6d285814cab24f9785a709';
const M2_ID = '6a6d285d14cab24f9785a70f';

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
  console.log('Fetching June 2025 · INT 1...');
  const m1Res = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/${M1_ID}`);
  const m2Res = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/${M2_ID}`);

  fs.writeFileSync('scratch_june2025_int1_m1.json', JSON.stringify(m1Res, null, 2));
  fs.writeFileSync('scratch_june2025_int1_m2.json', JSON.stringify(m2Res, null, 2));

  function analyze(modName, res) {
    const qs = res.chapter.questions;
    console.log(`\n=== ${modName} (${qs.length} questions) ===`);
    let pics = [];
    let hasExpl = 0;

    qs.forEach((q, idx) => {
      if (q.explanation && q.explanation.trim().length > 0) hasExpl++;
      const pic = q.questionPic;
      if (pic) {
        pics.push({ idx: idx + 1, id: q._id, pic });
      }
    });

    console.log(`Explanations: ${hasExpl}/${qs.length}`);
    console.log(`Questions with images: ${pics.length}`);
    pics.forEach(p => console.log(`  Q${p.idx} (${p.id}): ${p.pic}`));

    let summary = `====================================================\nJUNE 2025 · INT 1 — ${modName} (${qs.length} QUESTIONS)\n====================================================\n\n`;
    qs.forEach((q, idx) => {
      summary += `----------------------------------------------------\nQUESTION ${idx + 1} | ID: ${q._id} | TYPE: ${q.typeOfAnswer}\n`;
      if (q.questionPic) summary += `IMAGE: ${q.questionPic}\n`;
      summary += `STEM:\n${stripHtml(q.question)}\n\n`;
      if (q.typeOfAnswer === 'MCQ') {
        summary += `CORRECT ANSWER:\n${stripHtml(q.correctAnswer)}\n\n`;
        summary += `WRONG ANSWERS (${q.wrongAnswer?.length || 0}):\n`;
        (q.wrongAnswer || []).forEach((w, wi) => {
          summary += `  [${wi + 1}] ${stripHtml(w)}\n`;
        });
      } else {
        summary += `CORRECT GRID-IN / ESSAY ANSWER:\n${JSON.stringify(q.answer)}\n`;
      }
      summary += `\n`;
    });
    fs.writeFileSync(`clean_june2025_int1_${modName.toLowerCase()}_detailed.txt`, summary);
  }

  analyze('M1', m1Res);
  analyze('M2', m2Res);
}

run().catch(console.error);
