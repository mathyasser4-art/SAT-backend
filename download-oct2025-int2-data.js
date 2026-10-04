const https = require('https');
const fs = require('fs');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a626236c3d08d90637d367e';
const M2_ID = '6a626240c3d08d90637d3684';

function get(url) {
  return new Promise((resolve, reject) => {
    https.get(url, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          resolve({ raw: data });
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
  console.log(`🔍 Downloading October 2025 · INT 2...`);
  const m1Data = await get(`${API_BASE}/chapter/getChapterQuestion/${M1_ID}`);
  const m2Data = await get(`${API_BASE}/chapter/getChapterQuestion/${M2_ID}`);

  fs.writeFileSync('scratch_oct2025_int2_m1.json', JSON.stringify(m1Data, null, 2));
  fs.writeFileSync('scratch_oct2025_int2_m2.json', JSON.stringify(m2Data, null, 2));

  function dumpDetails(data, label, outFile) {
    const qs = data.chapter?.questions || [];
    let out = `====================================================\n`;
    out += `OCTOBER 2025 · INT 2 — ${label} (${qs.length} QUESTIONS)\n`;
    out += `====================================================\n\n`;

    qs.forEach((q, idx) => {
      out += `----------------------------------------------------\n`;
      out += `QUESTION ${idx + 1} | ID: ${q._id} | TYPE: ${q.typeOfAnswer}\n`;
      if (q.questionPic) {
        out += `IMAGE: ${q.questionPic}\n`;
      }
      out += `STEM:\n${stripHtml(q.question)}\n\n`;

      if (q.typeOfAnswer === 'MCQ') {
        out += `CORRECT ANSWER:\n${stripHtml(q.correctAnswer)}\n\n`;
        out += `WRONG ANSWERS (${(q.wrongAnswer || []).length}):\n`;
        (q.wrongAnswer || []).forEach((w, widx) => {
          out += `  [${widx + 1}] ${stripHtml(w)}\n`;
        });
      } else {
        out += `CORRECT GRID-IN / ESSAY ANSWER:\n${JSON.stringify(q.answer)}\n`;
      }
      out += `\n`;
    });

    fs.writeFileSync(outFile, out, 'utf8');
    console.log(`Saved ${outFile} with ${qs.length} questions.`);
  }

  dumpDetails(m1Data, 'M1', 'clean_oct2025_int2_m1_detailed.txt');
  dumpDetails(m2Data, 'M2', 'clean_oct2025_int2_m2_detailed.txt');
}

run().catch(console.error);
