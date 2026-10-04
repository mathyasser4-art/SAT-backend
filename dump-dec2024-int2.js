const https = require('https');
const fs = require('fs');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6aa690e1ec7ba02921a4488b';
const M2_ID = '6aa690e7ec7ba02921a44891';

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

function clean(s) {
  if (!s) return '';
  if (Array.isArray(s)) return s.map(clean).join(' | ');
  return String(s).replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
}

async function run() {
  console.log('Fetching December 2024 · INT 2...');
  const m1Res = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/${M1_ID}`);
  const m2Res = await fetchJson(`${API_BASE}/chapter/getChapterQuestion/${M2_ID}`);

  fs.writeFileSync('scratch_dec2024_int2_m1.json', JSON.stringify(m1Res, null, 2));
  fs.writeFileSync('scratch_dec2024_int2_m2.json', JSON.stringify(m2Res, null, 2));

  function analyze(modName, res, outTxt) {
    const qs = res.chapter.questions;
    console.log(`\n=== ${modName} (${qs.length} questions) ===`);
    let pics = [];
    let logLines = [];

    qs.forEach((q, idx) => {
      const qNum = idx + 1;
      const text = clean(q.question);
      const ans = clean(q.answer);
      const corr = clean(q.correctAnswer);
      const wrongs = (q.wrongAnswer || []).map(clean);
      const picUrl = q.questionPic || q.pic?.url || 'none';

      if (picUrl !== 'none') {
        pics.push({ qNum, id: q._id, url: picUrl });
      }

      logLines.push(`Q${qNum} [${q._id}]`);
      logLines.push(`  Stem: ${text.slice(0, 140)}`);
      logLines.push(`  Ans: ${ans}`);
      logLines.push(`  Corr: ${corr}`);
      logLines.push(`  Wrongs: ${wrongs.join(' /// ')}`);
      logLines.push(`  Pic: ${picUrl}`);
      logLines.push(`  Exp: ${q.explanation ? q.explanation.slice(0, 50) + '...' : 'NONE'}`);
      logLines.push('');
    });

    fs.writeFileSync(outTxt, logLines.join('\n'));
    console.log(`Saved log to ${outTxt}`);
    console.log(`Images found: ${pics.length}`);
    return pics;
  }

  const p1 = analyze('Module 1', m1Res, 'dec2024_int2_m1.txt');
  const p2 = analyze('Module 2', m2Res, 'dec2024_int2_m2.txt');

  const allPics = [...p1.map(p => ({ ...p, mod: 'M1' })), ...p2.map(p => ({ ...p, mod: 'M2' }))];
  fs.writeFileSync('dec2024_int2_images.json', JSON.stringify(allPics, null, 2));
  console.log(`\nTotal images to process: ${allPics.length}`);
}

run().catch(console.error);
