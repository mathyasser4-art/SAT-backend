const axios = require('axios');
const fs = require('fs');

const BASE_URL = 'https://sat-backend-production.up.railway.app';
const M2_ID = '6a6946bec3d08d90637d3cc9';

async function compare() {
  const res2 = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${M2_ID}`);
  const liveM2 = res2.data.chapter.questions;
  const scratchM2 = JSON.parse(fs.readFileSync('scratch_sep2025_us1_m2.json', 'utf8')).chapter.questions;

  console.log('Comparing Module 2 questions:');
  liveM2.forEach((lq, idx) => {
    const sq = scratchM2.find(q => q._id === lq._id) || scratchM2[idx];
    console.log(`Q${idx+1}: live_id=${lq._id} (${lq.typeOfAnswer}, choices=${(lq.wrongAnswer||[]).length}) | scratch_id=${sq?._id} (${sq?.typeOfAnswer}, choices=${(sq?.wrongAnswer||[]).length})`);
  });
}

compare().catch(console.error);
