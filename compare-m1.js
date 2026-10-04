const axios = require('axios');
const fs = require('fs');

const BASE_URL = 'https://sat-backend-production.up.railway.app';
const M1_ID = '6a6946b7c3d08d90637d3cc3';
const M2_ID = '6a6946bec3d08d90637d3cc9';

async function compare() {
  const res1 = await axios.get(`${BASE_URL}/chapter/getChapterQuestion/${M1_ID}`);
  const liveM1 = res1.data.chapter.questions;
  const scratchM1 = JSON.parse(fs.readFileSync('scratch_sep2025_us1_m1.json', 'utf8')).chapter.questions;

  console.log('Comparing Module 1 questions:');
  liveM1.forEach((lq, idx) => {
    const sq = scratchM1.find(q => q._id === lq._id) || scratchM1[idx];
    console.log(`Q${idx+1}: live_id=${lq._id} (${lq.typeOfAnswer}, choices=${(lq.wrongAnswer||[]).length}) | scratch_id=${sq?._id} (${sq?.typeOfAnswer}, choices=${(sq?.wrongAnswer||[]).length})`);
  });
}

compare().catch(console.error);
