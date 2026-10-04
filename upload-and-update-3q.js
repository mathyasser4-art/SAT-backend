const axios = require('axios');
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');

const API_BASE = 'https://sat-backend-production.up.railway.app';
const imgDir = path.join(__dirname, 'sep2025_us1_images');

async function uploadImageWithRetry(questionId, filePath, retries = 3) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const form = new FormData();
      form.append('image', fs.createReadStream(filePath));

      const res = await axios.put(`${API_BASE}/question/updateQuestion/${questionId}`, form, {
        headers: form.getHeaders(),
        timeout: 30000
      });
      return res.data;
    } catch (err) {
      console.log(`  [Attempt ${attempt}/${retries}] Upload error for ${questionId}: ${err.message}`);
      if (attempt === retries) throw err;
      await new Promise(r => setTimeout(r, 2000));
    }
  }
}

async function updateQuestionJsonWithRetry(questionId, payload, retries = 3) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const res = await axios.put(`${API_BASE}/question/updateQuestion/${questionId}`, payload, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 30000
      });
      return res.data;
    } catch (err) {
      console.log(`  [Attempt ${attempt}/${retries}] JSON update error for ${questionId}: ${err.message}`);
      if (attempt === retries) throw err;
      await new Promise(r => setTimeout(r, 2000));
    }
  }
}

async function run() {
  console.log('🚀 Step 1: Uploading clean light images for Q2, Q3, Q13...\n');

  // Upload Q2
  console.log('Uploading Q2 image...');
  const q2Res = await uploadImageWithRetry('6a694ee3c3d08d90637d3cd9', path.join(imgDir, 'm1_q2_light.png'));
  console.log('✅ Q2 Image updated:', q2Res.question?.questionPic || q2Res.message);

  // Upload Q3
  console.log('Uploading Q3 image (Scatterplot)...');
  const q3Res = await uploadImageWithRetry('6a694f2ec3d08d90637d3cdf', path.join(imgDir, 'm1_q3_light.png'));
  console.log('✅ Q3 Image updated:', q3Res.question?.questionPic || q3Res.message);

  // Upload Q13
  console.log('Uploading Q13 image...');
  const q13Res = await uploadImageWithRetry('6a695322c3d08d90637d3d39', path.join(imgDir, 'm1_q13_light.png'));
  console.log('✅ Q13 Image updated:', q13Res.question?.questionPic || q13Res.message);

  console.log('\n🚀 Step 2: Updating text & answer settings for Q3...\n');
  const cleanQ3Stem = '<p>The scatterplot shows 5 measurements of the body length, in centimeters (cm), of a New Zealand fur seal from an age of 1 year to 6 years old. A line of best fit is also shown. For a New Zealand fur seal at an age of 3 years old, what is the body length predicted by the line of best fit, to the nearest 10 cm?</p>';

  const q3Update = await updateQuestionJsonWithRetry('6a694f2ec3d08d90637d3cdf', {
    question: cleanQ3Stem,
    answer: ['100', '120'], // Accepting 100 as primary, 120 as secondary tolerance
    explanation: '<p>To find the body length predicted by the line of best fit for a 3-year-old seal:</p><p>1. Locate <strong>3</strong> on the horizontal axis (Age in years).</p><p>2. Move vertically up to intersect the line of best fit.</p><p>3. Move horizontally to the vertical axis (Body length in centimeters), which reads <strong>100 cm</strong>.</p><p>Rounded to the nearest 10 cm, the predicted length is <strong>100</strong>.</p>'
  });
  console.log('✅ Q3 Stem & Answer updated:', q3Update.message || 'success');

  console.log('\n🚀 Step 3: Verifying live data from database...\n');
  const checkRes = await axios.get(`${API_BASE}/chapter/getChapterQuestion/6a6946b7c3d08d90637d3cc3`);
  const qs = checkRes.data.chapter.questions;

  const targetIds = [
    { num: 2, id: '6a694ee3c3d08d90637d3cd9' },
    { num: 3, id: '6a694f2ec3d08d90637d3cdf' },
    { num: 13, id: '6a695322c3d08d90637d3d39' }
  ];

  for (const t of targetIds) {
    const q = qs.find(item => item._id === t.id);
    console.log(`=== LIVE QUESTION ${t.num} (${t.id}) ===`);
    console.log('Question Pic:', q?.questionPic);
    console.log('Question Stem:', q?.question);
    console.log('Type of Answer:', q?.typeOfAnswer);
    console.log('Correct Answer:', q?.correctAnswer);
    console.log('Answer (grid-in):', q?.answer);
    console.log('Wrong Answers:', q?.wrongAnswer);
    console.log('Explanation:', q?.explanation);
    console.log('----------------------------------------------------');
  }

  console.log('\n🚀 Step 4: Updating local scratch JSON and detailed review file...\n');
  const scratchPath = path.join(__dirname, 'scratch_sep2025_us1_m1.json');
  if (fs.existsSync(scratchPath)) {
    const scratch = JSON.parse(fs.readFileSync(scratchPath, 'utf8'));
    for (const t of targetIds) {
      const idx = scratch.chapter.questions.findIndex(item => item._id === t.id);
      const liveQ = qs.find(item => item._id === t.id);
      if (idx !== -1 && liveQ) {
        scratch.chapter.questions[idx] = liveQ;
      }
    }
    fs.writeFileSync(scratchPath, JSON.stringify(scratch, null, 2), 'utf8');
    console.log('✅ Updated scratch_sep2025_us1_m1.json');
  }
}

run().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
