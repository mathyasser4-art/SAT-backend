const fs = require('fs');
const data = JSON.parse(fs.readFileSync('scratch_dec_2025_us1_m1.json', 'utf8'));
const qs = data.chapter.questions;

[3, 6, 19, 20, 21].forEach(idx => {
  console.log('=== Q' + (idx+1) + ' FULL OBJ ===');
  console.log(JSON.stringify(qs[idx], null, 2));
});
