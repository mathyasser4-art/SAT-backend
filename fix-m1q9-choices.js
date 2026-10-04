const axios = require('axios');

const BASE_URL = 'https://sat-backend-production.up.railway.app';
const Q9_ID = '6a686213c3d08d90637d3baa';

async function fixQ9() {
  console.log('Restoring M1 Q9 choices...');
  const key = '<p><img src="https://res.cloudinary.com/drxqzhgce/image/upload/v1785225644/quill-images/sazugihhpazjkuyotz78.png"></p>';
  const wrong = [
    '<p><img src="https://res.cloudinary.com/drxqzhgce/image/upload/v1785225616/quill-images/c0iiaexo5pcfucolseii.png"></p>',
    '<p><img src="https://res.cloudinary.com/drxqzhgce/image/upload/v1785225633/quill-images/luzaostpranjbvkm5ak3.png"></p>',
    '<p><img src="https://res.cloudinary.com/drxqzhgce/image/upload/v1785225657/quill-images/zntpmigf6sjjzmytm0ed.png"></p>'
  ];

  const res = await axios.put(`${BASE_URL}/question/updateQuestion/${Q9_ID}`, {
    correctAnswer: key,
    wrongAnswer: wrong
  });
  console.log('M1 Q9 updated:', res.data.message || 'success');
}

fixQ9();
