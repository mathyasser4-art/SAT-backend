const https = require('https');
const fs = require('fs');

const pngBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
const buf = Buffer.from(pngBase64, 'base64');

const boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW';
const header = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="image"; filename="dot.png"\r\nContent-Type: image/png\r\n\r\n`);
const footer = Buffer.from(`\r\n--${boundary}--\r\n`);
const body = Buffer.concat([header, buf, footer]);

const req = https.request('https://sat-backend-production.up.railway.app/question/updateQuestion/6a5410164d554e04aa1bfd0d', {
  method: 'PUT',
  headers: {
    'Content-Type': 'multipart/form-data; boundary=' + boundary,
    'Content-Length': body.length
  }
}, res => {
  let d = '';
  res.on('data', c => d += c);
  res.on('end', () => console.log('Status:', res.statusCode, 'Body:', d));
});
req.on('error', console.error);
req.write(body);
req.end();
