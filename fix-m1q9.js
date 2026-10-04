const https = require('https');

function f(formula) {
  return `<span class="ql-formula" data-value="${formula}"></span>`;
}

const payload = JSON.stringify({
  question: `<p>The expression ${f('6x^4 + 17x^2 + 7')} can be rewritten as ${f('(3x^2 + a)(2x^2 + b)')}, where ${f('a')} and ${f('b')} are positive integers, or as ${f('(3x^2 + c)(2x^2 + d)')}, where ${f('c')} and ${f('d')} are positive nonintegers. What is the value of ${f('a + c')}?</p>`
});

const req = https.request('https://sat-backend-production.up.railway.app/question/updateQuestion/6a52e3b64d554e04aa1bf41e', {
  method: 'PUT',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload)
  }
}, res => {
  let d = '';
  res.on('data', c => d += c);
  res.on('end', () => console.log('Fixed M1 Q9:', d));
});

req.write(payload);
req.end();
