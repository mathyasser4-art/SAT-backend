const bcrypt = require('bcryptjs');

const password = '123456';
const saltRounds = 10;

const hash = bcrypt.hashSync(password, saltRounds);
console.log('Hashed password (salt rounds 10):');
console.log(hash);
console.log('\nCopy this exact string into your MongoDB password field.');

