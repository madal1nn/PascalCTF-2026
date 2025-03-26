const crypto = require('crypto');
const SECRET = 'super-secret-key';

function createUser() {
  return crypto.randomUUID();
}

module.exports = { createUser, SECRET };
