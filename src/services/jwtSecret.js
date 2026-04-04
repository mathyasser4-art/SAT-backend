function getJwtSecret() {
  const secret = process.env.TOKEN_SECRET_KEY || process.env.JWT_SECRET;

  if (!secret) {
    throw new Error('Missing JWT secret: set TOKEN_SECRET_KEY or JWT_SECRET');
  }

  return secret;
}

module.exports = getJwtSecret;