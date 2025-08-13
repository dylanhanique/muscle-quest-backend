import { createHash, randomBytes } from 'crypto';

export function getEnvVar(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing env var: ${name}`);
  }
  return value;
}

export function hashToken(token: string) {
  const salt = randomBytes(16).toString('hex');

  const hash = createHash('sha256')
    .update(salt + token)
    .digest('hex');

  return { hash, salt };
}
