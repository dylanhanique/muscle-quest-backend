import { createHash } from 'crypto';

export function getEnvVar(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing env var: ${name}`);
  }
  return value;
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}
