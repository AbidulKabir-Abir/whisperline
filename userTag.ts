import { queryOne } from '../config/database';

const CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // No ambiguous chars (0,O,1,I)

function randomTag(): string {
  let tag = '@';
  const arr = new Uint8Array(8);
  // Node.js crypto for server-side randomness
  const crypto = require('crypto');
  crypto.randomFillSync(arr);
  for (let i = 0; i < 8; i++) {
    tag += CHARS[arr[i] % CHARS.length];
  }
  return tag;
}

export async function generateUserTag(maxAttempts = 10): Promise<string> {
  for (let i = 0; i < maxAttempts; i++) {
    const tag = randomTag();
    const existing = await queryOne(
      'SELECT user_tag FROM users WHERE user_tag = $1',
      [tag]
    );
    if (!existing) return tag;
  }
  throw new Error('Failed to generate unique user tag after max attempts');
}
