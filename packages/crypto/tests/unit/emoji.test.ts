import { describe, expect, it } from 'vitest';
import { EMOJI_TABLE, EMOJI_TABLE_SIZE, fingerprintToEmoji } from '../../src/emoji.js';

describe('emoji fingerprint', () => {
  it('table has exactly 256 entries', () => {
    expect(EMOJI_TABLE_SIZE).toBe(256);
    expect(EMOJI_TABLE.length).toBe(256);
  });

  it('all 256 entries are unique', () => {
    const unique = new Set(EMOJI_TABLE);
    expect(unique.size).toBe(256);
  });

  it('maps 4 bytes to 4 emoji', () => {
    const bytes = new Uint8Array([0, 1, 2, 3]);
    const result = fingerprintToEmoji(bytes);
    expect(result).toBe('🐶🐱🐭🐹');
  });

  it('is deterministic', () => {
    const bytes = new Uint8Array([42, 100, 200, 255]);
    const r1 = fingerprintToEmoji(bytes);
    const r2 = fingerprintToEmoji(bytes);
    expect(r1).toBe(r2);
  });

  it('handles boundary values', () => {
    const first = fingerprintToEmoji(new Uint8Array([0]));
    expect(first).toBe('🐶');
    const last = fingerprintToEmoji(new Uint8Array([255]));
    expect(last).toBe('🪂');
  });
});
