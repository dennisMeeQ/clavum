import { randomBytes } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { dekCache } from '../../src/cache.js';

afterEach(() => {
  dekCache.clear();
});

describe('DEK cache', () => {
  it('should set and get a DEK', () => {
    const dek = new Uint8Array(randomBytes(32));
    dekCache.set('secret-1', dek);

    const cached = dekCache.get('secret-1');
    expect(cached).not.toBeNull();
    expect(cached).toHaveLength(32);
  });

  it('should return null for expired DEK', () => {
    const dek = new Uint8Array(randomBytes(32));
    dekCache.set('secret-2', dek, 1); // 1ms TTL

    // Wait for expiry
    const start = Date.now();
    while (Date.now() - start < 5) {
      /* spin */
    }

    expect(dekCache.get('secret-2')).toBeNull();
  });

  it('should return null for unknown secret', () => {
    expect(dekCache.get('nonexistent')).toBeNull();
  });

  it('should clear all cached DEKs', () => {
    dekCache.set('a', new Uint8Array(randomBytes(32)));
    dekCache.set('b', new Uint8Array(randomBytes(32)));

    dekCache.clear();

    expect(dekCache.get('a')).toBeNull();
    expect(dekCache.get('b')).toBeNull();
  });

  it('should cache different secrets independently', () => {
    const dek1 = new Uint8Array(randomBytes(32));
    const dek2 = new Uint8Array(randomBytes(32));

    dekCache.set('s1', dek1);
    dekCache.set('s2', dek2);

    const cached1 = dekCache.get('s1');
    const cached2 = dekCache.get('s2');

    expect(cached1).not.toBeNull();
    expect(cached2).not.toBeNull();
    expect(Buffer.from(cached1!).toString('hex')).not.toBe(Buffer.from(cached2!).toString('hex'));
  });
});
