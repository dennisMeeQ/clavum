import { describe, expect, it } from 'vitest';
import { concat, fromBase64Url, timingSafeEqual, toBase64Url, wipe } from '../../src/utils.js';

describe('wipe', () => {
  it('overwrites buffer with zeros', () => {
    const buf = new Uint8Array([1, 2, 3, 4, 5]);
    wipe(buf);
    expect(buf).toEqual(new Uint8Array(5));
  });

  it('handles empty buffer', () => {
    const buf = new Uint8Array(0);
    wipe(buf); // should not throw
    expect(buf.length).toBe(0);
  });
});

describe('concat', () => {
  it('concatenates multiple arrays', () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3, 4, 5]);
    const c = new Uint8Array([6]);
    expect(concat(a, b, c)).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
  });

  it('handles empty arrays', () => {
    const a = new Uint8Array([1, 2]);
    const empty = new Uint8Array(0);
    expect(concat(a, empty)).toEqual(new Uint8Array([1, 2]));
    expect(concat(empty, a)).toEqual(new Uint8Array([1, 2]));
    expect(concat(empty, empty)).toEqual(new Uint8Array(0));
  });

  it('handles single array', () => {
    const a = new Uint8Array([1, 2, 3]);
    const result = concat(a);
    expect(result).toEqual(a);
    // Should be a new copy
    expect(result.buffer).not.toBe(a.buffer);
  });

  it('handles no arguments', () => {
    expect(concat()).toEqual(new Uint8Array(0));
  });
});

describe('timingSafeEqual', () => {
  it('returns true for equal arrays', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3]);
    expect(timingSafeEqual(a, b)).toBe(true);
  });

  it('returns false for different arrays', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 4]);
    expect(timingSafeEqual(a, b)).toBe(false);
  });

  it('returns false for different lengths', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2]);
    expect(timingSafeEqual(a, b)).toBe(false);
  });

  it('handles empty arrays', () => {
    expect(timingSafeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });
});

describe('toBase64Url / fromBase64Url', () => {
  it('round-trips arbitrary bytes', () => {
    const original = new Uint8Array([0, 1, 62, 63, 128, 255]);
    const encoded = toBase64Url(original);
    const decoded = fromBase64Url(encoded);
    expect(decoded).toEqual(original);
  });

  it('produces URL-safe output (no +, /, =)', () => {
    // Bytes that produce +, / in standard base64
    const bytes = new Uint8Array([251, 255, 254]);
    const encoded = toBase64Url(bytes);
    expect(encoded).not.toMatch(/[+/=]/);
  });

  it('handles empty input', () => {
    expect(toBase64Url(new Uint8Array(0))).toBe('');
    expect(fromBase64Url('')).toEqual(new Uint8Array(0));
  });

  it('matches known encoding', () => {
    // "Hello" → base64url "SGVsbG8"
    const hello = new TextEncoder().encode('Hello');
    expect(toBase64Url(hello)).toBe('SGVsbG8');
  });
});
