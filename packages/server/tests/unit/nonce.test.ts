import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../../src/db.js';
import { cleanExpired, isReplay, storeNonce } from '../../src/services/nonce.js';

beforeEach(async () => {
  await prisma.usedNonce.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe('nonce service', () => {
  it('should detect replay after storing nonce', async () => {
    const hash = 'test-sig-hash-001';
    const expiresAt = new Date(Date.now() + 120_000);

    await storeNonce(hash, expiresAt);
    expect(await isReplay(hash)).toBe(true);
  });

  it('should return false for unknown nonce', async () => {
    expect(await isReplay('never-seen-before')).toBe(false);
  });

  it('should clean up expired nonces', async () => {
    // Insert an already-expired nonce
    await prisma.usedNonce.create({
      data: {
        nonce: 'expired-nonce',
        expiresAt: new Date(Date.now() - 10_000),
      },
    });

    // Insert a still-valid nonce
    await prisma.usedNonce.create({
      data: {
        nonce: 'valid-nonce',
        expiresAt: new Date(Date.now() + 120_000),
      },
    });

    const cleaned = await cleanExpired();
    expect(cleaned).toBe(1);

    // Expired one is gone
    expect(await isReplay('expired-nonce')).toBe(false);
    // Valid one remains
    expect(await isReplay('valid-nonce')).toBe(true);
  });
});
