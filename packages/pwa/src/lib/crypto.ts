/**
 * WebCrypto-based key generation and ECDH for Clavum PWA.
 *
 * Uses the Web Crypto API for X25519 and Ed25519 operations.
 * Note: X25519 is available in modern browsers (Chrome 113+, Safari 17+).
 */

/**
 * Generate an X25519 keypair using WebCrypto.
 * Returns raw 32-byte keys.
 */
export async function generateX25519Keypair(): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}> {
  const keyPair = (await crypto.subtle.generateKey('X25519', true, [
    'deriveBits',
  ])) as CryptoKeyPair;

  const publicRaw = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
  const privateRaw = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));

  // PKCS8 wraps the raw 32-byte key, extract it (last 32 bytes of the PKCS8 structure)
  const privateKey = privateRaw.slice(-32);

  return { publicKey: publicRaw, privateKey };
}

/**
 * Generate an Ed25519 keypair using WebCrypto.
 * Returns raw keys.
 */
export async function generateEd25519Keypair(): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}> {
  const keyPair = (await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;

  const publicRaw = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
  const privateRaw = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));

  const privateKey = privateRaw.slice(-32);

  return { publicKey: publicRaw, privateKey };
}

/**
 * Convert Uint8Array to base64url string.
 */
export function toBase64Url(bytes: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Convert base64url string to Uint8Array.
 */
export function fromBase64Url(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/**
 * Store keys in IndexedDB.
 */
export async function storeKeys(keys: Record<string, Uint8Array>): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('clavum', 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains('keys')) {
        db.createObjectStore('keys');
      }
    };
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction('keys', 'readwrite');
      const store = tx.objectStore('keys');
      for (const [name, value] of Object.entries(keys)) {
        store.put(value, name);
      }
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => reject(tx.error);
    };
    request.onerror = () => reject(request.error);
  });
}

/**
 * Load a key from IndexedDB.
 */
export async function loadKey(name: string): Promise<Uint8Array | null> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('clavum', 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains('keys')) {
        db.createObjectStore('keys');
      }
    };
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction('keys', 'readonly');
      const store = tx.objectStore('keys');
      const getReq = store.get(name);
      getReq.onsuccess = () => {
        db.close();
        resolve(getReq.result ?? null);
      };
      getReq.onerror = () => reject(getReq.error);
    };
    request.onerror = () => reject(request.error);
  });
}

/**
 * QR payload shape from the server invitation.
 */
export interface QrPayload {
  pub: string; // base64url server X25519 public key
  token: string;
  url: string; // server URL
}

/**
 * Parse QR code data into structured payload.
 */
export function parseQrPayload(data: string): QrPayload {
  const parsed = JSON.parse(data);
  if (!parsed.pub || !parsed.token || !parsed.url) {
    throw new Error('Invalid QR payload: missing pub, token, or url');
  }
  return parsed as QrPayload;
}
