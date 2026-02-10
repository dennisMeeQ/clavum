<script lang="ts">
import {
  generateEd25519Keypair,
  generateX25519Keypair,
  parseQrPayload,
  type QrPayload,
  storeKeys,
  toBase64Url,
} from '$lib/crypto';

type PairingState = 'scan' | 'pairing' | 'paired' | 'error';

let state: PairingState = $state('scan');
let error: string = $state('');
let fingerprint: string = $state('');
let phoneId: string = $state('');
const qrInput: string = $state('');

async function handlePair(qrData: string) {
  try {
    state = 'pairing';
    const qr: QrPayload = parseQrPayload(qrData);

    // Generate keypairs
    const x25519Keys = await generateX25519Keypair();
    const ed25519Keys = await generateEd25519Keypair();

    // Register with server
    const res = await fetch(`${qr.url}/api/pair/phone`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: qr.token,
        x25519_pub: toBase64Url(x25519Keys.publicKey),
        ed25519_pub: toBase64Url(ed25519Keys.publicKey),
        name: 'Phone',
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error((err as { error?: string }).error || `Server error: ${res.status}`);
    }

    const data = (await res.json()) as {
      phoneId: string;
      serverX25519Pub: string;
      fingerprint: string;
    };

    // Store keys in IndexedDB
    await storeKeys({
      phone_x25519_priv: x25519Keys.privateKey,
      phone_x25519_pub: x25519Keys.publicKey,
      phone_ed25519_priv: ed25519Keys.privateKey,
      phone_ed25519_pub: ed25519Keys.publicKey,
    });

    // Store server info in localStorage
    localStorage.setItem('clavum_server_url', qr.url);
    localStorage.setItem('clavum_server_pub', data.serverX25519Pub);
    localStorage.setItem('clavum_phone_id', data.phoneId);
    localStorage.setItem('clavum_paired', 'true');

    fingerprint = data.fingerprint;
    phoneId = data.phoneId;
    state = 'paired';
  } catch (e) {
    error = e instanceof Error ? e.message : 'Unknown error';
    state = 'error';
  }
}

function handleManualPair() {
  if (qrInput.trim()) {
    handlePair(qrInput.trim());
  }
}
</script>

<div class="pair-container">
	{#if state === 'scan'}
		<h1>🔗 Pair with Server</h1>
		<p>Scan the QR code from your server, or paste the pairing data below.</p>

		<!-- QR Scanner placeholder — add html5-qrcode later -->
		<div class="qr-placeholder">
			<p>📷 QR Scanner coming soon</p>
		</div>

		<div class="manual-entry">
			<h3>Manual Entry</h3>
			<textarea
				bind:value={qrInput}
				placeholder='Paste QR JSON: {"pub":"...","token":"...","url":"..."}'
				rows="4"
			></textarea>
			<button onclick={handleManualPair}>Pair</button>
		</div>
	{:else if state === 'pairing'}
		<h1>⏳ Pairing...</h1>
		<p>Generating keys and registering with server...</p>
	{:else if state === 'paired'}
		<h1>✅ Paired!</h1>
		<p class="fingerprint">{fingerprint}</p>
		<p class="fingerprint-hint">
			Verify this fingerprint matches what the server admin sees.
		</p>
		<p class="phone-id">Phone ID: {phoneId}</p>
		<a href="/">← Back to Home</a>
	{:else if state === 'error'}
		<h1>❌ Pairing Failed</h1>
		<p class="error">{error}</p>
		<button onclick={() => { state = 'scan'; error = ''; }}>Try Again</button>
	{/if}
</div>

<style>
	.pair-container {
		max-width: 480px;
		margin: 2rem auto;
		padding: 1rem;
		text-align: center;
	}

	.qr-placeholder {
		border: 2px dashed #666;
		border-radius: 8px;
		padding: 3rem;
		margin: 1rem 0;
		color: #888;
	}

	.manual-entry {
		margin-top: 1.5rem;
	}

	textarea {
		width: 100%;
		font-family: monospace;
		font-size: 0.85rem;
		padding: 0.5rem;
		border-radius: 4px;
		border: 1px solid #ccc;
	}

	button {
		margin-top: 0.5rem;
		padding: 0.75rem 2rem;
		font-size: 1rem;
		border: none;
		border-radius: 6px;
		background: #2563eb;
		color: white;
		cursor: pointer;
	}

	button:hover {
		background: #1d4ed8;
	}

	.fingerprint {
		font-size: 3rem;
		margin: 1rem 0;
	}

	.fingerprint-hint {
		color: #666;
		font-size: 0.9rem;
	}

	.phone-id {
		font-family: monospace;
		color: #888;
		font-size: 0.8rem;
	}

	.error {
		color: #dc2626;
	}
</style>
