/* CrimeWatch — E2E Encryption (WebCrypto API) — crypto.js
 *
 * Flow:
 *  1. Fetch server RSA-OAEP public key (PEM) from /api/keys/public
 *  2. For each report: generate fresh AES-256-GCM key
 *  3. Encrypt report JSON with AES-GCM  → ciphertext + IV + tag
 *  4. Wrap AES key with server RSA public key (OAEP-SHA256)
 *  5. Send: encrypted_payload, encryption_iv, encryption_tag, wrapped_key
 *  Server decrypts only when an officer explicitly requests plaintext.
 */

const CW_CRYPTO = (() => {
  let _serverPublicKey = null; // CryptoKey (RSA-OAEP)

  // ── HELPERS ────────────────────────────────────────────────
  function b64encode(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }
  function b64decode(str) {
    return Uint8Array.from(atob(str), c => c.charCodeAt(0)).buffer;
  }
  function pemToBuffer(pem) {
    const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
    return b64decode(b64);
  }

  // ── IMPORT SERVER PUBLIC KEY (RSA-OAEP) ───────────────────
  async function importServerPublicKey(pem) {
    const keyBuffer = pemToBuffer(pem);
    _serverPublicKey = await crypto.subtle.importKey(
      'spki', keyBuffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false, ['wrapKey']
    );
    return _serverPublicKey;
  }

  // ── GENERATE CLIENT ECDH KEY PAIR (for future client-client E2E) ──
  async function generateClientKeyPair() {
    const pair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true, ['deriveKey']
    );
    const pub = await crypto.subtle.exportKey('spki', pair.publicKey);
    return {
      keyPair: pair,
      publicKeyPem: `-----BEGIN PUBLIC KEY-----\n${b64encode(pub)}\n-----END PUBLIC KEY-----`,
    };
  }

  // ── ENCRYPT REPORT ────────────────────────────────────────
  async function encryptReport(reportObj) {
    if (!_serverPublicKey) throw new Error('Server public key not loaded. Call loadServerKey() first.');

    // 1. Encode payload
    const plaintext = new TextEncoder().encode(JSON.stringify(reportObj));

    // 2. Generate fresh AES-256-GCM key
    const aesKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );

    // 3. Generate random 12-byte IV
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // 4. Encrypt: AES-GCM outputs ciphertext + 16-byte tag appended
    const ciphertextWithTag = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      aesKey, plaintext
    );
    const ciphertext = ciphertextWithTag.slice(0, ciphertextWithTag.byteLength - 16);
    const tag        = ciphertextWithTag.slice(ciphertextWithTag.byteLength - 16);

    // 5. Wrap AES key with server RSA-OAEP public key
    const wrappedKey = await crypto.subtle.wrapKey(
      'raw', aesKey, _serverPublicKey,
      { name: 'RSA-OAEP' }
    );

    return {
      encrypted_payload: b64encode(ciphertext),
      encryption_iv:     b64encode(iv),
      encryption_tag:    b64encode(tag),
      wrapped_key:       b64encode(wrappedKey),
    };
  }

  // ── LOAD SERVER KEY FROM API ──────────────────────────────
  async function loadServerKey(apiBase = '') {
    const res  = await fetch(`${apiBase}/api/keys/public`);
    const data = await res.json();
    await importServerPublicKey(data.public_key);
    return data;
  }

  // ── GENERATE RANDOM HASH (client_id) ──────────────────────
  async function generateClientId() {
    const arr = crypto.getRandomValues(new Uint8Array(16));
    return 'CW-' + Date.now() + '-' + b64encode(arr).replace(/[+/=]/g, '').slice(0, 8);
  }

  return { loadServerKey, encryptReport, generateClientKeyPair, generateClientId, b64encode, b64decode };
})();

export default CW_CRYPTO;
