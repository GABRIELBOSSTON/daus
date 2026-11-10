/**
 * lib/crypto.ts
 *
 * Implementasi kriptografi murni menggunakan native Web Crypto API (SubtleCrypto).
 * Sesuai spesifikasi arsitektur secure-vault & RECOVERY-DESIGN.md:
 * - HKDF-SHA256(prfOutput, salt=hkdfSalt, info="vault-v1-kek") -> Kunci KEK PRF
 *   (hkdfSalt acak 32 byte disimpan di params.salt pada entry prf-1, terpisah dari kolom prf_salt)
 * - Normalisasi Passphrase: NFKD + trim + lowercase sebelum PBKDF2
 * - PBKDF2-SHA256 dengan 600.000 iterasi dan salt acak 16 byte tersendiri untuk recovery-1
 * - Key Wrapping DEK dengan AAD: `${vaultId}|${entry.id}|${version}`
 * - Rotasi DEK eksplisit: generate DEK baru, enkripsi ulang body, bungkus ulang key_wraps, naikkan version
 * - Ciphertext murni hanya berisi enkripsi vault (AES-256-GCM) oleh DEK
 * - IV 12-byte baru di setiap enkripsi ulang (TIDAK PERNAH pakai ulang IV)
 * - prf_salt DIBUAT SEKALI saat registrasi khusus untuk extensions.prf.eval.first
 */

// Helper untuk kompatibilitas type BufferSource di TypeScript 5.5+
function asBufferSource(b: Uint8Array | ArrayBuffer): BufferSource {
  return b as unknown as BufferSource;
}

// Helper: Konversi Uint8Array / ArrayBuffer ke Base64URL
export function bufferToBase64Url(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// Helper: Konversi Base64URL string ke Uint8Array
export function base64UrlToBuffer(b64url: string): Uint8Array {
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) {
    b64 += '=';
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Normalisasi Passphrase kanonik: NFKD + trim + lowercase.
 * Memastikan variasi representasi karakter Unicode atau kapitalisasi tidak merusak derivasi kunci.
 */
export function normalizePassphrase(passphrase: string): string {
  return passphrase.normalize('NFKD').trim().toLowerCase();
}

/**
 * Buat prf_salt acak berukuran 32 byte untuk WebAuthn PRF.
 * Dibuat HANYA SEKALI saat registrasi dan disimpan di database kolom prf_salt.
 */
export function generatePrfSalt(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Buat HKDF salt acak 32 byte untuk entry prf-1 (params.salt).
 * Terpisah dari kolom prf_salt di database.
 */
export function generateHkdfSalt(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Buat PBKDF2 salt acak 16 byte khusus untuk entry recovery-1 (params.salt).
 * Terpisah dari kolom prf_salt di database.
 */
export function generatePbkdf2Salt(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(16));
}

/**
 * Buat IV acak 12 byte untuk AES-GCM.
 * WAJIB: Selalu buat IV baru untuk setiap enkripsi atau wrap.
 */
export function generateIV(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(12));
}

/**
 * Menghasilkan recovery passphrase yang aman dan berkekuatan tinggi (12 kata acak).
 */
export function generateRecoveryPassphrase(): string {
  const words = [
    'alpha', 'beacon', 'canyon', 'delta', 'ember', 'falcon', 'glacier', 'horizon',
    'island', 'jupiter', 'kestrel', 'lagoon', 'meadow', 'nebula', 'oasis', 'pulsar',
    'quartz', 'river', 'summit', 'timber', 'ursa', 'valley', 'zenith', 'aurora',
    'breeze', 'cascade', 'dune', 'echo', 'forest', 'granite', 'harbor', 'icicle'
  ];
  const indices = globalThis.crypto.getRandomValues(new Uint8Array(12));
  return Array.from(indices).map(idx => words[idx % words.length]).join('-');
}

/**
 * Derivasi K_prf dari 32-byte deterministik output WebAuthn PRF extension.
 * HKDF-SHA256(prfOutput, salt=hkdfSalt, info="vault-v1-kek") -> AES-GCM 256-bit Key.
 */
export async function derivePrfKey(prfOutput: Uint8Array, hkdfSalt: Uint8Array): Promise<CryptoKey> {
  const subtle = globalThis.crypto.subtle;
  const ikm = await subtle.importKey(
    'raw',
    asBufferSource(prfOutput),
    'HKDF',
    false,
    ['deriveKey']
  );

  return await subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: asBufferSource(hkdfSalt),
      info: asBufferSource(new TextEncoder().encode('vault-v1-kek')),
    },
    ikm,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Derivasi K_recovery dari recovery passphrase menggunakan PBKDF2-SHA256 (600.000 iterasi).
 * Passphrase dinormalisasi kanonik (NFKD + trim + lowercase).
 * Menggunakan salt acak 16 byte khusus milik entry recovery-1.
 */
export async function deriveRecoveryKey(passphrase: string, pbkdf2Salt: Uint8Array): Promise<CryptoKey> {
  const subtle = globalThis.crypto.subtle;
  const normalized = normalizePassphrase(passphrase);

  const passwordKey = await subtle.importKey(
    'raw',
    asBufferSource(new TextEncoder().encode(normalized)),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return await subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: asBufferSource(pbkdf2Salt),
      iterations: 600000,
      hash: 'SHA-256',
    },
    passwordKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Format Additional Authenticated Data (AAD) untuk wrap/unwrap:
 * `${vaultId}|${entryId}|${version}`
 */
export function buildWrapAad(vaultId: string, entryId: string, version: number): Uint8Array {
  return new TextEncoder().encode(`${vaultId}|${entryId}|${version}`);
}

/**
 * Struktur entry di dalam kolom database `key_wraps` (JSONB).
 */
export interface KeyWrapEntry {
  id: string; // contoh: "prf-1", "recovery-1"
  type: 'prf' | 'recovery';
  iv: string; // Base64URL 12 byte
  wrappedKey: string; // Base64URL raw DEK terenkripsi AES-GCM dengan AAD
  params: {
    kdf: string;
    info?: string;
    salt?: string; // Base64URL (16 byte untuk PBKDF2, 32 byte untuk HKDF)
    iterations?: number;
  };
}

/**
 * Wrap raw DEK dengan KEK (Key Encryption Key) menggunakan AES-GCM + AAD.
 */
export async function wrapDEK({
  dek,
  kek,
  vaultId,
  entryId,
  version,
}: {
  dek: CryptoKey;
  kek: CryptoKey;
  vaultId: string;
  entryId: string;
  version: number;
}): Promise<{ wrappedKeyBytes: Uint8Array; iv: Uint8Array }> {
  const subtle = globalThis.crypto.subtle;
  const rawDek = await subtle.exportKey('raw', dek);
  const iv = generateIV();
  const aad = buildWrapAad(vaultId, entryId, version);

  const wrappedBuffer = await subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: asBufferSource(iv),
      additionalData: asBufferSource(aad),
    },
    kek,
    asBufferSource(rawDek)
  );

  return {
    wrappedKeyBytes: new Uint8Array(wrappedBuffer),
    iv,
  };
}

/**
 * Unwrap raw DEK dari wrappedKey menggunakan KEK dan verifikasi AAD.
 * Jika entry dipindah ke vaultId lain atau version diubah, autentikasi GCM gagal keras.
 */
export async function unwrapDEK({
  wrappedKeyBytes,
  iv,
  kek,
  vaultId,
  entryId,
  version,
}: {
  wrappedKeyBytes: Uint8Array;
  iv: Uint8Array;
  kek: CryptoKey;
  vaultId: string;
  entryId: string;
  version: number;
}): Promise<CryptoKey> {
  const subtle = globalThis.crypto.subtle;
  const aad = buildWrapAad(vaultId, entryId, version);

  const rawDek = await subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: asBufferSource(iv),
      additionalData: asBufferSource(aad),
    },
    kek,
    asBufferSource(wrappedKeyBytes)
  );

  return await subtle.importKey(
    'raw',
    asBufferSource(rawDek),
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Enkripsi data vault murni menggunakan DEK dan IV 12-byte baru.
 */
export async function encryptVaultPlaintext({
  plaintext,
  dek,
}: {
  plaintext: string;
  dek: CryptoKey;
}): Promise<{ ciphertextBytes: Uint8Array; iv: Uint8Array }> {
  const subtle = globalThis.crypto.subtle;
  const iv = generateIV();

  const encBuffer = await subtle.encrypt(
    { name: 'AES-GCM', iv: asBufferSource(iv) },
    dek,
    asBufferSource(new TextEncoder().encode(plaintext))
  );

  return {
    ciphertextBytes: new Uint8Array(encBuffer),
    iv,
  };
}

/**
 * Dekripsi data vault murni menggunakan DEK dan IV dari database.
 */
export async function decryptVaultCiphertext({
  ciphertextBytes,
  iv,
  dek,
}: {
  ciphertextBytes: Uint8Array;
  iv: Uint8Array;
  dek: CryptoKey;
}): Promise<string> {
  const subtle = globalThis.crypto.subtle;

  const plainBuffer = await subtle.decrypt(
    { name: 'AES-GCM', iv: asBufferSource(iv) },
    dek,
    asBufferSource(ciphertextBytes)
  );

  return new TextDecoder().decode(plainBuffer);
}

/**
 * Generate DEK AES-256 acak baru.
 */
export async function generateDEK(): Promise<CryptoKey> {
  return await globalThis.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Rotasi DEK Eksplisit (AC#12):
 * 1. Generate Master DEK baru.
 * 2. Enkripsi ulang plaintext body dengan IV 12-byte baru.
 * 3. Naikkan nomor versi (version + 1).
 * 4. Bungkus ulang DEK baru untuk setiap KEK yang ada dengan AAD baru: `${vaultId}|${entry.id}|${newVersion}`.
 */
export async function rotateVaultDEK({
  plaintext,
  vaultId,
  oldVersion,
  kekEntries,
}: {
  plaintext: string;
  vaultId: string;
  oldVersion: number;
  kekEntries: { id: string; type: 'prf' | 'recovery'; kek: CryptoKey; params: KeyWrapEntry['params'] }[];
}): Promise<{
  newCiphertextBytes: Uint8Array;
  newVaultIV: Uint8Array;
  newKeyWraps: KeyWrapEntry[];
  newVersion: number;
  newDek: CryptoKey;
}> {
  const newDek = await generateDEK();
  const newVersion = oldVersion + 1;

  // Enkripsi ulang plaintext dengan DEK baru & IV baru
  const { ciphertextBytes: newCiphertextBytes, iv: newVaultIV } = await encryptVaultPlaintext({
    plaintext,
    dek: newDek,
  });

  // Re-wrap DEK baru untuk setiap jalur akses dengan AAD versi baru
  const newKeyWraps: KeyWrapEntry[] = [];
  for (const entry of kekEntries) {
    const { wrappedKeyBytes, iv: wrapIV } = await wrapDEK({
      dek: newDek,
      kek: entry.kek,
      vaultId,
      entryId: entry.id,
      version: newVersion,
    });

    newKeyWraps.push({
      id: entry.id,
      type: entry.type,
      iv: bufferToBase64Url(wrapIV),
      wrappedKey: bufferToBase64Url(wrappedKeyBytes),
      params: entry.params,
    });
  }

  return {
    newCiphertextBytes,
    newVaultIV,
    newKeyWraps,
    newVersion,
    newDek,
  };
}
