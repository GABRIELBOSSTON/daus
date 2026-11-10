/**
 * lib/db.ts
 *
 * Layer akses database Postgres untuk tabel `vault`.
 * Menggunakan driver serverless Neon (@neondatabase/serverless).
 * Mendukung pooled endpoint (-pooler) dan sslmode=require.
 * TIDAK ADA fallback lokal storage. Gagal keras jika DATABASE_URL/POSTGRES_URL tidak ada.
 */

import { neon } from '@neondatabase/serverless';
import type { KeyWrapEntry } from './crypto';

export interface VaultRow {
  id: string;
  credential_id: Uint8Array;
  public_key: Uint8Array;
  counter: number;
  prf_salt: Uint8Array;
  ciphertext: Uint8Array;
  iv: Uint8Array;
  key_wraps: KeyWrapEntry[];
  version: number;
  created_at: Date;
  updated_at: Date;
}

/**
 * Validasi dan normalisasi connection string Neon.
 * Memastikan sslmode=require terpasang dan memberi peringatan bila belum memakai pooled endpoint (-pooler).
 */
function getValidatedNeonConnectionString(): string {
  const rawUrl = process.env.DATABASE_URL || process.env.POSTGRES_URL;
  if (!rawUrl) {
    throw new Error('DATABASE_URL atau POSTGRES_URL environment variable wajib dikonfigurasi.');
  }

  let url = rawUrl.trim();

  // Pastikan sslmode=require
  if (!url.includes('sslmode=')) {
    url += (url.includes('?') ? '&' : '?') + 'sslmode=require';
  }

  // Peringatan jika belum menggunakan endpoint pooled (-pooler) pada domain neon.tech
  if (url.includes('neon.tech') && !url.includes('-pooler')) {
    console.warn(
      '[Neon DB] Disarankan menggunakan endpoint pooled Neon (-pooler pada hostname) untuk koneksi serverless Vercel guna mencegah batas koneksi Postgres tercapai.'
    );
  }

  return url;
}

let sqlClient: ReturnType<typeof neon> | null = null;

function ensureClient(): ReturnType<typeof neon> {
  if (!sqlClient) {
    const url = getValidatedNeonConnectionString();
    sqlClient = neon(url);
  }
  return sqlClient;
}

function toUint8Array(val: unknown): Uint8Array {
  if (val instanceof Uint8Array) return val;
  if (Buffer.isBuffer(val)) return new Uint8Array(val.buffer, val.byteOffset, val.byteLength);
  if (typeof val === 'string') {
    if (val.startsWith('\\x')) {
      return new Uint8Array(Buffer.from(val.slice(2), 'hex'));
    }
    return new Uint8Array(Buffer.from(val, 'hex'));
  }
  return new Uint8Array(Buffer.from(String(val)));
}

function parseKeyWraps(val: unknown): KeyWrapEntry[] {
  if (Array.isArray(val)) return val as KeyWrapEntry[];
  if (typeof val === 'string') {
    return JSON.parse(val) as KeyWrapEntry[];
  }
  return [];
}

/**
 * Mengambil record vault yang tersimpan.
 */
export async function getVault(): Promise<VaultRow | null> {
  const sql = ensureClient();
  const rows = (await sql`
    SELECT id, credential_id, public_key, counter, prf_salt, ciphertext, iv, key_wraps, version, created_at, updated_at
    FROM vault
    ORDER BY created_at ASC
    LIMIT 1
  `) as Record<string, unknown>[];

  if (!rows || rows.length === 0) return null;
  const row = rows[0];

  return {
    id: String(row.id),
    credential_id: toUint8Array(row.credential_id),
    public_key: toUint8Array(row.public_key),
    counter: Number(row.counter),
    prf_salt: toUint8Array(row.prf_salt),
    ciphertext: toUint8Array(row.ciphertext),
    iv: toUint8Array(row.iv),
    key_wraps: parseKeyWraps(row.key_wraps),
    version: Number(row.version),
    created_at: new Date(String(row.created_at)),
    updated_at: new Date(String(row.updated_at)),
  };
}

/**
 * Menyimpan credential, key_wraps, dan ciphertext pertama kali saat registrasi.
 */
export async function createVault({
  id,
  credentialId,
  publicKey,
  counter,
  prfSalt,
  ciphertext,
  iv,
  keyWraps,
  version = 1,
}: {
  id?: string;
  credentialId: Uint8Array;
  publicKey: Uint8Array;
  counter: number;
  prfSalt: Uint8Array;
  ciphertext: Uint8Array;
  iv: Uint8Array;
  keyWraps: KeyWrapEntry[];
  version?: number;
}): Promise<VaultRow> {
  const sql = ensureClient();
  const rows = (id
    ? await sql`
        INSERT INTO vault (
          id,
          credential_id,
          public_key,
          counter,
          prf_salt,
          ciphertext,
          iv,
          key_wraps,
          version,
          updated_at
        ) VALUES (
          ${id},
          ${Buffer.from(credentialId)},
          ${Buffer.from(publicKey)},
          ${counter},
          ${Buffer.from(prfSalt)},
          ${Buffer.from(ciphertext)},
          ${Buffer.from(iv)},
          ${JSON.stringify(keyWraps)},
          ${version},
          now()
        )
        RETURNING id, credential_id, public_key, counter, prf_salt, ciphertext, iv, key_wraps, version, created_at, updated_at
      `
    : await sql`
        INSERT INTO vault (
          credential_id,
          public_key,
          counter,
          prf_salt,
          ciphertext,
          iv,
          key_wraps,
          version,
          updated_at
        ) VALUES (
          ${Buffer.from(credentialId)},
          ${Buffer.from(publicKey)},
          ${counter},
          ${Buffer.from(prfSalt)},
          ${Buffer.from(ciphertext)},
          ${Buffer.from(iv)},
          ${JSON.stringify(keyWraps)},
          ${version},
          now()
        )
        RETURNING id, credential_id, public_key, counter, prf_salt, ciphertext, iv, key_wraps, version, created_at, updated_at
      `) as Record<string, unknown>[];

  const row = rows[0];
  return {
    id: String(row.id),
    credential_id: toUint8Array(row.credential_id),
    public_key: toUint8Array(row.public_key),
    counter: Number(row.counter),
    prf_salt: toUint8Array(row.prf_salt),
    ciphertext: toUint8Array(row.ciphertext),
    iv: toUint8Array(row.iv),
    key_wraps: parseKeyWraps(row.key_wraps),
    version: Number(row.version),
    created_at: new Date(String(row.created_at)),
    updated_at: new Date(String(row.updated_at)),
  };
}

/**
 * Mengupdate ciphertext dan IV baru saat user melakukan edit pada vault.
 * Diperbarui juga kolom updated_at = now().
 */
export async function updateVaultCiphertext({
  id,
  ciphertext,
  iv,
}: {
  id: string;
  ciphertext: Uint8Array;
  iv: Uint8Array;
}): Promise<void> {
  const sql = ensureClient();
  await sql`
    UPDATE vault
    SET ciphertext = ${Buffer.from(ciphertext)},
        iv = ${Buffer.from(iv)},
        updated_at = now()
    WHERE id = ${id}
  `;
}

/**
 * Mengupdate key_wraps dan version (saat terjadi rotasi DEK).
 */
export async function updateVaultKeyWraps({
  id,
  ciphertext,
  iv,
  keyWraps,
  version,
}: {
  id: string;
  ciphertext: Uint8Array;
  iv: Uint8Array;
  keyWraps: KeyWrapEntry[];
  version: number;
}): Promise<void> {
  const sql = ensureClient();
  await sql`
    UPDATE vault
    SET ciphertext = ${Buffer.from(ciphertext)},
        iv = ${Buffer.from(iv)},
        key_wraps = ${JSON.stringify(keyWraps)},
        version = ${version},
        updated_at = now()
    WHERE id = ${id}
  `;
}

/**
 * Mengupdate counter autentikasi untuk clone detection.
 */
export async function updateVaultCounter({
  id,
  counter,
}: {
  id: string;
  counter: number;
}): Promise<void> {
  const sql = ensureClient();
  await sql`
    UPDATE vault
    SET counter = ${counter},
        updated_at = now()
    WHERE id = ${id}
  `;
}
