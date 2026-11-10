/**
 * app/api/vault/route.ts
 *
 * Menerima ciphertext dan IV baru saat user mengedit kredensial di vault,
 * atau key_wraps baru saat rotasi DEK.
 * - Dilindungi oleh session cookie terikat ke credential_id pemilik.
 * - AC#11 Proteksi Lockout Permanen: Wajib menolak penulisan jika key_wraps kosong atau bukan array.
 */

import { NextRequest, NextResponse } from 'next/server';
import { getVault, updateVaultCiphertext, updateVaultKeyWraps } from '@/lib/db';
import { verifySessionToken } from '@/lib/webauthn';
import { base64UrlToBuffer, type KeyWrapEntry } from '@/lib/crypto';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  // 1. Ambil vault yang ada
  const vault = await getVault();
  if (!vault) {
    return NextResponse.json({ error: 'Vault tidak ditemukan' }, { status: 404 });
  }

  // 2. Verifikasi sesi aktif dan terikat ke credentialId pemilik vault
  const sessionCookie = req.cookies.get('vault_session')?.value;
  if (!sessionCookie || !(await verifySessionToken(sessionCookie, vault.credential_id))) {
    return NextResponse.json(
      { error: 'Sesi tidak valid, tidak cocok dengan credential_id, atau telah kedaluwarsa. Silakan buka vault kembali.' },
      { status: 401 }
    );
  }

  let body: {
    ciphertext?: string;
    iv?: string;
    keyWraps?: KeyWrapEntry[];
    version?: number;
  };

  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Body JSON tidak valid' }, { status: 400 });
  }

  const { ciphertext, iv, keyWraps, version } = body;
  if (!ciphertext || !iv) {
    return NextResponse.json(
      { error: 'Ciphertext dan IV wajib disertakan' },
      { status: 400 }
    );
  }

  // AC#11 Proteksi Lockout Permanen: Jika payload menyertakan keyWraps, tolak jika bukan array non-kosong
  if (keyWraps !== undefined) {
    if (!Array.isArray(keyWraps) || keyWraps.length === 0) {
      return NextResponse.json(
        { error: 'Validasi gagal: key_wraps tidak boleh kosong atau bukan array (AC#11 lockout protection)' },
        { status: 400 }
      );
    }
  }

  const ciphertextBytes = base64UrlToBuffer(ciphertext);
  const ivBytes = base64UrlToBuffer(iv);

  if (ivBytes.length !== 12) {
    return NextResponse.json(
      { error: 'IV harus berukuran tepat 12 byte' },
      { status: 400 }
    );
  }

  if (ciphertextBytes.length === 0) {
    return NextResponse.json(
      { error: 'Ciphertext tidak boleh kosong' },
      { status: 400 }
    );
  }

  // 3. Update database
  if (keyWraps !== undefined && version !== undefined) {
    // Update rotasi DEK
    await updateVaultKeyWraps({
      id: vault.id,
      ciphertext: ciphertextBytes,
      iv: ivBytes,
      keyWraps,
      version,
    });
  } else {
    // Update ciphertext & IV biasa
    await updateVaultCiphertext({
      id: vault.id,
      ciphertext: ciphertextBytes,
      iv: ivBytes,
    });
  }

  return NextResponse.json({ success: true });
}
