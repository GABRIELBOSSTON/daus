/**
 * app/api/auth/challenge/route.ts
 *
 * Mengirim WebAuthn challenge + ciphertext, IV, prfSalt, credentialId, keyWraps, dan version ke client.
 * Server TIDAK PERNAH mengirim plaintext. Dekripsi terjadi secara lokal di browser.
 */

import { NextRequest, NextResponse } from 'next/server';
import { getVault } from '@/lib/db';
import { getAuthenticationOptions } from '@/lib/webauthn';
import { bufferToBase64Url } from '@/lib/crypto';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const vault = await getVault();
  if (!vault) {
    return NextResponse.json(
      { error: 'Vault belum terdaftar. Silakan lakukan registrasi awal terlebih dahulu.' },
      { status: 404 }
    );
  }

  // Generate opsi autentikasi WebAuthn
  const authOptions = await getAuthenticationOptions({
    req,
    credentialId: vault.credential_id,
  });

  const res = NextResponse.json({
    challenge: authOptions.challenge,
    options: authOptions,
    vaultId: vault.id,
    credentialId: bufferToBase64Url(vault.credential_id),
    prfSalt: bufferToBase64Url(vault.prf_salt),
    ciphertext: bufferToBase64Url(vault.ciphertext),
    iv: bufferToBase64Url(vault.iv),
    keyWraps: vault.key_wraps,
    version: vault.version,
  });

  // Simpan challenge ke cookie HTTP-only untuk diverifikasi saat POST /api/auth/verify
  res.cookies.set('auth_challenge', authOptions.challenge, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 300,
    path: '/',
  });

  return res;
}
