/**
 * app/api/register/route.ts
 *
 * Registrasi credential WebAuthn platform (Android PRF enclave).
 * - Dijaga oleh environment variable ALLOW_REGISTRATION. Default 'false'.
 * - AC#11 Proteksi Lockout Permanen: Wajib memvalidasi key_wraps berupa array non-kosong.
 * - Session cookie terikat ke credential_id pemilik.
 */

import { NextRequest, NextResponse } from 'next/server';
import { getRegistrationOptions, verifyRegistration, createSessionToken } from '@/lib/webauthn';
import { getVault, createVault } from '@/lib/db';
import { generatePrfSalt, bufferToBase64Url, base64UrlToBuffer, type KeyWrapEntry } from '@/lib/crypto';
import type { RegistrationResponseJSON } from '@simplewebauthn/server';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  // 1. Cek izin registrasi
  if (process.env.ALLOW_REGISTRATION?.trim().toLowerCase() !== 'true') {
    return NextResponse.json(
      { error: 'Registrasi dinonaktifkan (ALLOW_REGISTRATION=false)' },
      { status: 403 }
    );
  }

  // 2. Cek apakah vault sudah terdaftar (hanya 1 vault diperbolehkan)
  const existing = await getVault();
  if (existing) {
    return NextResponse.json(
      { error: 'Vault sudah terdaftar sebelumnya' },
      { status: 400 }
    );
  }

  // 3. Generate registration options WebAuthn
  const options = await getRegistrationOptions(req);

  // 4. Buat prf_salt acak (32 byte) sekali saat registrasi
  const prfSalt = generatePrfSalt();
  const prfSaltBase64 = bufferToBase64Url(prfSalt);

  // 5. Generate UUID untuk vaultId agar client bisa menghitung AAD wrap
  const vaultId = crypto.randomUUID();

  const res = NextResponse.json({
    options,
    prfSalt: prfSaltBase64,
    vaultId,
  });

  res.cookies.set('reg_challenge', options.challenge, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 300,
    path: '/',
  });

  res.cookies.set('reg_vault_id', vaultId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 300,
    path: '/',
  });

  return res;
}

export async function POST(req: NextRequest) {
  // 1. Cek izin registrasi
  if (process.env.ALLOW_REGISTRATION?.trim().toLowerCase() !== 'true') {
    return NextResponse.json(
      { error: 'Registrasi dinonaktifkan (ALLOW_REGISTRATION=false)' },
      { status: 403 }
    );
  }

  // 2. Cek apakah vault sudah ada
  const existing = await getVault();
  if (existing) {
    return NextResponse.json(
      { error: 'Vault sudah terdaftar sebelumnya' },
      { status: 400 }
    );
  }

  const expectedChallenge = req.cookies.get('reg_challenge')?.value;
  const expectedVaultId = req.cookies.get('reg_vault_id')?.value;
  if (!expectedChallenge || !expectedVaultId) {
    return NextResponse.json(
      { error: 'Session challenge registrasi telah kedaluwarsa atau tidak valid' },
      { status: 400 }
    );
  }

  let body: {
    registrationResponse: RegistrationResponseJSON;
    prfSalt: string;
    ciphertext: string;
    iv: string;
    keyWraps: KeyWrapEntry[];
    vaultId: string;
    version?: number;
  };

  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Body JSON tidak valid' }, { status: 400 });
  }

  const { registrationResponse, prfSalt, ciphertext, iv, keyWraps, vaultId, version = 1 } = body;
  if (!registrationResponse || !prfSalt || !ciphertext || !iv || !vaultId) {
    return NextResponse.json(
      { error: 'Parameter registrasi tidak lengkap' },
      { status: 400 }
    );
  }

  // AC#11 Proteksi Lockout Permanen: key_wraps wajib berupa array dan tidak boleh kosong
  if (!Array.isArray(keyWraps) || keyWraps.length === 0) {
    return NextResponse.json(
      { error: 'Validasi gagal: key_wraps wajib berupa array non-kosong (AC#11 lockout protection)' },
      { status: 400 }
    );
  }

  if (vaultId !== expectedVaultId) {
    return NextResponse.json(
      { error: 'Vault ID tidak sesuai dengan challenge session' },
      { status: 400 }
    );
  }

  // 3. Verifikasi signature WebAuthn di server
  let verification;
  try {
    verification = await verifyRegistration({
      response: registrationResponse,
      expectedChallenge,
      req,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json(
      { error: `Verifikasi registrasi gagal: ${msg}` },
      { status: 400 }
    );
  }

  if (!verification.verified || !verification.registrationInfo) {
    return NextResponse.json(
      { error: 'Verifikasi WebAuthn gagal di server' },
      { status: 400 }
    );
  }

  const { credential } = verification.registrationInfo;

  // 4. Simpan ke database
  const credentialIdBytes = typeof credential.id === 'string'
    ? base64UrlToBuffer(credential.id)
    : new Uint8Array(credential.id);
  const publicKeyBytes = credential.publicKey;
  const counterNumber = credential.counter ?? 0;
  const prfSaltBytes = base64UrlToBuffer(prfSalt);
  const ciphertextBytes = base64UrlToBuffer(ciphertext);
  const ivBytes = base64UrlToBuffer(iv);

  if (ivBytes.length !== 12) {
    return NextResponse.json({ error: 'IV harus tepat 12 byte' }, { status: 400 });
  }

  await createVault({
    id: vaultId,
    credentialId: credentialIdBytes,
    publicKey: publicKeyBytes,
    counter: counterNumber,
    prfSalt: prfSaltBytes,
    ciphertext: ciphertextBytes,
    iv: ivBytes,
    keyWraps,
    version,
  });

  // 5. Buat session token yang terikat secara kriptografis ke credentialId
  const sessionToken = await createSessionToken(credentialIdBytes);

  const res = NextResponse.json({ success: true, vaultId });
  res.cookies.delete('reg_challenge');
  res.cookies.delete('reg_vault_id');
  res.cookies.set('vault_session', sessionToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 900, // 15 menit
    path: '/',
  });

  return res;
}
