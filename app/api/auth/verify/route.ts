/**
 * app/api/auth/verify/route.ts
 *
 * Verifikasi signature WebAuthn di server dan update counter anti-cloning.
 * Menetapkan session cookie yang terikat ke credential_id pemilik vault.
 */

import { NextRequest, NextResponse } from 'next/server';
import { getVault, updateVaultCounter } from '@/lib/db';
import { verifyAuthentication, createSessionToken } from '@/lib/webauthn';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  const vault = await getVault();
  if (!vault) {
    return NextResponse.json({ error: 'Vault tidak ditemukan' }, { status: 404 });
  }

  let body: {
    authenticationResponse?: AuthenticationResponseJSON;
    recoveryUnlock?: boolean;
  };

  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Body JSON tidak valid' }, { status: 400 });
  }

  // Jalur 1: Autentikasi WebAuthn (Biometrik Android PRF)
  if (body.authenticationResponse) {
    const expectedChallenge = req.cookies.get('auth_challenge')?.value;
    if (!expectedChallenge) {
      return NextResponse.json(
        { error: 'Session challenge autentikasi telah kedaluwarsa atau tidak valid' },
        { status: 400 }
      );
    }

    let verification;
    try {
      verification = await verifyAuthentication({
        response: body.authenticationResponse,
        expectedChallenge,
        credentialId: vault.credential_id,
        credentialPublicKey: vault.public_key,
        currentCounter: vault.counter,
        req,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return NextResponse.json(
        { error: `Verifikasi signature WebAuthn gagal: ${msg}` },
        { status: 400 }
      );
    }

    if (!verification.verified || !verification.authenticationInfo) {
      return NextResponse.json(
        { error: 'Verifikasi WebAuthn gagal' },
        { status: 400 }
      );
    }

    // Naikkan counter di database untuk deteksi cloning
    const newCounter = verification.authenticationInfo.newCounter;
    await updateVaultCounter({
      id: vault.id,
      counter: newCounter,
    });

    // Session token terikat ke credential_id pemilik
    const sessionToken = await createSessionToken(vault.credential_id);
    const res = NextResponse.json({ verified: true });

    res.cookies.delete('auth_challenge');
    res.cookies.set('vault_session', sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 900, // 15 menit
      path: '/',
    });

    return res;
  }

  // Jalur 2: Recovery Passphrase (didekripsi di browser via PBKDF2)
  if (body.recoveryUnlock) {
    const sessionToken = await createSessionToken(vault.credential_id);
    const res = NextResponse.json({ verified: true, method: 'recovery' });

    res.cookies.delete('auth_challenge');
    res.cookies.set('vault_session', sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 900,
      path: '/',
    });

    return res;
  }

  return NextResponse.json(
    { error: 'Tipe verifikasi tidak dikenali' },
    { status: 400 }
  );
}
