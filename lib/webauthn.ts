/**
 * lib/webauthn.ts
 *
 * Helper server-side untuk registrasi dan verifikasi WebAuthn menggunakan @simplewebauthn/server.
 * - Validasi origin dan rpId sesuai domain deploy
 * - Clone detection via counter check
 * - Session token signing via Web Crypto API HMAC-SHA256 yang terikat ke credential_id
 */

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type VerifiedRegistrationResponse,
  type VerifiedAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from '@simplewebauthn/server';
import { bufferToBase64Url } from './crypto';

const RP_NAME = 'secure-vault';
const SESSION_SECRET = process.env.SESSION_SECRET || 'secure-vault-session-key-fallback-secret-2026';

/**
 * Mengambil RP_ID yang valid:
 * 1. process.env.RP_ID jika ada
 * 2. Hostname dari header request / Vercel domain
 * 3. Fallback: 'localhost'
 */
export function getRpId(req?: Request): string {
  if (process.env.RP_ID) return process.env.RP_ID;
  if (process.env.VERCEL_PROJECT_PRODUCTION_URL) return process.env.VERCEL_PROJECT_PRODUCTION_URL;
  if (process.env.VERCEL_URL) return process.env.VERCEL_URL.split(':')[0];
  if (req) {
    const host = req.headers.get('host');
    if (host) return host.split(':')[0];
  }
  return 'localhost';
}

/**
 * Mengambil Expected Origin yang valid:
 * 1. process.env.RP_ORIGIN jika ada
 * 2. Origin dari header request
 * 3. Fallback http://localhost:3000
 */
export function getExpectedOrigin(req?: Request): string {
  if (process.env.RP_ORIGIN) return process.env.RP_ORIGIN;
  if (req) {
    const origin = req.headers.get('origin');
    if (origin) return origin;
    const proto = req.headers.get('x-forwarded-proto') || (req.url.startsWith('https') ? 'https' : 'http');
    const host = req.headers.get('host');
    if (host) return `${proto}://${host}`;
  }
  return 'http://localhost:3000';
}

/**
 * Generate Registration Options untuk WebAuthn.
 * Meminta platform authenticator (Android biometric enclave).
 */
export async function getRegistrationOptions(req: Request) {
  const rpID = getRpId(req);
  return await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID,
    userName: 'vault-owner',
    userDisplayName: 'Vault Owner',
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'required',
      authenticatorAttachment: 'platform',
    },
    supportedAlgorithmIDs: [-7, -257], // ES256, RS256
  });
}

/**
 * Verifikasi Registration Response di server.
 */
export async function verifyRegistration({
  response,
  expectedChallenge,
  req,
}: {
  response: RegistrationResponseJSON;
  expectedChallenge: string;
  req: Request;
}): Promise<VerifiedRegistrationResponse> {
  const expectedRPID = getRpId(req);
  const expectedOrigin = getExpectedOrigin(req);

  return await verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    requireUserVerification: true,
  });
}

/**
 * Generate Authentication Options untuk WebAuthn.
 */
export async function getAuthenticationOptions({
  req,
  credentialId,
}: {
  req: Request;
  credentialId: Uint8Array;
}) {
  const rpID = getRpId(req);
  const credIdBase64 = bufferToBase64Url(credentialId);

  return await generateAuthenticationOptions({
    rpID,
    userVerification: 'required',
    allowCredentials: [
      {
        id: credIdBase64,
        transports: ['internal'],
      },
    ],
  });
}

/**
 * Verifikasi Authentication Response di server.
 * Memastikan signature sah, origin dan RP_ID valid, dan counter tidak mundur (anti-cloning).
 */
export async function verifyAuthentication({
  response,
  expectedChallenge,
  credentialId,
  credentialPublicKey,
  currentCounter,
  req,
}: {
  response: AuthenticationResponseJSON;
  expectedChallenge: string;
  credentialId: Uint8Array;
  credentialPublicKey: Uint8Array;
  currentCounter: number;
  req: Request;
}): Promise<VerifiedAuthenticationResponse> {
  const expectedRPID = getRpId(req);
  const expectedOrigin = getExpectedOrigin(req);

  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    credential: {
      id: bufferToBase64Url(credentialId),
      publicKey: new Uint8Array(credentialPublicKey),
      counter: currentCounter,
    },
    requireUserVerification: true,
  });

  // Anti-cloning check: Jika counter mundur, tolak autentikasi!
  if (verification.verified && verification.authenticationInfo) {
    const newCounter = verification.authenticationInfo.newCounter;
    if (newCounter < currentCounter && (newCounter > 0 || currentCounter > 0)) {
      throw new Error('Deteksi kloning: Authenticator counter mundur!');
    }
  }

  return verification;
}

/**
 * Helper: Buat signed session token (HMAC-SHA256).
 * TERIKAT secara kriptografis ke credentialId pemilik vault.
 */
export async function createSessionToken(credentialId: Uint8Array): Promise<string> {
  const subtle = globalThis.crypto.subtle;
  const payload = JSON.stringify({
    authenticated: true,
    credentialId: bufferToBase64Url(credentialId),
    exp: Date.now() + 15 * 60 * 1000, // 15 menit
  });
  const key = await subtle.importKey(
    'raw',
    new TextEncoder().encode(SESSION_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return `${bufferToBase64Url(new TextEncoder().encode(payload))}.${bufferToBase64Url(sig)}`;
}

/**
 * Helper: Verifikasi session token dari cookie HTTP-only.
 * Memvalidasi HMAC signature, timestamp kedaluwarsa, dan kecocokan credentialId.
 */
export async function verifySessionToken(token: string, expectedCredentialId?: Uint8Array): Promise<boolean> {
  try {
    const subtle = globalThis.crypto.subtle;
    const parts = token.split('.');
    if (parts.length !== 2) return false;
    const payloadBytes = Buffer.from(parts[0], 'base64url');
    const sigBytes = Buffer.from(parts[1], 'base64url');

    const key = await subtle.importKey(
      'raw',
      new TextEncoder().encode(SESSION_SECRET),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const valid = await subtle.verify('HMAC', key, sigBytes, payloadBytes);
    if (!valid) return false;

    const payload = JSON.parse(payloadBytes.toString('utf-8'));
    if (payload.exp < Date.now()) return false;
    if (payload.authenticated !== true) return false;

    if (expectedCredentialId) {
      if (payload.credentialId !== bufferToBase64Url(expectedCredentialId)) {
        return false;
      }
    }

    return true;
  } catch {
    return false;
  }
}
