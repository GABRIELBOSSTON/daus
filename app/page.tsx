'use client';

/**
 * app/page.tsx
 *
 * Secure Vault Frontend (Next.js 15 App Router, TypeScript strict mode).
 * - Tombol "Buka Vault" (WebAuthn PRF biometrik Android)
 * - Tampilan list kredensial terdekripsi di memori browser
 * - Form edit / tambah kredensial dengan re-enkripsi IV 12-byte baru
 * - Fallback jalur pemulihan: Passphrase PBKDF2 (600.000 iterasi) dengan salt 16-byte khusus
 * - Key Wrapping terpisah di key_wraps dengan AAD: `${vaultId}|${entry.id}|${version}`
 * - Entry prf-1 membawa HKDF salt 32-byte acak tersendiri di params.salt
 * - Model Keamanan: Plaintext dan Kunci TIDAK PERNAH dikirim ke server atau disimpan ke disk/storage.
 */

import { useState, useEffect } from 'react';
import {
  bufferToBase64Url,
  base64UrlToBuffer,
  derivePrfKey,
  deriveRecoveryKey,
  wrapDEK,
  unwrapDEK,
  encryptVaultPlaintext,
  decryptVaultCiphertext,
  generateDEK,
  generateHkdfSalt,
  generatePbkdf2Salt,
  generateRecoveryPassphrase,
  type KeyWrapEntry,
} from '@/lib/crypto';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from '@simplewebauthn/server';

interface CredentialItem {
  id: string;
  title: string;
  username: string;
  password: string;
  url?: string;
  notes?: string;
}

interface WebAuthnPrfOutput {
  prf?: {
    results?: {
      first?: ArrayBuffer;
    };
  };
}

export default function VaultPage() {
  // Device & Platform Capability
  const [platformSupported, setPlatformSupported] = useState<boolean | null>(null);
  const [checkingPlatform, setCheckingPlatform] = useState(true);

  // Vault State
  const [vaultExists, setVaultExists] = useState<boolean | null>(null);
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [loading, setLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState<string>('');

  // Unlocked Data (In-Memory Only! Never persisted to storage)
  const [credentials, setCredentials] = useState<CredentialItem[]>([]);
  const [dek, setDek] = useState<CryptoKey | null>(null);
  const [vaultId, setVaultId] = useState<string | null>(null);
  const [version, setVersion] = useState<number>(1);
  const [unlockMethod, setUnlockMethod] = useState<'prf' | 'recovery' | null>(null);

  // Recovery UI State
  const [showRecoveryInput, setShowRecoveryInput] = useState(false);
  const [recoveryPassphraseInput, setRecoveryPassphraseInput] = useState('');
  const [newRecoveryPassphrase, setNewRecoveryPassphrase] = useState<string | null>(null);

  // Edit / Form State
  const [isEditing, setIsEditing] = useState(false);
  const [visiblePasswords, setVisiblePasswords] = useState<Record<string, boolean>>({});

  // Form input untuk credential baru
  const [newTitle, setNewTitle] = useState('');
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newUrl, setNewUrl] = useState('');
  const [newNotes, setNewNotes] = useState('');

  // Deteksi dukungan platform biometrik (Android Fingerprint / Face Unlock enclave)
  useEffect(() => {
    async function checkCapabilities() {
      try {
        if (typeof window !== 'undefined' && window.PublicKeyCredential) {
          const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
          setPlatformSupported(available);
        } else {
          setPlatformSupported(false);
        }
      } catch {
        setPlatformSupported(false);
      } finally {
        setCheckingPlatform(false);
      }
    }
    checkCapabilities();
    checkVaultRegistration();
  }, []);

  async function checkVaultRegistration() {
    try {
      const res = await fetch('/api/auth/challenge');
      if (res.status === 404) {
        setVaultExists(false);
      } else if (res.ok) {
        setVaultExists(true);
      } else {
        setVaultExists(false);
      }
    } catch {
      setVaultExists(false);
    }
  }

  // =========================================================================
  // 1. ALUR REGISTRASI (WebAuthn PRF + Recovery Passphrase)
  // =========================================================================
  async function handleRegister() {
    setLoading(true);
    setErrorMessage('');
    setStatusMessage('Menyiapkan pendaftaran WebAuthn PRF...');

    try {
      // 1. Ambil opsi registrasi, prf_salt, dan target vaultId dari server
      const optRes = await fetch('/api/register');
      if (!optRes.ok) {
        const errData = await optRes.json();
        throw new Error(errData.error || 'Gagal mengambil opsi registrasi');
      }
      const { options, prfSalt: prfSaltB64, vaultId: regVaultId } = await optRes.json();
      const prfSaltBytes = base64UrlToBuffer(prfSaltB64);

      // 2. Buat Master DEK (Data Encryption Key) acak
      const masterDek = await generateDEK();

      // 3. Generate recovery passphrase (12 kata) & K_recovery via PBKDF2 (600.000 iterasi)
      const generatedPassphrase = generateRecoveryPassphrase();
      setNewRecoveryPassphrase(generatedPassphrase);

      // Salt 16 byte acak khusus untuk recovery-1 (tidak memakai ulang prf_salt)
      const pbkdf2SaltBytes = generatePbkdf2Salt();
      setStatusMessage('Menghitung K_recovery lewat PBKDF2 (600.000 iterasi, salt 16 byte)...');
      const recoveryKey = await deriveRecoveryKey(generatedPassphrase, pbkdf2SaltBytes);

      // Wrap DEK dengan recoveryKey menggunakan AAD `${vaultId}|recovery-1|1`
      const { wrappedKeyBytes: recWrapBytes, iv: recWrapIV } = await wrapDEK({
        dek: masterDek,
        kek: recoveryKey,
        vaultId: regVaultId,
        entryId: 'recovery-1',
        version: 1,
      });

      const recoveryWrapEntry: KeyWrapEntry = {
        id: 'recovery-1',
        type: 'recovery',
        iv: bufferToBase64Url(recWrapIV),
        wrappedKey: bufferToBase64Url(recWrapBytes),
        params: {
          kdf: 'pbkdf2-sha256',
          salt: bufferToBase64Url(pbkdf2SaltBytes),
          iterations: 600000,
        },
      };

      const keyWrapsList: KeyWrapEntry[] = [recoveryWrapEntry];
      let registrationResponse: RegistrationResponseJSON | null = null;

      // 4. Jika platform biometrik didukung, daftarkan WebAuthn PRF
      if (platformSupported) {
        setStatusMessage('Sentuh sensor biometrik Android untuk mendaftarkan credential...');

        const credential = (await navigator.credentials.create({
          publicKey: {
            ...options,
            challenge: base64UrlToBuffer(options.challenge),
            user: {
              ...options.user,
              id: base64UrlToBuffer(options.user.id),
            },
            excludeCredentials: options.excludeCredentials?.map(
              (c: { id: string; type: string; transports?: AuthenticatorTransport[] }) => ({
                ...c,
                id: base64UrlToBuffer(c.id),
              })
            ),
            extensions: {
              prf: {
                eval: {
                  first: prfSaltBytes,
                },
              },
            },
          },
        })) as PublicKeyCredential;

        if (!credential) {
          throw new Error('Pendaftaran dibatalkan atau credential kosong');
        }

        const extResults = credential.getClientExtensionResults() as unknown as WebAuthnPrfOutput;
        const prfResult = extResults?.prf?.results?.first;

        if (prfResult) {
          // HKDF salt 32 byte acak tersendiri untuk prf-1
          const hkdfSaltBytes = generateHkdfSalt();
          setStatusMessage('Menderivasi K_prf via HKDF-SHA256 (info="vault-v1-kek")...');
          const prfKey = await derivePrfKey(new Uint8Array(prfResult), hkdfSaltBytes);

          // Wrap DEK dengan prfKey menggunakan AAD `${vaultId}|prf-1|1`
          const { wrappedKeyBytes: prfWrapBytes, iv: prfWrapIV } = await wrapDEK({
            dek: masterDek,
            kek: prfKey,
            vaultId: regVaultId,
            entryId: 'prf-1',
            version: 1,
          });

          keyWrapsList.unshift({
            id: 'prf-1',
            type: 'prf',
            iv: bufferToBase64Url(prfWrapIV),
            wrappedKey: bufferToBase64Url(prfWrapBytes),
            params: {
              kdf: 'hkdf-sha256',
              info: 'vault-v1-kek',
              salt: bufferToBase64Url(hkdfSaltBytes),
            },
          });
        }

        registrationResponse = {
          id: credential.id,
          rawId: bufferToBase64Url(credential.rawId),
          response: {
            attestationObject: bufferToBase64Url(
              (credential.response as AuthenticatorAttestationResponse).attestationObject
            ),
            clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
          },
          type: 'public-key',
          clientExtensionResults: extResults as unknown as AuthenticationExtensionsClientOutputs,
        };
      } else {
        throw new Error(
          'Platform Authenticator tidak tersedia. Registrasi WebAuthn PRF memerlukan perangkat Android yang mendukung.'
        );
      }

      // 5. Buat sample initial vault data
      const initialVaultData: CredentialItem[] = [
        {
          id: 'cred-1',
          title: 'Akun Utama',
          username: 'admin',
          password: 'PasswordSuperRahasia!2026',
          url: 'https://vault.example.com',
          notes: 'Kredensial contoh pertama Anda. Terenkripsi dengan AES-256-GCM.',
        },
      ];

      setStatusMessage('Mengenkripsi plaintext vault dengan DEK AES-256-GCM baru...');
      const { ciphertextBytes, iv: vaultIV } = await encryptVaultPlaintext({
        plaintext: JSON.stringify(initialVaultData),
        dek: masterDek,
      });

      // 6. Kirim ke /api/register
      setStatusMessage('Menyimpan ciphertext & key_wraps ke server...');
      const regRes = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          registrationResponse,
          prfSalt: prfSaltB64,
          ciphertext: bufferToBase64Url(ciphertextBytes),
          iv: bufferToBase64Url(vaultIV),
          keyWraps: keyWrapsList,
          vaultId: regVaultId,
          version: 1,
        }),
      });

      if (!regRes.ok) {
        const err = await regRes.json();
        throw new Error(err.error || 'Gagal menyimpan registrasi ke server');
      }

      // Sukses
      setVaultExists(true);
      setVaultId(regVaultId);
      setVersion(1);
      setCredentials(initialVaultData);
      setDek(masterDek);
      setIsUnlocked(true);
      setUnlockMethod('prf');
      setStatusMessage('Vault berhasil dibuat dan terbuka!');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(err);
      setErrorMessage(msg || 'Registrasi gagal');
      setStatusMessage('');
    } finally {
      setLoading(false);
    }
  }

  // =========================================================================
  // 2. ALUR BUKA VAULT (WebAuthn PRF Biometrik Android)
  // =========================================================================
  async function handleUnlockWebAuthn() {
    setLoading(true);
    setErrorMessage('');
    setStatusMessage('Meminta challenge dari server...');

    try {
      // 1. GET /api/auth/challenge
      const challengeRes = await fetch('/api/auth/challenge');
      if (!challengeRes.ok) {
        const errData = await challengeRes.json();
        throw new Error(errData.error || 'Gagal mengambil challenge');
      }

      const {
        options,
        vaultId: vId,
        prfSalt: prfSaltB64,
        ciphertext: ciphertextB64,
        iv: ivB64,
        keyWraps,
        version: vVersion,
      } = await challengeRes.json();

      setVaultId(vId);
      setVersion(vVersion);

      const prfSaltBytes = base64UrlToBuffer(prfSaltB64);
      const ciphertextBytes = base64UrlToBuffer(ciphertextB64);
      const vaultIV = base64UrlToBuffer(ivB64);

      // Cari wrap entry prf-1
      const prfWrapEntry = keyWraps.find((w: KeyWrapEntry) => w.type === 'prf');
      if (!prfWrapEntry || !prfWrapEntry.params.salt) {
        throw new Error('Tidak ditemukan entry prf lengkap di key_wraps');
      }

      const hkdfSaltBytes = base64UrlToBuffer(prfWrapEntry.params.salt);

      // 2. Evaluasi WebAuthn PRF di perangkat Android
      setStatusMessage('Sentuh sensor biometrik (sidik jari / Face Unlock) di perangkat Android...');

      const credential = (await navigator.credentials.get({
        publicKey: {
          ...options,
          challenge: base64UrlToBuffer(options.challenge),
          allowCredentials: options.allowCredentials?.map(
            (c: { id: string; type: string; transports?: AuthenticatorTransport[] }) => ({
              id: base64UrlToBuffer(c.id),
              type: 'public-key',
              transports: c.transports,
            })
          ),
          extensions: {
            prf: {
              eval: {
                first: prfSaltBytes,
              },
            },
          },
        },
      })) as PublicKeyCredential;

      if (!credential) {
        throw new Error('Otorisasi biometrik dibatalkan');
      }

      const extResults = credential.getClientExtensionResults() as unknown as WebAuthnPrfOutput;
      const prfResult = extResults?.prf?.results?.first;

      if (!prfResult) {
        throw new Error(
          'Output WebAuthn PRF tidak diterima dari authenticator. Silakan gunakan Jalur Pemulihan (Recovery Passphrase).'
        );
      }

      // 3. HKDF-SHA256(prfOutput, salt=hkdfSalt, info="vault-v1-kek") -> K_prf
      setStatusMessage('Menghitung kunci HKDF-SHA256...');
      const prfKey = await derivePrfKey(new Uint8Array(prfResult), hkdfSaltBytes);

      // 4. Unwrap DEK dengan AAD `${vaultId}|${entry.id}|${version}`
      setStatusMessage('Membuka wrap DEK dengan verifikasi AAD...');
      const unlockedDek = await unwrapDEK({
        wrappedKeyBytes: base64UrlToBuffer(prfWrapEntry.wrappedKey),
        iv: base64UrlToBuffer(prfWrapEntry.iv),
        kek: prfKey,
        vaultId: vId,
        entryId: prfWrapEntry.id,
        version: vVersion,
      });

      // 5. Dekripsi ciphertext vault dengan DEK dan vaultIV
      setStatusMessage('Mendekripsi data vault...');
      const plaintext = await decryptVaultCiphertext({
        ciphertextBytes,
        iv: vaultIV,
        dek: unlockedDek,
      });

      // 6. Kirim signature ke /api/auth/verify untuk validasi server & update clone counter
      setStatusMessage('Memvalidasi signature dan memperbarui anti-cloning counter...');
      const authResponsePayload: AuthenticationResponseJSON = {
        id: credential.id,
        rawId: bufferToBase64Url(credential.rawId),
        response: {
          authenticatorData: bufferToBase64Url(
            (credential.response as AuthenticatorAssertionResponse).authenticatorData
          ),
          clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
          signature: bufferToBase64Url(
            (credential.response as AuthenticatorAssertionResponse).signature
          ),
          userHandle: (credential.response as AuthenticatorAssertionResponse).userHandle
            ? bufferToBase64Url(
                (credential.response as AuthenticatorAssertionResponse).userHandle!
              )
            : undefined,
        },
        type: 'public-key',
        clientExtensionResults: extResults as unknown as AuthenticationExtensionsClientOutputs,
      };

      const verifyRes = await fetch('/api/auth/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          authenticationResponse: authResponsePayload,
        }),
      });

      if (!verifyRes.ok) {
        const err = await verifyRes.json();
        throw new Error(err.error || 'Verifikasi server gagal');
      }

      // Parse kredensial
      const parsedCredentials: CredentialItem[] = JSON.parse(plaintext);
      setCredentials(parsedCredentials);
      setDek(unlockedDek);
      setIsUnlocked(true);
      setUnlockMethod('prf');
      setStatusMessage('Vault berhasil dibuka!');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(err);
      setErrorMessage(msg || 'Gagal membuka vault');
      setStatusMessage('');
    } finally {
      setLoading(false);
    }
  }

  // =========================================================================
  // 3. ALUR BUKA VAULT JALUR PEMULIHAN (Recovery Passphrase / PBKDF2)
  // =========================================================================
  async function handleUnlockRecovery() {
    if (!recoveryPassphraseInput.trim()) {
      setErrorMessage('Masukkan recovery passphrase terlebih dahulu.');
      return;
    }

    setLoading(true);
    setErrorMessage('');
    setStatusMessage('Mengambil ciphertext dan key_wraps dari server...');

    try {
      const challengeRes = await fetch('/api/auth/challenge');
      if (!challengeRes.ok) {
        throw new Error('Gagal mengambil data dari server');
      }
      const {
        vaultId: vId,
        ciphertext: ciphertextB64,
        iv: ivB64,
        keyWraps,
        version: vVersion,
      } = await challengeRes.json();

      setVaultId(vId);
      setVersion(vVersion);

      const ciphertextBytes = base64UrlToBuffer(ciphertextB64);
      const vaultIV = base64UrlToBuffer(ivB64);

      // Cari wrap entry recovery-1
      const recWrapEntry = keyWraps.find((w: KeyWrapEntry) => w.type === 'recovery');
      if (!recWrapEntry || !recWrapEntry.params.salt) {
        throw new Error('Tidak ditemukan entry recovery di key_wraps');
      }

      const pbkdf2SaltBytes = base64UrlToBuffer(recWrapEntry.params.salt);

      setStatusMessage('Menghitung PBKDF2 (600.000 iterasi) dengan normalisasi NFKD...');
      const recoveryKey = await deriveRecoveryKey(
        recoveryPassphraseInput,
        pbkdf2SaltBytes
      );

      setStatusMessage('Membuka wrap DEK dengan verifikasi AAD...');
      const unlockedDek = await unwrapDEK({
        wrappedKeyBytes: base64UrlToBuffer(recWrapEntry.wrappedKey),
        iv: base64UrlToBuffer(recWrapEntry.iv),
        kek: recoveryKey,
        vaultId: vId,
        entryId: recWrapEntry.id,
        version: vVersion,
      });

      setStatusMessage('Mendekripsi data vault...');
      const plaintext = await decryptVaultCiphertext({
        ciphertextBytes,
        iv: vaultIV,
        dek: unlockedDek,
      });

      // Beritahu server untuk menetapkan cookie sesi
      await fetch('/api/auth/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recoveryUnlock: true }),
      });

      const parsed: CredentialItem[] = JSON.parse(plaintext);
      setCredentials(parsed);
      setDek(unlockedDek);
      setIsUnlocked(true);
      setUnlockMethod('recovery');
      setShowRecoveryInput(false);
      setStatusMessage('Vault berhasil dibuka via Jalur Pemulihan!');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(err);
      setErrorMessage(
        'Gagal mendekripsi: Recovery passphrase salah atau data rusak. ' + (msg || '')
      );
      setStatusMessage('');
    } finally {
      setLoading(false);
    }
  }

  // =========================================================================
  // 4. SIMPAN PERUBAHAN KE VAULT (Re-enkripsi dengan IV 12-byte baru)
  // =========================================================================
  async function handleSaveVault(updatedCredentials: CredentialItem[]) {
    if (!dek) {
      setErrorMessage('Kunci dekripsi (DEK) tidak tersedia di memori. Buka vault kembali.');
      return;
    }

    setLoading(true);
    setErrorMessage('');
    setStatusMessage('Mengenkripsi ulang vault dengan IV 12-byte baru...');

    try {
      // Re-enkripsi data dengan DEK dan IV 12-byte baru (TIDAK PERNAH pakai ulang IV)
      const { ciphertextBytes: newCiphertextBytes, iv: newVaultIV } = await encryptVaultPlaintext({
        plaintext: JSON.stringify(updatedCredentials),
        dek,
      });

      // Kirim ciphertext baru ke /api/vault
      setStatusMessage('Menyimpan ciphertext baru ke server...');
      const res = await fetch('/api/vault', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ciphertext: bufferToBase64Url(newCiphertextBytes),
          iv: bufferToBase64Url(newVaultIV),
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Gagal menyimpan vault ke server');
      }

      setCredentials(updatedCredentials);
      setIsEditing(false);
      setStatusMessage('Perubahan vault berhasil dienkripsi dan disimpan!');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(err);
      setErrorMessage(msg || 'Gagal menyimpan perubahan');
      setStatusMessage('');
    } finally {
      setLoading(false);
    }
  }

  // Tambah item kredensial baru
  function handleAddCredential() {
    if (!newTitle.trim() || !newUsername.trim() || !newPassword.trim()) {
      setErrorMessage('Judul, username, dan password wajib diisi.');
      return;
    }

    const newItem: CredentialItem = {
      id: `cred-${Date.now()}`,
      title: newTitle.trim(),
      username: newUsername.trim(),
      password: newPassword,
      url: newUrl.trim() || undefined,
      notes: newNotes.trim() || undefined,
    };

    const updated = [...credentials, newItem];
    setNewTitle('');
    setNewUsername('');
    setNewPassword('');
    setNewUrl('');
    setNewNotes('');
    handleSaveVault(updated);
  }

  // Hapus item kredensial
  function handleDeleteCredential(id: string) {
    if (!confirm('Hapus kredensial ini dari vault?')) return;
    const updated = credentials.filter((c) => c.id !== id);
    handleSaveVault(updated);
  }

  // Kunci kembali vault (bersihkan memori secara instan)
  function handleLockVault() {
    setCredentials([]);
    setDek(null);
    setVaultId(null);
    setIsUnlocked(false);
    setIsEditing(false);
    setStatusMessage('Vault telah dikunci. Memori dibersihkan.');
  }

  // Toggle visibilitas password
  function togglePassword(id: string) {
    setVisiblePasswords((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  }

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-start p-4 md:p-8">
      <div className="w-full max-w-3xl space-y-6">
        {/* HEADER */}
        <header className="border-b border-slate-800 pb-5 text-center md:text-left flex flex-col md:flex-row justify-between items-center gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 bg-emerald-500/10 border border-emerald-500/30 rounded-full text-emerald-400 text-xs font-mono uppercase tracking-wider mb-2">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              Zero-Knowledge Credential Vault
            </div>
            <h1 className="text-3xl font-extrabold tracking-tight text-white">
              Secure Vault
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Enkripsi AES-256-GCM + WebAuthn PRF Extension (Android Secure Enclave)
            </p>
          </div>

          {isUnlocked && (
            <button
              onClick={handleLockVault}
              className="px-4 py-2 bg-rose-600/20 hover:bg-rose-600/30 border border-rose-500/40 text-rose-300 text-sm font-medium rounded-lg transition"
            >
              🔒 Kunci Vault
            </button>
          )}
        </header>

        {/* STATUS & ERROR ALERTS */}
        {statusMessage && (
          <div className="p-3 bg-blue-950/60 border border-blue-600/40 text-blue-300 rounded-lg text-sm flex items-center gap-2">
            <span className="animate-spin text-base">⏳</span>
            <span>{statusMessage}</span>
          </div>
        )}

        {errorMessage && (
          <div className="p-3 bg-rose-950/60 border border-rose-600/40 text-rose-300 rounded-lg text-sm">
            <strong>Error:</strong> {errorMessage}
          </div>
        )}

        {/* MODAL / BANNER RECOVERY CODE DISPLAY ON REGISTRATION */}
        {newRecoveryPassphrase && (
          <div className="p-5 bg-amber-950/40 border border-amber-600/50 rounded-xl space-y-3">
            <div className="flex items-center gap-2 text-amber-400 font-bold text-base">
              <span>⚠️</span>
              <h3>PENTING: SIMPAN RECOVERY PASSPHRASE ANDA SEKARANG</h3>
            </div>
            <p className="text-xs text-amber-200/90 leading-relaxed">
              Jika HP Android Anda hilang atau rusak tanpa kode ini, vault Anda akan{' '}
              <strong>hilang permanen</strong> dan tidak ada orang di dunia yang bisa membukanya
              (karena server tidak memegang kunci). Catat kode ini di tempat aman / kertas fisik:
            </p>
            <div className="p-3 bg-slate-900 border border-amber-700/60 rounded-lg font-mono text-sm text-amber-300 select-all break-all">
              {newRecoveryPassphrase}
            </div>
            <div className="flex flex-col sm:flex-row gap-2 pt-1">
              <button
                onClick={() => {
                  navigator.clipboard.writeText(newRecoveryPassphrase);
                  alert('Recovery Passphrase berhasil disalin ke clipboard!');
                }}
                className="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold text-xs rounded-lg transition"
              >
                📋 Salin ke Clipboard
              </button>
              <button
                onClick={() => setNewRecoveryPassphrase(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-lg border border-slate-700 transition"
              >
                Saya Telah Mencatat Kode Ini
              </button>
            </div>
          </div>
        )}

        {/* MAIN BODY: LOCKED STATE */}
        {!isUnlocked && (
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 md:p-8 space-y-6 shadow-xl">
            {/* Security Indicator */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs text-slate-400">
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                <span className="text-slate-500 block mb-1">Android Platform Biometrics:</span>
                {checkingPlatform ? (
                  <span>Memeriksa dukungan...</span>
                ) : platformSupported ? (
                  <span className="text-emerald-400 font-semibold flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                    Tersedia (Platform Authenticator)
                  </span>
                ) : (
                  <span className="text-amber-400 font-semibold flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-amber-500"></span>
                    Tidak Tersedia (Gunakan Fallback Recovery)
                  </span>
                )}
              </div>
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                <span className="text-slate-500 block mb-1">Status Vault Database:</span>
                {vaultExists === null ? (
                  <span>Memeriksa database...</span>
                ) : vaultExists ? (
                  <span className="text-cyan-400 font-semibold flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-cyan-500"></span>
                    Vault Terdaftar (Ciphertext Tersimpan)
                  </span>
                ) : (
                  <span className="text-slate-400 font-semibold flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-slate-500"></span>
                    Belum Terdaftar
                  </span>
                )}
              </div>
            </div>

            {/* ACTION BUTTONS */}
            {vaultExists ? (
              <div className="space-y-4 pt-2">
                <button
                  onClick={handleUnlockWebAuthn}
                  disabled={loading}
                  className="w-full py-4 px-6 bg-emerald-600 hover:bg-emerald-500 active:scale-[0.99] disabled:opacity-50 text-white font-bold text-lg rounded-xl shadow-lg shadow-emerald-950/40 transition flex items-center justify-center gap-3"
                >
                  <span className="text-2xl">📱</span>
                  <span>Buka Vault dengan Biometrik Android</span>
                </button>

                <div className="text-center">
                  <button
                    onClick={() => setShowRecoveryInput(!showRecoveryInput)}
                    className="text-xs text-slate-400 hover:text-slate-200 underline transition"
                  >
                    {showRecoveryInput
                      ? 'Sembunyikan Jalur Pemulihan'
                      : 'Buka dengan Recovery Passphrase (PBKDF2 600.000 iterasi)'}
                  </button>
                </div>

                {showRecoveryInput && (
                  <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
                    <label className="block text-xs font-semibold text-slate-300">
                      Masukkan 12-kata Recovery Passphrase:
                    </label>
                    <input
                      type="password"
                      value={recoveryPassphraseInput}
                      onChange={(e) => setRecoveryPassphraseInput(e.target.value)}
                      placeholder="alpha-beacon-canyon-delta-..."
                      className="w-full p-3 bg-slate-900 border border-slate-700 rounded-lg text-sm font-mono text-slate-100 focus:outline-none focus:border-emerald-500"
                    />
                    <button
                      onClick={handleUnlockRecovery}
                      disabled={loading || !recoveryPassphraseInput}
                      className="w-full py-2.5 px-4 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white text-sm font-semibold rounded-lg transition"
                    >
                      Buka via Recovery Passphrase
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <div className="space-y-4 pt-2">
                <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl text-center space-y-2">
                  <p className="text-sm text-slate-300 font-medium">
                    Vault belum diinisialisasi.
                  </p>
                  <p className="text-xs text-slate-500">
                    Klik tombol di bawah untuk mendaftarkan secure enclave Android Anda via WebAuthn PRF.
                  </p>
                </div>

                <button
                  onClick={handleRegister}
                  disabled={loading}
                  className="w-full py-4 px-6 bg-cyan-600 hover:bg-cyan-500 active:scale-[0.99] disabled:opacity-50 text-white font-bold text-lg rounded-xl shadow-lg shadow-cyan-950/40 transition flex items-center justify-center gap-3"
                >
                  <span className="text-2xl">🔑</span>
                  <span>Inisialisasi & Daftarkan Vault Baru</span>
                </button>
              </div>
            )}
          </div>
        )}

        {/* MAIN BODY: UNLOCKED STATE */}
        {isUnlocked && (
          <div className="space-y-6">
            {/* Status Pill */}
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center bg-slate-900/60 border border-slate-800 p-4 rounded-xl gap-2">
              <div>
                <span className="text-xs text-slate-400 block">Jalur Dekripsi:</span>
                <span className="text-sm font-semibold text-emerald-400">
                  {unlockMethod === 'prf'
                    ? '🛡️ WebAuthn PRF (Secure Enclave Android + HKDF-SHA256)'
                    : '🔑 Passphrase Pemulihan (PBKDF2 600.000 iterasi)'}
                </span>
                {vaultId && (
                  <span className="text-[11px] text-slate-500 block mt-0.5">
                    Vault ID: {vaultId.slice(0, 8)}... (v{version})
                  </span>
                )}
              </div>
              <div className="text-xs text-slate-400">
                Total Kredensial:{' '}
                <span className="font-bold text-white">{credentials.length}</span>
              </div>
            </div>

            {/* CREDENTIALS LIST */}
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <h2 className="text-lg font-bold text-white">Daftar Kredensial Terdekripsi</h2>
                <button
                  onClick={() => setIsEditing(!isEditing)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-semibold rounded-lg text-slate-200 border border-slate-700 transition"
                >
                  {isEditing ? 'Tutup Form Tambah' : '+ Tambah Akun'}
                </button>
              </div>

              {/* FORM TAMBAH KREDENSIAL */}
              {isEditing && (
                <div className="p-5 bg-slate-900 border border-slate-700/80 rounded-xl space-y-3 shadow-lg">
                  <h3 className="text-sm font-bold text-white">+ Tambah Kredensial Baru</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div>
                      <label className="text-xs text-slate-400 block mb-1">Judul / Layanan *</label>
                      <input
                        type="text"
                        value={newTitle}
                        onChange={(e) => setNewTitle(e.target.value)}
                        placeholder="Contoh: GitHub, AWS, Google"
                        className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-100"
                      />
                    </div>
                    <div>
                      <label className="text-xs text-slate-400 block mb-1">Username / Email *</label>
                      <input
                        type="text"
                        value={newUsername}
                        onChange={(e) => setNewUsername(e.target.value)}
                        placeholder="username / email"
                        className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-100"
                      />
                    </div>
                    <div>
                      <label className="text-xs text-slate-400 block mb-1">Password *</label>
                      <input
                        type="text"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        placeholder="kata sandi"
                        className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-100 font-mono"
                      />
                    </div>
                    <div>
                      <label className="text-xs text-slate-400 block mb-1">URL (Opsional)</label>
                      <input
                        type="text"
                        value={newUrl}
                        onChange={(e) => setNewUrl(e.target.value)}
                        placeholder="https://..."
                        className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-100"
                      />
                    </div>
                  </div>
                  <div>
                    <label className="text-xs text-slate-400 block mb-1">Catatan Tambahan (Opsional)</label>
                    <textarea
                      value={newNotes}
                      onChange={(e) => setNewNotes(e.target.value)}
                      placeholder="Recovery code, PIN, token tambahan..."
                      rows={2}
                      className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-100"
                    />
                  </div>
                  <div className="flex justify-end gap-2 pt-2">
                    <button
                      onClick={() => setIsEditing(false)}
                      className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-xs rounded-lg text-slate-300"
                    >
                      Batal
                    </button>
                    <button
                      onClick={handleAddCredential}
                      disabled={loading || !newTitle || !newUsername || !newPassword}
                      className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-bold text-xs rounded-lg"
                    >
                      Enkripsi & Simpan ke Vault
                    </button>
                  </div>
                </div>
              )}

              {/* LIST ITEMS */}
              {credentials.length === 0 ? (
                <div className="p-8 text-center text-slate-500 bg-slate-900/40 border border-slate-800 rounded-xl text-sm">
                  Belum ada kredensial tersimpan di vault ini.
                </div>
              ) : (
                credentials.map((cred) => (
                  <div
                    key={cred.id}
                    className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-3 hover:border-slate-700 transition"
                  >
                    <div className="flex justify-between items-start">
                      <div>
                        <h4 className="font-bold text-white text-base">{cred.title}</h4>
                        {cred.url && (
                          <a
                            href={cred.url}
                            target="_blank"
                            rel="noreferrer"
                            className="text-xs text-cyan-400 hover:underline"
                          >
                            {cred.url}
                          </a>
                        )}
                      </div>
                      <button
                        onClick={() => handleDeleteCredential(cred.id)}
                        className="text-xs text-rose-400 hover:text-rose-300 px-2 py-1 rounded bg-rose-950/30 border border-rose-900/40"
                      >
                        Hapus
                      </button>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                      <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                        <span className="text-slate-500 block">Username:</span>
                        <div className="flex justify-between items-center mt-0.5">
                          <span className="font-mono text-slate-200 select-all">
                            {cred.username}
                          </span>
                          <button
                            onClick={() => {
                              navigator.clipboard.writeText(cred.username);
                              alert('Username disalin!');
                            }}
                            className="text-[10px] text-slate-400 hover:text-white"
                          >
                            Copy
                          </button>
                        </div>
                      </div>

                      <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                        <span className="text-slate-500 block">Password:</span>
                        <div className="flex justify-between items-center mt-0.5">
                          <span className="font-mono text-slate-200 select-all">
                            {visiblePasswords[cred.id] ? cred.password : '••••••••••••••••'}
                          </span>
                          <div className="flex gap-2">
                            <button
                              onClick={() => togglePassword(cred.id)}
                              className="text-[10px] text-slate-400 hover:text-white"
                            >
                              {visiblePasswords[cred.id] ? 'Hide' : 'Show'}
                            </button>
                            <button
                              onClick={() => {
                                navigator.clipboard.writeText(cred.password);
                                alert('Password disalin!');
                              }}
                              className="text-[10px] text-slate-400 hover:text-white"
                            >
                              Copy
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>

                    {cred.notes && (
                      <div className="p-2.5 bg-slate-950/80 rounded-lg border border-slate-800/80 text-xs">
                        <span className="text-slate-500 block mb-0.5">Catatan:</span>
                        <p className="text-slate-300 font-mono whitespace-pre-wrap select-all">
                          {cred.notes}
                        </p>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </div>
    </main>
  );
}
