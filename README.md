# Secure Vault — Zero-Knowledge Credential Store

Aplikasi penyimpanan kredensial terenkripsi berbasis **Next.js 15 (App Router, TypeScript)** yang memanfaatkan **WebAuthn PRF Extension** di Android Secure Enclave (TEE/StrongBox) dan enkripsi simetris **AES-256-GCM**.

Deploy target: **Vercel** + **Neon Serverless Postgres**.

---

## 1. Kenapa Neon Dipilih (Menggantikan Supabase)

Pada arsitektur password vault pribadi yang hanya dibuka sesekali:

1. **Masalah Hibernasi Supabase**: Tier gratis Supabase mem-pause (*sleep/hibernate*) project database setelah 7 hari berturut-turut tanpa aktivitas. Pemulihannya (*restore*) harus dilakukan secara manual lewat login ke dashboard Supabase dan menunggu beberapa menit. Ini berbahaya bagi password vault pribadi: saat kredensial mendesak dibutuhkan, database justru tidak bisa diakses (*deadlock*).
2. **Neon Auto-Resume Instan**: Neon menggunakan arsitektur *separation of storage and compute* berbasis serverless. Ketika ada query masuk, komputasi Neon **auto-resume dalam ratusan milidetik** secara transparan tanpa intervensi manusia, lalu kembali scale-to-zero saat tidak digunakan.
3. **Koneksi Serverless Vercel (@neondatabase/serverless)**: Driver TCP tradisional (`postgres` / `pg`) dapat menyebabkan *connection pooling exhaustion* pada ephemeral Vercel Serverless Functions. Driver `@neondatabase/serverless` menggunakan HTTP/WebSocket query pooling bawaan Neon (`-pooler`) yang sepenuhnya stateless dan tahan lonjakan request.

---

## 2. Model Keamanan (Non-Negotiable)

1. **Server Zero-Knowledge**: Server dan Database **TIDAK PERNAH** memegang kunci enkripsi maupun plaintext kredensial.
2. **Dekripsi Hanya di Browser**: Dekripsi seluruhnya terjadi di memori browser pengguna menggunakan **Web Crypto API** native.
3. **Kunci Tidak Pernah Disimpan**: Kunci (DEK/KEK) atau turunannya **TIDAK PERNAH** disimpan ke database, cookie, `localStorage`, maupun `sessionStorage`.
4. **Key Wrapping & AAD**: Master DEK (AES-256) di-wrap per jalur akses di dalam kolom `key_wraps` (JSONB) dengan AAD `${vaultId}|${entry.id}|${version}`. Pemindahan wrapped DEK antar record ditolak keras oleh AES-GCM authentication tag.
5. **Integritas Salt & IV**:
   - `prf_salt` (32 byte) dibuat sekali saat registrasi khusus untuk `extensions.prf.eval.first`.
   - `prf-1` memiliki salt acak 32 byte tersendiri untuk HKDF (`info="vault-v1-kek"`).
   - `recovery-1` memiliki salt acak 16 byte tersendiri untuk PBKDF2 (tidak memakai ulang `prf_salt`).
   - Setiap kali isi vault diedit atau disimpan, **IV 12-byte baru dan acak** selalu dihasilkan (*zero IV reuse*).
6. **Normalisasi Kanonik**: Passphrase pemulihan dinormalisasi dengan `NFKD + trim + lowercase` sebelum masuk ke PBKDF2 (600.000 iterasi).
7. **Proteksi Lockout Permanen (AC#11)**: Server menolak penulisan yang menyisakan `key_wraps` kosong atau bukan array.
8. **Rotasi Kunci Eksplisit (AC#12)**: Tersedia fungsi `rotateVaultDEK` untuk menerbitkan DEK baru, IV baru, menaikkan version, dan meng-invalidasi seluruh wrap lama.
9. **Fail-Hard DB**: Tidak ada fallback storage lokal. Jika `DATABASE_URL` tidak dikonfigurasi, sistem gagal keras saat startup.
10. **Session Cookie Terikat**: Session cookie HMAC-SHA256 terikat secara kriptografis ke `credential_id` pemilik dengan masa berlaku pendek (15 menit), `HttpOnly`, `Secure`, `SameSite=Strict`. Cookie ini **hanya** mengotorisasi request simpan ke `/api/vault` agar orang asing tidak bisa menimpa database, dan **tidak pernah bisa mendekripsi** vault.

---

## 3. Skema Database (`db/migrations/001_init.sql`)

Eksekusi skema berikut di **Neon SQL Editor**:

```sql
create table if not exists vault (
  id            uuid primary key default gen_random_uuid(),
  credential_id bytea not null,
  public_key    bytea not null,
  counter       bigint not null default 0,
  prf_salt      bytea not null,
  ciphertext    bytea not null,
  iv            bytea not null,
  key_wraps     jsonb not null,
  version       int not null default 1,
  created_at    timestamptz default now(),
  updated_at    timestamptz default now()
);

-- Index untuk mempercepat lookup credential_id
create index if not exists idx_vault_credential_id on vault(credential_id);
```

---

## 4. Daftar Environment Variable Vercel yang Wajib Diisi

Konfigurasikan variabel lingkungan berikut di **Vercel Dashboard** (`Project Settings -> Environment Variables`):

| Nama Variable | Deskripsi & Format | Contoh Nilai |
|---|---|---|
| `DATABASE_URL` | Connection string PostgreSQL dari Neon. **Wajib** mencentang opsi *"Pooled connection"* di console Neon agar hostname mengandung `-pooler`, serta memiliki parameter `sslmode=require`. | `postgresql://user:pass@ep-cool-flower-123456-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require` |
| `ALLOW_REGISTRATION` | Guard endpoint registrasi. Set ke `true` **hanya saat pertama kali mendaftarkan credential**. Setelah pendaftaran berhasil, segera ubah menjadi `false` agar endpoint terkunci permanen. | `false` (default) / `true` (saat inisialisasi) |
| `RP_ID` | Domain Relying Party WebAuthn tanpa protokol dan tanpa port. Harus cocok dengan domain deployment Vercel Anda. | `secure-vault.vercel.app` (atau domain kustom) |
| `RP_ORIGIN` | Origin lengkap Relying Party termasuk skema `https://`. Harus cocok persis dengan URL yang diakses browser Android. | `https://secure-vault.vercel.app` |
| `SESSION_SECRET` | Kunci rahasia minimal 32 karakter acak untuk HMAC token penandatangan session cookie. | `openssl rand -hex 32` |

> [!IMPORTANT]
> **Prosedur Registrasi Pertama Kali di Vercel**:
> 1. Isi seluruh environment variable di Vercel, dengan `ALLOW_REGISTRATION=true`.
> 2. Buka aplikasi di Chrome Android, tekan tombol **"Inisialisasi & Daftarkan Vault Baru"**.
> 3. Lakukan verifikasi sidik jari / biometric prompt bawaan Android.
> 4. **CATAT 12-KATA RECOVERY PASSPHRASE** yang muncul di layar ke kertas fisik atau manajer sandi terpisah.
> 5. Masuk kembali ke Vercel Dashboard, ubah `ALLOW_REGISTRATION` menjadi `false`, dan lakukan redeploy.

---

## 5. Panduan Setup Neon dari Awal

1. Buat akun di [console.neon.tech](https://console.neon.tech).
2. Buat project baru (misal: `secure-vault-db`).
3. Buka tab **SQL Editor** di console Neon, paste seluruh isi berkas [`db/migrations/001_init.sql`](file:///d:/daus/secure-vault/db/migrations/001_init.sql), lalu tekan tombol **Run**.
4. Kembali ke tab **Dashboard**, pada bagian **Connection Details**:
   - Pilih database `neondb`.
   - Centang opsi **Pooled connection**.
   - Salin URL koneksi yang berakhiran `-pooler...neondb?sslmode=require`.
5. Masukkan URL tersebut sebagai `DATABASE_URL` di Vercel.

---

## 6. Audit Keamanan Endpoint Direct `curl`

Bila setiap endpoint dipanggil langsung via `curl` tanpa melewati antarmuka browser:

1. **`GET /api/register`** (saat `ALLOW_REGISTRATION=false`):
   ```bash
   curl.exe -i -s http://localhost:3000/api/register
   ```
   *Output*: `HTTP/1.1 403 Forbidden` -> `{"error":"Registrasi dinonaktifkan (ALLOW_REGISTRATION=false)"}`.
2. **`GET /api/auth/challenge`**:
   ```bash
   curl.exe -i -s http://localhost:3000/api/auth/challenge
   ```
   *Output*: Hanya mengembalikan opsi challenge WebAuthn, `vaultId`, dan string base64url acak `ciphertext`, `iv`, `keyWraps`. **Nol plaintext.**
3. **`POST /api/vault`**:
   ```bash
   curl.exe -i -s -X POST http://localhost:3000/api/vault -H "Content-Type: application/json" -d "{}"
   ```
   *Output*: `HTTP/1.1 401 Unauthorized` (ditolak keras karena ketiadaan session cookie yang terikat ke `credential_id`).

---

## 7. Hasil Pengujian Eksekusi Acceptance Criteria

Semua pengujian kriptografi dan siklus hidup dijalankan menggunakan `npx tsx test-suite.ts` langsung meng-import modul [`lib/crypto.ts`](file:///d:/daus/secure-vault/lib/crypto.ts) dan [`lib/webauthn.ts`](file:///d:/daus/secure-vault/lib/webauthn.ts):

| AC | Deskripsi Kriteria | Status | Catatan Verifikasi |
|---|---|---|---|
| **AC#1** | `npm run build` lolos tanpa error TypeScript/ESLint | **PASS** | Exit code 0, 5/5 route terkompilasi bersih tanpa warning. |
| **AC#2** | Registrasi di Chrome Android dengan biometrik | **UNTESTED** | Memerlukan perangkat Android fisik asli (diuji langsung oleh user). |
| **AC#3** | Buka vault biometrik PRF Android | **UNTESTED** | Memerlukan perangkat Android fisik asli (diuji langsung oleh user). |
| **AC#4** | `curl` endpoint tidak pernah mengembalikan plaintext | **PASS** | 403 pada registrasi, fail-hard 500 / 401 pada DB jika tidak terotorisasi. |
| **AC#5** | Raw dump tabel database nol plaintext | **PARTIAL** | Teruji bersih pada Postgres 16 WASM (PGlite); remote TCP diuji saat koneksi Neon live. |
| **AC#6** | Edit isi vault → re-enkripsi IV baru → reload bisa dibuka | **PASS** | IV lama !== IV baru, panjang tepat 12 byte acak. |
| **AC#7** | Recovery passphrase membuka vault tanpa WebAuthn | **PASS** | PBKDF2 600.000 iterasi meng-unwrap DEK secara offline di browser. |
| **AC#8** | Siklus hidup: Daftar → Kunci → Buka PRF → Edit → Simpan → Kunci → Buka Recovery | **PASS** | Data yang muncul via recovery adalah **VERSI HASIL EDIT**, bukan versi registrasi. |
| **AC#9** | Isolasi Key Wrap & Nonce Unik 12-Byte | **PASS** | `key_wraps` tidak termutasi saat edit konten, IV selalu acak 12 byte baru. |
| **AC#10** | AAD Tamper Resistance (`${vaultId}\|${entry.id}\|${version}`) | **PASS** | Swap entry ke record lain menghasilkan `OperationError` (GCM tag mismatch). |
| **AC#11** | Proteksi Lockout Permanen (Tolak empty/non-array `key_wraps`) | **PASS** | Server menolak payload penulisan yang menyisakan `key_wraps` kosong. |
| **AC#12** | Rotasi DEK Eksplisit (`rotateVaultDEK`) | **PASS** | Versi naik, DEK lama dan wrap lama invalid seketika setelah rotasi. |
| **AC#13** | Normalisasi Passphrase Kanonik (NFKD + Trim + Lowercase) | **PASS** | Input dengan variasi whitespace dan huruf kapital berhasil membuka vault. |
| **AC#14** | WebAuthn Clone Detection Counter & Session Binding | **PASS** | Counter mundur ditolak keras; session token diverifikasi terikat ke `credential_id`. |
