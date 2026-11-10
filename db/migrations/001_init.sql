-- ==============================================================================
-- Secure Vault Database Migration
-- Table: vault (Neon PostgreSQL)
--
-- Model Keamanan:
-- 1. Server dan Database TIDAK PERNAH memegang kunci enkripsi atau plaintext.
-- 2. Database HANYA menyimpan ciphertext (AES-256-GCM) dan IV acak.
-- 3. key_wraps (JSONB) menyimpan wrapped DEK per jalur akses (prf-1, recovery-1)
--    beserta parameter KDF masing-masing (info, salt acak 16/32 byte, iterasi).
-- 4. AAD pada wrap/unwrap: "${vaultId}|${entry.id}|${version}" untuk mencegah swap antar record.
-- 5. prf_salt (32 byte) dibuat sekali saat registrasi khusus untuk extensions.prf.eval.first.
-- 6. IV berukuran 12 byte dan WAJIB dibuat baru setiap kali ada enkripsi ulang.
-- 7. updated_at diperbarui setiap kali terjadi penulisan pada tabel vault.
-- ==============================================================================

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

