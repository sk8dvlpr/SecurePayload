-- Milestone 2: kolom jadwal destroy (crypto-shredding) untuk key lifecycle
-- Jalankan sekali pada tabel secure_keys yang sudah ada (setelah 001_key_lifecycle.sql).

ALTER TABLE secure_keys ADD COLUMN destroy_after INTEGER NULL;

-- Nilai status lengkap setelah migrasi ini:
--   active    = kunci produksi saat ini
--   retiring  = masih valid sampai valid_until (grace period)
--   revoked   = ditolak segera
--   destroyed = kunci telah dihancurkan; arsip tidak dapat didekripsi lagi
--
-- Varian dialek:
--   SQLite / PostgreSQL : INTEGER NULL (unix timestamp, konsisten dengan valid_until)
--   MySQL               : BIGINT NULL
--
-- Kolom ini OPSIONAL: hanya dipakai jika fitur destroy diaktifkan
-- (KeyLifecycleManager dengan opsi useDestroyAfter=true — scheduleDestroy()/destroyIfDue()).
-- Tanpa fitur destroy, kolom dibiarkan NULL dan tidak dibaca sama sekali.
