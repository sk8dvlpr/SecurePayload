-- Phase 10: Key lifecycle columns for rotation + grace period
-- Jalankan sekali pada tabel secure_keys yang sudah ada.

ALTER TABLE secure_keys ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'active';
ALTER TABLE secure_keys ADD COLUMN valid_until INTEGER NULL;

-- Nilai status:
--   active   = kunci produksi saat ini
--   retiring = masih valid sampai valid_until (grace period)
--   revoked  = ditolak segera
