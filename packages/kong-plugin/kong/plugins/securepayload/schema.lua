---
-- Schema plugin Kong: securepayload.
--
-- Field mengikuti spesifikasi M4 + tambahan yang dibutuhkan agar plugin
-- berfungsi (mode, expected_sig_alg, hmac_secret(s), derive_keys) —
-- lihat tabel konfigurasi & limitasi di README.

return {
  name = "securepayload",
  fields = {
    { protocols = {
        type = "set",
        required = true,
        default = { "http", "https" },
        elements = { type = "string", one_of = { "http", "https" } },
    } },
    { config = {
        type = "record",
        fields = {
          { version = { type = "string", default = "4", len_min = 1, len_max = 8 } },

          { mode = { type = "string", required = true, default = "hmac",
              one_of = { "hmac", "aead", "both" } } },

          { expected_sig_alg = { type = "string", required = true, default = "HMAC-SHA256",
              one_of = { "HMAC-SHA256", "ED25519", "HYBRID-MLDSA44-ED25519" } } },

          { clock_skew = { type = "integer", default = 5, minimum = 0 } },
          { replay_ttl = { type = "integer", default = 300, minimum = 0 } },

          { hmac_secret = { type = "string", len_min = 32, referenceable = true } },

          { hmac_secrets = { type = "map",
              keys = { type = "string", match = "^[^:%s]+:[^:%s]+$" },
              values = { type = "string", len_min = 32, referenceable = true } } },

          { derive_keys = { type = "boolean", default = false } },

          { replay_store = { type = "record",
              fields = {
                { host = { type = "string", default = "127.0.0.1" } },
                { port = { type = "integer", default = 6379, between = { 1, 65535 } } },
              } } },

          { unverified_mode_action = { type = "string", default = "pass",
              one_of = { "pass", "reject" } } },
        },
    } },
  },
}
