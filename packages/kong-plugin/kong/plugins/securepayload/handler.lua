---
-- Handler plugin Kong: securepayload (fase access).
--
-- Semua logika verifikasi ada di modul murni (crypto / canonical /
-- verifier); file ini hanya:
--   1. mengumpulkan konteks request via Kong PDK;
--   2. memanggil verifier.verify();
--   3. merespons kegagalan dengan JSON error ringkas (kontrak sama dengan
--      integrasi PHP: {"error": "<pesan>"} + status terpetakan);
--   4. mencatat event/warn tanpa PERNAH menampilkan secret.
--
-- Bekerja juga di OpenResty polos: gunakan pola pada README (bagian
-- "OpenResty/Nginx polos") yang memanggil modul yang sama.

local verifier = require "kong.plugins.securepayload.verifier"
local replay_redis = require "kong.plugins.securepayload.replay_redis"

local SecurePayloadHandler = {
  -- Jalankan sebelum mayoritas plugin auth/rate-limit: request tanpa
  -- signature valid tidak boleh menyentuh upstream.
  PRIORITY = 1500,
  VERSION = "1.0.0",
}

function SecurePayloadHandler.access(conf)
  local req = kong.request

  -- Store replay hanya dibangun bila dikonfigurasi (butuh lua-resty-redis)
  local store_fn = nil
  if conf.replay_store then
    store_fn = replay_redis.build_fn(conf.replay_store)
  end

  local result = verifier.verify({
    version = conf.version,
    mode = conf.mode,
    expected_sig_alg = conf.expected_sig_alg,
    clock_skew = conf.clock_skew,
    replay_ttl = conf.replay_ttl,
    hmac_secret = conf.hmac_secret,
    hmac_secrets = conf.hmac_secrets,
    derive_keys = conf.derive_keys,
    unverified_mode_action = conf.unverified_mode_action,
    replay_store_fn = store_fn,
  }, {
    headers = req.get_headers(),
    method = req.get_method(),
    path = req.get_path(),
    raw_query = req.get_raw_query(),
    raw_body = req.get_raw_body(),
  })

  if result.ok then
    if result.unverified then
      -- Mode aead/both: payload tidak dapat diverifikasi di gateway.
      kong.log.warn("securepayload: request terenkripsi dilewatkan TANPA verifikasi penuh",
        " mode=", conf.mode, " action=", conf.unverified_mode_action or "pass")
    end
    return -- lanjutkan pipeline
  end

  if result.event then
    kong.log.warn("securepayload event=", result.event, ": ", result.error)
  end

  kong.response.exit(result.status, { error = result.error }, {
    ["Content-Type"] = "application/json",
  })
end

return SecurePayloadHandler
