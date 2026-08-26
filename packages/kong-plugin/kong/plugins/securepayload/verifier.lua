---
-- Port semantik verifikasi src/Server/RequestVerifier.php untuk gateway
-- (Kong / OpenResty).
--
-- Prinsip:
--   - Fail-closed; urutan pengecekan mengikuti RequestVerifier.
--   - Kode status mengikuti SecurePayloadException
--     (400 BAD_REQUEST, 401 UNAUTHORIZED, 422 UNPROCESSABLE, 500 SERVER_ERROR).
--   - Perbandingan signature/digest SELALU constant-time (crypto.ct_compare).
--   - Path/method/query didefinisikan dari input request server, BUKAN dari
--     header X-Canonical-Request.
--   - Mode 'hmac'      : verifikasi PENUH.
--   - Mode 'aead'/'both': MUSTAHIL diverifikasi penuh di gateway (HMAC
--     menandatangani plaintext yang hanya bisa dibuka setelah dekripsi) ->
--     hanya structural checks; hasil dikendalikan unverified_mode_action.
--
-- Modul ini murni logika: konteks request di-inject lewat parameter, dan
-- store replay di-inject sebagai fungsi conf.replay_store_fn(key, ttl)
-- -> true|false|nil(err) agar dapat diuji tanpa Redis.

local crypto = require "kong.plugins.securepayload.crypto"
local canonical = require "kong.plugins.securepayload.canonical"

local _M = {}

local AEAD_ALG = "XCHACHA20-POLY1305-IETF" -- SecurePayload::AEAD_ALG
local HMAC_ALG = "HMAC-SHA256"             -- SecurePayload::HMAC_ALG

-- Nama header SecurePayload (versi UPPERCASE; lookup dinormalisasi).
local HX = {
  SIG_VER    = "X-SIGNATURE-VERSION",
  CLIENT_ID  = "X-CLIENT-ID",
  KEY_ID     = "X-KEY-ID",
  TIMESTAMP  = "X-TIMESTAMP",
  NONCE      = "X-NONCE",
  SIG_ALG    = "X-SIGNATURE-ALGORITHM",
  SIGNATURE  = "X-SIGNATURE",
  BODY_DIGEST= "X-BODY-DIGEST",
  AEAD_ALG   = "X-AEAD-ALGORITHM",
  AEAD_NONCE = "X-AEAD-NONCE",
}

local KDF_PURPOSE_SIGN_REQ = "sp-sign-req"

-- ---------------------------------------------------------------------------
-- Helper
-- ---------------------------------------------------------------------------

local function fail(status, message, event)
  return { ok = false, status = status, error = message, event = event }
end

local function now_epoch()
  -- ngx.time() tersedia di OpenResty/Kong; os.time() fallback utk busted.
  if ngx and ngx.time then
    return ngx.time()
  end
  return os.time()
end

local function decode_json(conf, s)
  if conf.json_decode_fn then
    return conf.json_decode_fn(s), true
  end
  local has_cjson, cjson = pcall(require, "cjson.safe")
  if not has_cjson or type(cjson) ~= "table" then
    return nil, false
  end
  return cjson.decode(s), true
end

--- Normalisasi header ke map UPPERCASE (port $H di RequestVerifier).
function _M.normalize_headers(headers)
  local H = {}
  for k, v in pairs(headers or {}) do
    if type(k) == "string" and type(v) == "string" then
      H[k:upper()] = v
    end
  end
  return H
end

--- Resolusi secret HMAC: exact "cid:kid" pada hmac_secrets, fallback single.
local function resolve_hmac_secret(conf, cid, kid)
  if conf.hmac_secrets then
    local s = conf.hmac_secrets[cid .. ":" .. kid]
    if s ~= nil and s ~= "" then
      return s
    end
  end
  local s = conf.hmac_secret
  if s ~= nil and s ~= "" then
    return s
  end
  return nil
end

-- ---------------------------------------------------------------------------
-- Verifikasi penuh (mode hmac) — port blok "Verifikasi Tanda Tangan"
-- ---------------------------------------------------------------------------

function _M.verify_hmac(conf, H, req, method, path, q_str, raw_body)
  local alg = H[HX.SIG_ALG] or ""
  local sig_in = H[HX.SIGNATURE] or ""
  local dig_h = H[HX.BODY_DIGEST] or ""

  -- Anti-downgrade: algoritma ditentukan konfigurasi server/gateway,
  -- BUKAN oleh header request.
  local expected_alg = conf.expected_sig_alg or HMAC_ALG
  if expected_alg ~= HMAC_ALG then
    return fail(500, "signAlg '" .. expected_alg ..
      "' belum didukung plugin gateway v1 (hanya HMAC-SHA256)")
  end
  if alg ~= expected_alg or sig_in == "" or dig_h == "" then
    return fail(400, "Header tanda tangan tidak lengkap/salah algoritma")
  end

  local dig_val = dig_h:sub(8) -- strip prefix 'sha256='
  if dig_h:sub(1, 7) ~= "sha256=" or dig_val == "" then
    return fail(400, "Format digest salah (harus sha256=...)")
  end

  -- 1. Integritas body plaintext: X-Body-Digest == sha256(raw body)
  local calc_dig = crypto.sha256_b64(raw_body)
  if not crypto.ct_compare(dig_val, calc_dig) then
    return fail(422, "Integritas Body Digest HMAC gagal")
  end

  -- 2. Resolusi secret (multi-klien via map "cid:kid")
  local secret = resolve_hmac_secret(conf, req.cid, req.kid)
  if secret == nil then
    return fail(500, "Secret Key HMAC tidak ditemukan di server", "key_not_found")
  end
  if #secret < 32 then
    return fail(500, "HMAC Secret terlalu pendek (minimum 32 karakter).")
  end

  -- 3. Subkey HKDF bila server memakai deriveKeys=true (no-op bila tidak)
  local sign_key = secret
  if conf.derive_keys then
    sign_key = crypto.hkdf_sha256(secret, KDF_PURPOSE_SIGN_REQ .. "|v" .. conf.version, 32)
  end

  -- 4. Signature atas pesan kanonik (plaintext terikat via digest)
  local msg = canonical.hmac_message(
    conf.version, req.cid, req.kid, req.ts_str, req.nonce_b64,
    method, path, q_str, calc_dig)
  local expected_sig = crypto.hmac_sha256_b64(sign_key, msg)
  if not crypto.ct_compare(sig_in, expected_sig) then
    return fail(401, "Tanda Tangan (Signature) tidak valid", "signature_invalid")
  end

  return { ok = true, mode = "HMAC" }
end

-- ---------------------------------------------------------------------------
-- Structural checks (mode aead / both) — gateway TIDAK bisa dekripsi
-- ---------------------------------------------------------------------------

function _M.verify_structural(conf, H, mode, raw_body)
  -- Header AEAD wajib ada dengan algoritma yang dikenal; JANGAN loloskan
  -- diam-diam (anti-downgrade; port baris 116-121 RequestVerifier).
  if (H[HX.AEAD_ALG] or "") ~= AEAD_ALG then
    return fail(401, "Mode " .. mode ..
      " mewajibkan enkripsi AEAD, namun header AEAD tidak ada atau algoritmanya tidak dikenal")
  end
  if (H[HX.AEAD_NONCE] or "") == "" then
    return fail(400, "Header keamanan tidak lengkap (X-AEAD-Nonce kosong)")
  end

  if mode == "both" then
    -- BOTH mengirim header HMAC juga (menandatangani plaintext pra-enkripsi).
    -- Gateway hanya bisa mengecek kehadiran/format — nilai signature/digest
    -- tidak dapat direkomputasi tanpa plaintext.
    local expected_alg = conf.expected_sig_alg or HMAC_ALG
    if (H[HX.SIG_ALG] or "") ~= expected_alg
      or (H[HX.SIGNATURE] or "") == ""
      or (H[HX.BODY_DIGEST] or "") == "" then
      return fail(400, "Header tanda tangan tidak lengkap/salah algoritma")
    end
    local dig_h = H[HX.BODY_DIGEST]
    if dig_h:sub(1, 7) ~= "sha256=" or dig_h:sub(8) == "" then
      return fail(400, "Format digest salah (harus sha256=...)")
    end
  end

  -- Envelope AEAD: JSON object berisi __aead_b64 non-empty
  -- (port baris 124-129 RequestVerifier).
  local json_obj, have_decoder = decode_json(conf, raw_body)
  if not have_decoder then
    return fail(500, "Decoder JSON tidak tersedia di lingkungan gateway")
  end
  local blob = nil
  if type(json_obj) == "table" then
    blob = json_obj["__aead_b64"]
  end
  if type(blob) ~= "string" or blob == "" then
    return fail(400, "Payload AEAD tidak ditemukan")
  end

  -- Payload terenkripsi tidak dapat diverifikasi di gateway: terapkan policy.
  if (conf.unverified_mode_action or "pass") == "reject" then
    return fail(401, "Mode '" .. mode ..
      "' tidak dapat diverifikasi penuh di gateway (unverified_mode_action=reject)")
  end

  -- "pass": handler akan mencatat warn + metric; request dilanjutkan.
  return { ok = true, mode = (mode == "both") and "BOTH-AEAD" or "AEAD", unverified = true }
end

-- ---------------------------------------------------------------------------
-- Entry point verifikasi
-- ---------------------------------------------------------------------------

---
-- Verifikasi satu request.
--
-- @param conf table konfigurasi plugin (field sama seperti schema.lua):
--   version, mode, expected_sig_alg, clock_skew, replay_ttl,
--   hmac_secret, hmac_secrets, derive_keys, unverified_mode_action,
--   replay_store_fn (opsional), json_decode_fn (opsional, testing).
-- @param input konteks request:
--   headers (table any-case), method, path, raw_query, raw_body, now (opsional).
-- @return {ok=true[,unverified=bool]} atau {ok=false,status,error,event}
function _M.verify(conf, input)
  conf = conf or {}
  input = input or {}

  conf.version = conf.version or "4"
  local skew = conf.clock_skew or 5
  local ttl = conf.replay_ttl or 300

  local H = _M.normalize_headers(input.headers)

  local ver       = H[HX.SIG_VER]    or ""
  local cid       = H[HX.CLIENT_ID]  or ""
  local kid       = H[HX.KEY_ID]     or ""
  local ts_str    = H[HX.TIMESTAMP]  or ""
  local nonce_b64 = H[HX.NONCE]      or ""

  -- 1. Keberadaan header + versi protokol
  if ver == "" or cid == "" or kid == "" or ts_str == "" or nonce_b64 == "" then
    return fail(400, "Header keamanan tidak lengkap")
  end
  if ver ~= conf.version then
    return fail(400, "Versi protokol tidak didukung")
  end

  -- 2. Format timestamp + window |now - ts|
  if not ts_str:match("^%d+$") then
    return fail(400, "Format timestamp salah")
  end
  local now = tonumber(input.now) or now_epoch()
  local ts = tonumber(ts_str)
  -- Tidak boleh masa depan melebihi skew; tidak boleh lebih lampau dari ttl+skew
  if ts > now + skew or ts < now - (ttl + skew) then
    return fail(401, "Timestamp di luar batas wajar (kadaluarsa atau jam salah)", "timestamp_invalid")
  end

  -- Nonce: Base64 strict, decode tepat 16 byte (pengencangan gateway)
  if not canonical.is_valid_nonce(nonce_b64) then
    return fail(400, "Format nonce tidak valid (harus base64 16 byte)")
  end

  -- Replay opsional: kunci mengikuti ReplayGuard.php
  -- ('sp_' + 48 hex pertama sha256(cid|kid|nonce)); timestamp TIDAK masuk
  -- kunci; TTL = replay_ttl + clock_skew.
  if conf.replay_store_fn then
    local key = "sp_" .. crypto.hex(crypto.sha256_raw(cid .. "|" .. kid .. "|" .. nonce_b64)):sub(1, 48)
    local fresh, err = conf.replay_store_fn(key, ttl + skew)
    if fresh == nil then
      return fail(500, "Layanan anti-replay tidak tersedia") -- fail-closed
    end
    if not fresh then
      return fail(401, "Replay detected", "replay_detected")
    end
  end

  -- Kanonik dari input request (BUKAN X-Canonical-Request)
  local method = (input.method or ""):upper()
  local path = canonical.normalize_path(input.path)
  local q_str = canonical.canonical_query(canonical.parse_query_php(input.raw_query))

  local mode = conf.mode or "hmac"
  if mode == "hmac" then
    return _M.verify_hmac(conf, H, {
      cid = cid, kid = kid, ts_str = ts_str, nonce_b64 = nonce_b64,
    }, method, path, q_str, input.raw_body or "")
  elseif mode == "aead" or mode == "both" then
    return _M.verify_structural(conf, H, mode, input.raw_body or "")
  end

  return fail(500, "Konfigurasi mode tidak dikenal")
end

return _M
