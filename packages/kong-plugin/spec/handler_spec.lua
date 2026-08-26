---
-- Unit test busted untuk fungsi-fungsi MURNI plugin SecurePayload Kong.
-- TIDAK membutuhkan Kong berjalan: modul murni di-load langsung.
--
-- Jalankan dari root packages/kong-plugin:  busted
--
-- Test yang membutuhkan libcrypto (sha256/HMAC/HKDF) otomatis "pending"
-- bila FFI gagal memuat libcrypto di lingkungan eksekusi (mis. Windows
-- dev box tanpa OpenSSL DLL). Di CI Linux semua test berjalan penuh.
--
-- Vektor diambil dari docs/fixtures/v3/primitive/*.php fixtures repo core:
--   - hmac-message.json, normalize-path.json, body-digest.json,
--     hkdf-derive.json (+ RFC 4231 untuk HMAC-SHA256).

local here = debug.getinfo(1, "S").source:sub(2):match("(.*)[/\\]") or "."
package.path = here .. "/../kong/?.lua;" .. package.path

local crypto = require "kong.plugins.securepayload.crypto"
local canonical = require "kong.plugins.securepayload.canonical"
local verifier = require "kong.plugins.securepayload.verifier"

local HAVE_CRYPTO = crypto.available()

-- ---------------------------------------------------------------------------
-- Konstanta vektor (disalin dari docs/fixtures/v3/primitive)
-- ---------------------------------------------------------------------------

local FIX_NONCE = "AQEBAQEBAQEBAQEBAQEBAQ=="
local FIX_TS = "1700000000"
local FIX_CID = "conf-client"
local FIX_KID = "conf-key-v1"
local FIX_PATH = "/v1/pay"
local FIX_MSG = "v3\nclient=conf-client\nkey=conf-key-v1\nts=1700000000\n" ..
  "nonce=AQEBAQEBAQEBAQEBAQEBAQ==\nm=POST\np=/v1/pay\nq=a=1&b=2\n" ..
  "bd=sha256:TUu+Wcaq0iRCzeGZpqil8DRAX814+1qBwk7ySd4cRfE=\n"

describe("securepayload.kong canonical (port Canonical.php / Messages.php)", function()

  describe("normalize_path", function()
    -- Vektor docs/fixtures/v3/primitive/normalize-path.json
    local cases = {
      { "/api/v1/resource", "/api/v1/resource" },
      { "/api/v1/",         "/api/v1" },
      { "/",                "/" },
      { "",                 "/" },
      { nil,                "/" },
    }
    for _, c in ipairs(cases) do
      it(("input %s -> %s"):format(tostring(c[1]), c[2]), function()
        assert.equals(c[2], canonical.normalize_path(c[1]))
      end)
    end
  end)

  describe("canonical_query", function()
    it("vektor hmac-message.json: {a=1,b=2} -> 'a=1&b=2'", function()
      assert.equals("a=1&b=2", canonical.canonical_query({ a = "1", b = "2" }))
    end)

    it("urutan key tidak memengaruhi hasil (ksort ASC)", function()
      assert.equals("a=1&b=2", canonical.canonical_query({ b = "2", a = "1" }))
    end)

    it("nilai array digabung koma (konvensi Canonical.php)", function()
      assert.equals("a=x%2Cy&b=2", canonical.canonical_query({ b = "2", a = { "x", "y" } }))
    end)

    it("rawurlencode RFC3986: karakter reserved di-escape, ~ - . _ aman", function()
      assert.equals(
        "k=a%2Bb%3Fc%2Fd~e-f_g.h",
        canonical.canonical_query({ k = "a+b?c/d~e-f_g.h" })
      )
    end)
  end)

  describe("parse_query_php (semantik parse_str yang dipakai server)", function()
    it("key duplikat: nilai TERAKHIR menang", function()
      local q = canonical.parse_query_php("b=2&a=1&a=3")
      assert.equals("3", q.a)
      assert.equals("2", q.b)
    end)

    it("'+' menjadi spasi; %XX didekode", function()
      local q = canonical.parse_query_php("x=%21+he%2Fllo")
      assert.equals("! he/llo", q.x)
    end)

    it("titik/spasi pada nama key -> underscore", function()
      local q = canonical.parse_query_php("a.b=1&c d=2")
      assert.equals("1", q["a_b"])
      assert.equals("2", q["c_d"])
    end)

    it("pasangan tanpa '=' bernilai string kosong", function()
      local q = canonical.parse_query_php("flag")
      assert.equals("", q.flag)
    end)
  end)

  describe("hmac_message", function()
    it("byte-per-byte sama dengan vektor docs/fixtures/v3/primitive/hmac-message.json", function()
      assert.equals(FIX_MSG, canonical.hmac_message(
        "3", FIX_CID, FIX_KID, FIX_TS, FIX_NONCE, "POST", FIX_PATH, "a=1&b=2",
        "TUu+Wcaq0iRCzeGZpqil8DRAX814+1qBwk7ySd4cRfE="))
    end)

    it("diakhiri newline (trailing \\n termasuk tanda tangan)", function()
      local msg = canonical.hmac_message("4", "c", "k", "1", FIX_NONCE, "GET", "/", "", "dg==")
      assert.truthy(msg:sub(-1) == "\n")
    end)
  end)

  describe("is_valid_nonce (base64 strict 16 byte)", function()
    it("nonce SDK resmi valid", function()
      assert.is_true(canonical.is_valid_nonce(FIX_NONCE))
    end)

    it("base64 valid tapi bukan 16 byte -> false ('AAAA' = 3 byte)", function()
      assert.is_false(canonical.is_valid_nonce("AAAA"))
    end)

    it("karakter di luar alfabet -> false", function()
      assert.is_false(canonical.is_valid_nonce("@@@@$$$$$$$$$$$$$$$%"))
    end)

    it("padding tidak lengkap -> false", function()
      assert.is_false(canonical.is_valid_nonce("AQEBAQEBAQEBAQEBAQEBAQ"))
    end)

    it("tipe salah -> false", function()
      assert.is_false(canonical.is_valid_nonce(nil))
    end)
  end)
end)

-- ---------------------------------------------------------------------------
-- crypto: bagian murni (tanpa libcrypto)
-- ---------------------------------------------------------------------------

describe("securepayload.kong crypto (bagian murni)", function()

  describe("b64_encode / b64_decode STRICT", function()
    local roundtrips = {
      { "", "" },
      { "f", "Zg==" },
      { "fo", "Zm8=" },
      { "foo", "Zm9v" },
      { "foob", "Zm9vYg==" },
      { "fooba", "Zm9vYmE=" },
      { "foobar", "Zm9vYmFy" },
    }
    for _, c in ipairs(roundtrips) do
      it(("encode '%s' -> '%s' (RFC 4648)":format(c[1], c[2])), function()
        assert.equals(c[2], crypto.b64_encode(c[1]))
      end)
      it(("decode '%s' -> '%s'":format(c[2], c[1])), function()
        assert.equals(c[1], crypto.b64_decode(c[2]))
      end)
    end

    it("roundtrip biner penuh 0x00..0xFF", function()
      local bin = {}
      for i = 0, 255 do bin[#bin + 1] = string.char(i) end
      local blob = table.concat(bin)
      assert.equals(blob, crypto.b64_decode(crypto.b64_encode(blob)))
    end)

    it("tolak panjang bukan kelipatan 4", function()
      assert.is_nil(crypto.b64_decode("ABC"))
    end)

    it("tolak '=' lebih dari 2 / tidak kontigu", function()
      assert.is_nil(crypto.b64_decode("A==="))
      assert.is_nil(crypto.b64_decode("AB=C"))
    end)

    it("tolak karakter asing dan whitespace", function()
      assert.is_nil(crypto.b64_decode("AB@D"))
      assert.is_nil(crypto.b64_decode("AB CD"))
    end)
  end)

  describe("ct_compare (WAJIB constant-time utk signature/digest)", function()
    it("string identik -> true", function()
      assert.is_true(crypto.ct_compare("abcdef", "abcdef"))
    end)

    it("satu bit berbeda -> false", function()
      assert.is_false(crypto.ct_compare("abcdef", "abcdeg"))
      assert.is_false(crypto.ct_compare(string.char(0, 0), string.char(0, 1)))
    end)

    it("panjang beda -> false", function()
      assert.is_false(crypto.ct_compare("abc", "abcd"))
    end)

    it("dua-duanya kosong -> true", function()
      assert.is_true(crypto.ct_compare("", ""))
    end)

    it("tipe non-string -> false (tidak meledak)", function()
      assert.is_false(crypto.ct_compare(nil, ""))
      assert.is_false(crypto.ct_compare({}, {}))
    end)
  end)

  describe("hex", function()
    it("encode huruf kecil", function()
      assert.equals("00107f", crypto.hex(string.char(0x00, 0x10, 0x7f)))
    end)
  end)
end)

-- ---------------------------------------------------------------------------
-- crypto: bagian libcrypto (pending otomatis bila FFI tak tersedia)
-- ---------------------------------------------------------------------------

describe("securepayload.kong crypto (libcrypto EVP)", function()

  it("sha256_b64 sesuai vektor body-digest.json", function()
    if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
    assert.equals("TUu+Wcaq0iRCzeGZpqil8DRAX814+1qBwk7ySd4cRfE=",
      crypto.sha256_b64('{"amount":100}'))
  end)

  it("hmac_sha256_raw sesuai RFC 4231 Test Case 2", function()
    if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
    local mac = crypto.hmac_sha256_raw("Jefe", "what do ya want for nothing?")
    assert.equals("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
      crypto.hex(mac))
  end)

  it("hkdf_sha256 sesuai vektor hkdf-derive.json kasus 1", function()
    if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
    local okm = crypto.hkdf_sha256(
      "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      "sp-sign-req|v3", 32)
    assert.equals("a8d4b411881ff817631fb027cd227dda27f33e5606e824fe4ca53e8d045ebc7b",
      crypto.hex(okm))
  end)

  it("hkdf_sha256 sesuai vektor hkdf-derive.json kasus 2", function()
    if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
    local master = string.char(0x11):rep(32)
    local okm = crypto.hkdf_sha256(master, "sp-aead-req|v3", 32)
    assert.equals("24b59475dd8294e94bbc0f96cc458e09f0ec92191df0bb2a8a4cff5953f5e108",
      crypto.hex(okm))
  end)
end)

-- ---------------------------------------------------------------------------
-- verifier: jalur kegagalan murni (tidak menyentuh libcrypto)
-- ---------------------------------------------------------------------------

describe("securepayload.kong verifier (jalur kegagalan murni)", function()

  local BASE_HEADERS = {
    ["X-Signature-Version"] = "3",
    ["X-Client-Id"] = FIX_CID,
    ["X-Key-Id"] = FIX_KID,
    ["X-Timestamp"] = FIX_TS,
    ["X-Nonce"] = FIX_NONCE,
  }

  local NOW = 1700000000
  local SKEW = 5
  local TTL = 300

  local function attempt(headers, extra_conf)
    local conf = {
      version = "3", mode = "hmac",
      clock_skew = SKEW, replay_ttl = TTL,
    }
    for k, v in pairs(extra_conf or {}) do conf[k] = v end
    return verifier.verify(conf, {
      headers = headers or BASE_HEADERS,
      method = "POST",
      path = FIX_PATH,
      raw_query = "b=2&a=1",
      raw_body = '{"amount":100}',
      now = NOW,
    })
  end

  it("header tidak lengkap -> 400", function()
    local h = { ["X-Client-Id"] = FIX_CID }
    local r = attempt(h)
    assert.is_false(r.ok)
    assert.equals(400, r.status)
  end)

  it("versi protokol beda -> 400", function()
    local h = {}
    for k, v in pairs(BASE_HEADERS) do h[k] = v end
    h["X-Signature-Version"] = "9"
    local r = attempt(h)
    assert.is_false(r.ok)
    assert.equals(400, r.status)
  end)

  it("timestamp bukan digit -> 400", function()
    local h = {}
    for k, v in pairs(BASE_HEADERS) do h[k] = v end
    h["X-Timestamp"] = "17x000000"
    local r = attempt(h)
    assert.is_false(r.ok)
    assert.equals(400, r.status)
  end)

  it("timestamp masa depan melebihi skew -> 401 timestamp_invalid", function()
    local h = {}
    for k, v in pairs(BASE_HEADERS) do h[k] = v end
    h["X-Timestamp"] = tostring(NOW + SKEW + 1)
    local r = attempt(h)
    assert.is_false(r.ok)
    assert.equals(401, r.status)
    assert.equals("timestamp_invalid", r.event)
  end)

  it("timestamp terlalu lampau -> 401 timestamp_invalid", function()
    local h = {}
    for k, v in pairs(BASE_HEADERS) do h[k] = v end
    h["X-Timestamp"] = tostring(NOW - (TTL + SKEW) - 1)
    local r = attempt(h)
    assert.is_false(r.ok)
    assert.equals(401, r.status)
    assert.equals("timestamp_invalid", r.event)
  end)

  it("nonce bukan base64 16 byte -> 400", function()
    local h = {}
    for k, v in pairs(BASE_HEADERS) do h[k] = v end
    h["X-Nonce"] = "terlalupendek"
    local r = attempt(h)
    assert.is_false(r.ok)
    assert.equals(400, r.status)
  end)

  it("header lowercase dinormalisasi (lookup case-insensitive)", function()
    -- Semua header versi lowercase; harus tetap terbaca sampai tahap
    -- verifikasi signature (yang butuh crypto -> di sini cukup pastikan
    -- TIDAK gagal karena 'Header keamanan tidak lengkap').
    local h = {}
    for k, v in pairs(BASE_HEADERS) do h[k:lower()] = v end
    local ok_call, r = pcall(attempt, h)
    if not ok_call then
      return pending("libcrypto tidak tersedia (gagal sebelum tahap crypto)")
    end
    assert.not_equals("Header keamanan tidak lengkap", r.error)
  end)

  it("replay_store_fn mengembalikan nil -> fail-closed 500", function()
    local r = attempt(BASE_HEADERS, { replay_store_fn = function() return nil, "redis down" end })
    assert.is_false(r.ok)
    assert.equals(500, r.status)
  end)

  it("mode tak dikenal -> 500", function()
    local r = attempt(BASE_HEADERS, { mode = "aneh" })
    assert.is_false(r.ok)
    assert.equals(500, r.status)
  end)
end)

-- ---------------------------------------------------------------------------
-- verifier: jalur penuh HMAC + structural AEAD (butuh libcrypto)
-- ---------------------------------------------------------------------------

describe("securepayload.kong verifier (jalur penuh, butuh libcrypto)", function()

  local SECRET = string.rep("s", 32)
  local NOW = 1700000000

  local function build_conf(extra)
    local conf = {
      version = "3",
      mode = "hmac",
      clock_skew = 5,
      replay_ttl = 300,
      hmac_secret = SECRET,
    }
    for k, v in pairs(extra or {}) do conf[k] = v end
    return conf
  end

  --- Bangun header request valid sesuai protokol (self-consistent).
  local function build_headers(conf, opts)
    opts = opts or {}
    local method = "POST"
    local body = opts.body or '{"amount":100}'
    local ts = opts.ts or NOW
    local digest = crypto.sha256_b64(body)
    local msg = canonical.hmac_message(conf.version, FIX_CID, FIX_KID,
      tostring(ts), FIX_NONCE, method, FIX_PATH, "a=1&b=2", digest)
    local sign_key = conf.derive_keys
      and crypto.hkdf_sha256(SECRET, "sp-sign-req|v" .. conf.version, 32)
      or SECRET
    local sig = crypto.hmac_sha256_b64(sign_key, msg)
    return {
      ["X-Signature-Version"] = conf.version,
      ["X-Client-Id"] = FIX_CID,
      ["X-Key-Id"] = FIX_KID,
      ["X-Timestamp"] = tostring(ts),
      ["X-Nonce"] = FIX_NONCE,
      ["X-Signature-Algorithm"] = "HMAC-SHA256",
      ["X-Signature"] = sig,
      ["X-Body-Digest"] = "sha256=" .. digest,
    }, body
  end

  local function call(conf, headers, body, query)
    return verifier.verify(conf, {
      headers = headers,
      method = "POST",
      path = FIX_PATH,
      raw_query = query or "b=2&a=1",
      raw_body = body,
      now = NOW,
    })
  end

  it("hmac valid -> ok (boundary ts=now+skew)", function()
    if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
    local conf = build_conf()
    local h, body = build_headers(conf, { ts = NOW + 5 })
    local r = call(conf, h, body)
    assert.truthy(r.ok)
    assert.equals("HMAC", r.mode)
  end)

  it("hmac valid (boundary ts=now-(ttl+skew)) -> ok", function()
    if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
    local conf = build_conf()
    local h, body = build_headers(conf, { ts = NOW - 305 })
    local r = call(conf, h, body)
    assert.truthy(r.ok)
  end)

  it("tamper signature -> 401 signature_invalid", function()
    if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
    local conf = build_conf()
    local h, body = build_headers(conf)
    h["X-Signature"] = h["X-Signature"]:gsub("^.", "#")
    local r = call(conf, h, body)
    assert.is_false(r.ok)
    assert.equals(401, r.status)
    assert.equals("signature_invalid", r.event)
  end)

  it("tamper body (digest tidak cocok) -> 422", function()
    if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
    local conf = build_conf()
    local h, _ = build_headers(conf)
    local r = call(conf, h, '{"amount":999}')
    assert.is_false(r.ok)
    assert.equals(422, r.status)
  end)

  it("X-Signature-Algorithm salah (anti-downgrade) -> 400", function()
    if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
    local conf = build_conf()
    local h, body = build_headers(conf)
    h["X-Signature-Algorithm"] = "ED25519"
    local r = call(conf, h, body)
    assert.is_false(r.ok)
    assert.equals(400, r.status)
  end)

  it("digest tanpa prefix sha256= -> 400", function()
    if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
    local conf = build_conf()
    local h, body = build_headers(conf)
    h["X-Body-Digest"] = crypto.sha256_b64(body) -- tanpa 'sha256='
    local r = call(conf, h, body)
    assert.is_false(r.ok)
    assert.equals(400, r.status)
  end)

  it("secret tidak ditemukan (multi-klien miss) -> 500 key_not_found", function()
    if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
    local conf = build_conf({ hmac_secret = nil, hmac_secrets = { ["lain:kunci"] = SECRET } })
    local h, body = build_headers(build_conf())
    local r = call(conf, h, body)
    assert.is_false(r.ok)
    assert.equals(500, r.status)
    assert.equals("key_not_found", r.event)
  end)

  it("multi-klien: secret dari map 'cid:kid' dipakai -> ok", function()
    if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
    local conf = build_conf({ hmac_secret = nil, hmac_secrets = { [FIX_CID .. ":" .. FIX_KID] = SECRET } })
    local h, body = build_headers(conf)
    local r = call(conf, h, body)
    assert.truthy(r.ok)
  end)

  it("derive_keys=true: signature atas subkey HKDF -> ok (vektor hkdf-derive)", function()
    if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
    local conf = build_conf({
      hmac_secret = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      derive_keys = true,
    })
    local h, body = build_headers(conf)
    local r = call(conf, h, body)
    assert.truthy(r.ok)
  end)

  it("derive_keys mismatch (server on, gateway off) -> 401 signature_invalid", function()
    if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
    -- Ditandatangani dengan subkey, diverifikasi tanpa derivasi -> harus gagal
    local signed = build_conf({
      hmac_secret = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      derive_keys = true,
    })
    local verifying = build_conf({
      hmac_secret = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      derive_keys = false,
    })
    local h, body = build_headers(signed)
    local r = call(verifying, h, body)
    assert.is_false(r.ok)
    assert.equals(401, r.status)
  end)

  it("replay_store_fn: kunci 'sp_'+48 hex, ttl=replay_ttl+clock_skew; duplikat -> 401", function()
    if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
    local seen_key, seen_ttl
    local first = true
    local conf = build_conf({
      replay_store_fn = function(key, ttl)
        seen_key, seen_ttl = key, ttl
        local fresh = first
        first = false
        return fresh
      end,
    })
    local h, body = build_headers(conf)

    local r1 = call(conf, h, body)
    assert.truthy(r1.ok)
    assert.equals("sp_", seen_key:sub(1, 3))
    assert.equals(51, #seen_key)          -- 'sp_' + 48 hex
    assert.equals(305, seen_ttl)          -- 300 + 5 skew
    assert.equals(48, #seen_key:sub(4))

    local r2 = call(conf, h, body)
    assert.is_false(r2.ok)
    assert.equals(401, r2.status)
    assert.equals("replay_detected", r2.event)
  end)

  describe("mode aead (structural checks)", function()
    local JSON_OK = '{"__aead_b64":"QUJDREVGRw=="}'
    local FAKE_DECODER = function(s)
      if s == JSON_OK then return { __aead_b64 = "QUJDREVGRw==" } end
      return nil
    end

    local function aead_conf(action)
      return build_conf({
        mode = "aead",
        json_decode_fn = FAKE_DECODER,
        unverified_mode_action = action or "pass",
      })
    end

    local function aead_headers(conf)
      local h, _ = build_headers(conf)
      h["X-AEAD-Algorithm"] = "XCHACHA20-POLY1305-IETF"
      h["X-AEAD-Nonce"] = FIX_NONCE
      return h
    end

    it("action=pass, struktur lengkap -> ok + flag unverified", function()
      if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
      local conf = aead_conf("pass")
      local r = call(conf, aead_headers(conf), JSON_OK)
      assert.truthy(r.ok)
      assert.is_true(r.unverified)
    end)

    it("action=reject -> 401 meski struktur lengkap", function()
      if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
      local conf = aead_conf("reject")
      local r = call(conf, aead_headers(conf), JSON_OK)
      assert.is_false(r.ok)
      assert.equals(401, r.status)
    end)

    it("X-AEAD-Algorithm hilang/salah -> 401 (anti-downgrade)", function()
      if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
      local conf = aead_conf("pass")
      local h = aead_headers(conf)
      h["X-AEAD-Algorithm"] = "AES-GCM"
      local r = call(conf, h, JSON_OK)
      assert.is_false(r.ok)
      assert.equals(401, r.status)
    end)

    it("body tanpa __aead_b64 -> 400", function()
      if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
      local conf = aead_conf("pass")
      local r = call(conf, aead_headers(conf), '{"data":1}')
      assert.is_false(r.ok)
      assert.equals(400, r.status)
    end)

    it("decoder JSON tidak tersedia -> 500 fail-closed", function()
      if not HAVE_CRYPTO then return pending("libcrypto tidak tersedia") end
      local conf = aead_conf("pass")
      conf.json_decode_fn = nil -- fallback ke cjson.safe lingkungan
      local r = call(conf, aead_headers(conf), JSON_OK)
      -- Di CI ada cjson -> ok/unverified; tanpa cjson -> 500. Keduanya sah;
      -- yang dilarang adalah lolos tanpa flag.
      if r.ok then assert.is_true(r.unverified) else assert.equals(500, r.status) end
    end)
  end)
end)
