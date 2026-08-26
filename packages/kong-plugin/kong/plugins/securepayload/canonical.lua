---
-- Port Lua dari src/Protocol/Canonical.php, Messages.php (dan util nonce
-- dari Digest.php) untuk plugin SecurePayload.
--
-- Semua fungsi murni (tanpa I/O, tanpa Kong PDK, tanpa FFI wajib) agar
-- bisa diuji via busted standalone dan dipakai di OpenResty polos.

local crypto = require "kong.plugins.securepayload.crypto"

local _M = {}

-- ---------------------------------------------------------------------------
-- rawurlencode gaya PHP (RFC 3986): unreserved = ALPHA / DIGIT / - . _ ~
-- ---------------------------------------------------------------------------

local function rawurlencode(str)
  return (str:gsub("[^A-Za-z0-9%-._~]", function(ch)
    return string.format("%%%02X", ch:byte())
  end))
end

_M.rawurlencode = rawurlencode

-- ---------------------------------------------------------------------------
-- Canonical::normalizePath()
-- ---------------------------------------------------------------------------

---
-- Normalisasi path: selalu diawali '/', tidak diakhiri '/' (kecuali root).
function _M.normalize_path(path)
  if path == nil or path == "" then
    return "/"
  end
  path = "/" .. (path:gsub("^/+", ""))
  if #path > 1 then
    path = (path:gsub("/+$", ""))
  end
  return path
end

-- ---------------------------------------------------------------------------
-- Canonical::canonicalQuery()
-- ---------------------------------------------------------------------------

local function php_str(mixed)
  if mixed == nil then
    return ""
  end
  if type(mixed) == "boolean" then
    return mixed and "1" or ""
  end
  return tostring(mixed)
end

---
-- Kanonisasi query: key diurutkan ASC byte-wise (ekuivalen ksort SORT_STRING),
-- nilai array digabung koma, pasangan di-encode rawurlencode.
-- @param q table<string, string|number|boolean|table>
function _M.canonical_query(q)
  if q == nil then
    return ""
  end
  local keys = {}
  for k in pairs(q) do
    keys[#keys + 1] = tostring(k)
  end
  if #keys == 0 then
    return ""
  end
  table.sort(keys)

  local out = {}
  for _, k in ipairs(keys) do
    local v = q[k]
    if type(v) == "table" then
      local parts = {}
      for _, item in ipairs(v) do
        parts[#parts + 1] = php_str(item)
      end
      v = table.concat(parts, ",")
    else
      v = php_str(v)
    end
    out[#out + 1] = rawurlencode(k) .. "=" .. rawurlencode(v)
  end
  return table.concat(out, "&")
end

-- ---------------------------------------------------------------------------
-- Emulasi parse_str() PHP (subset yang dipakai RequestVerifier)
-- ---------------------------------------------------------------------------

local function php_urldecode(s)
  s = s:gsub("+", " ")
  return (s:gsub("%%(%x%x)", function(h)
    return string.char(tonumber(h, 16))
  end))
end

_M.php_urldecode = php_urldecode

---
-- Parse query mentah dengan semantik parse_str() PHP yang dipakai server:
--   - pasangan key duplikat -> nilai TERAKHIR menang;
--   - '+' pada key/nilai -> spasi;
--   - titik/spasi pada nama key -> underscore.
--
-- Catatan: sintaks bracket-array PHP (a[]=1&a[]=2) TIDAK didukung — nilai
-- akan diperlakukan literal. Lihat tabel limitasi di README.
function _M.parse_query_php(raw_query)
  local q = {}
  if raw_query == nil or raw_query == "" then
    return q
  end
  for pair in raw_query:gmatch("[^&]+") do
    local k, v = pair:match("^([^=]*)=(.*)$")
    if k == nil then
      k, v = pair, ""
    end
    k = (php_urldecode(k)):gsub("[%. ]", "_")
    q[k] = php_urldecode(v)
  end
  return q
end

-- ---------------------------------------------------------------------------
-- Messages::hmacMessage()
-- ---------------------------------------------------------------------------

---
-- Pesan kanonik HMAC — HARUS identik byte-per-byte dengan sisi client/server
-- SecurePayload (trailing newline termasuk).
function _M.hmac_message(ver, client_id, key_id, ts, nonce_b64, method, path, q_str, body_digest_b64)
  return table.concat({
    "v" .. ver,
    "client=" .. client_id,
    "key=" .. key_id,
    "ts=" .. ts,
    "nonce=" .. nonce_b64,
    "m=" .. method,
    "p=" .. path,
    "q=" .. q_str,
    "bd=sha256:" .. body_digest_b64,
    "", -- trailing newline
  }, "\n")
end

-- ---------------------------------------------------------------------------
-- Validasi format nonce (Digest::genNonceB64 => base64 dari 16 byte acak)
-- ---------------------------------------------------------------------------

---
-- Nonce valid bila Base64 strict dan hasil decode tepat 16 byte.
-- Pengencangan khas gateway: RequestVerifier PHP hanya memvalid non-kosong;
-- SDK resmi selalu mengirim nonce 16 byte.
function _M.is_valid_nonce(nonce_b64)
  local raw = crypto.b64_decode(nonce_b64)
  return raw ~= nil and #raw == 16
end

return _M
