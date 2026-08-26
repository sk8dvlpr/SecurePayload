---
-- Utilitas kripto plugin SecurePayload (Kong/OpenResty).
--
-- SHA-256 dan HMAC-SHA256 dihitung via FFI ke libcrypto OpenSSL
-- (satu panggilan EVP/HMAC per operasi). Perbandingan nilai rahasia
-- (signature/digest) SELALU melalui ct_compare() yang constant-time
-- (xor-fold) — JANGAN pernah membandingkan dengan `==`.
--
-- b64_encode/b64_decode/hex/ct_compare murni Lua tanpa FFI sehingga
-- modul ini aman di-require dari busted standalone; fungsi hash/HMAC
-- baru menyentuh libcrypto saat dipanggil.

local ffi = require "ffi"
local bit = require "bit"

local _M = {}

-- ---------------------------------------------------------------------------
-- FFI libcrypto (EVP)
-- ---------------------------------------------------------------------------

ffi.cdef[[
typedef struct evp_md_st EVP_MD;
const EVP_MD *EVP_sha256(void);
int EVP_Digest(const void *data, size_t count, unsigned char *md,
               unsigned int *size, const EVP_MD *type, const void *impl);
unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
                    const unsigned char *data, size_t data_len,
                    unsigned char *md, unsigned int *md_len);
]]

local C  -- handle libcrypto; nil bila gagal dimuat

do
  local os_name = (jit and jit.os) or "?"
  local candidates
  if os_name == "Windows" then
    candidates = { "libcrypto-3-x64", "libcrypto-1_1-x64", "libcrypto" }
  elseif os_name == "OSX" then
    candidates = {
      "libcrypto.dylib",
      "/usr/local/opt/openssl@3/lib/libcrypto.dylib",
      "/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib",
    }
  else
    candidates = { "libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so" }
  end

  for _, name in ipairs(candidates) do
    local ok, lib = pcall(ffi.load, name)
    if ok then
      C = lib
      break
    end
  end
end

--- Apakah backend libcrypto tersedia di lingkungan berjalan saat ini.
function _M.available()
  return C ~= nil
end

local function ensure_backend()
  if not C then
    error("libcrypto OpenSSL tidak dapat dimuat via FFI", 0)
  end
end

-- ---------------------------------------------------------------------------
-- Digest & HMAC
-- ---------------------------------------------------------------------------

--- SHA-256 biner (32 byte) atas `data` (string biner-safe).
function _M.sha256_raw(data)
  ensure_backend()
  local md = ffi.new("unsigned char[32]")
  local md_len = ffi.new("unsigned int[1]")
  local ok = C.EVP_Digest(data, #data, md, md_len, C.EVP_sha256(), nil)
  if ok ~= 1 then
    error("EVP_Digest gagal", 0)
  end
  return ffi.string(md, md_len[0])
end

--- SHA-256 ter-encode Base64 — port Digest::bodyDigestB64().
function _M.sha256_b64(data)
  return _M.b64_encode(_M.sha256_raw(data))
end

--- HMAC-SHA256 biner (32 byte) atas `data` dengan kunci `key`.
function _M.hmac_sha256_raw(key, data)
  ensure_backend()
  local md = ffi.new("unsigned char[32]")
  local md_len = ffi.new("unsigned int[1]")
  local out = C.HMAC(C.EVP_sha256(), key, #key, data, #data, md, md_len)
  if out == nil then
    error("HMAC gagal", 0)
  end
  return ffi.string(md, md_len[0])
end

--- HMAC-SHA256 ter-encode Base64 (nilai X-Signature).
function _M.hmac_sha256_b64(key, data)
  return _M.b64_encode(_M.hmac_sha256_raw(key, data))
end

---
-- HKDF-SHA256 (RFC 5869), salt kosong, L <= 32 (satu blok expand).
-- Port Hkdf::deriveKey(): hash_hkdf('sha256', master, len, info).
function _M.hkdf_sha256(master, info, len)
  len = len or 32
  assert(type(master) == "string" and master ~= "", "Master key kosong untuk derivasi HKDF")
  assert(len >= 1 and len <= 32, "len HKDF harus 1..32 byte")
  -- Extract: PRK = HMAC-SHA256(salt="", IKM=master)
  local prk = _M.hmac_sha256_raw("", master)
  -- Expand: T(1) = HMAC-SHA256(PRK, info || 0x01) — cukup satu blok utk L<=32
  local t1 = _M.hmac_sha256_raw(prk, info .. string.char(1))
  return t1:sub(1, len)
end

-- ---------------------------------------------------------------------------
-- Perbandingan constant-time (WAJIB untuk signature/digest)
-- ---------------------------------------------------------------------------

---
-- Bandingkan dua string dalam waktu konstan via xor-fold.
-- Panjang berbeda langsung false (panjang bersifat publik); isi tidak
-- pernah memengaruhi jumlah iterasi loop.
function _M.ct_compare(a, b)
  if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then
    return false
  end
  local diff = 0
  for i = 1, #a do
    diff = bit.bor(diff, bit.bxor(string.byte(a, i), string.byte(b, i)))
  end
  return diff == 0
end

-- ---------------------------------------------------------------------------
-- Base64 (murni Lua, encode + decode STRICT) & hex
-- ---------------------------------------------------------------------------

local B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B64_INV = {}
for i = 1, #B64_CHARS do
  B64_INV[B64_CHARS:byte(i)] = i - 1
end

--- Encode Base64 standar (dengan padding '=').
function _M.b64_encode(data)
  if type(data) ~= "string" then
    return nil
  end
  local band, rshift = bit.band, bit.rshift
  local lshift = bit.lshift
  local out = {}
  local len = #data
  for i = 1, len, 3 do
    local b1, b2, b3 = string.byte(data, i, i + 2)
    local n = lshift(b1, 16) + lshift(b2 or 0, 8) + (b3 or 0)
    local q1 = B64_CHARS:sub(rshift(n, 18) + 1, rshift(n, 18) + 1)
    local q2 = B64_CHARS:sub(band(rshift(n, 12), 63) + 1, band(rshift(n, 12), 63) + 1)
    if b2 == nil then
      out[#out + 1] = q1 .. q2 .. "=="
    elseif b3 == nil then
      local q3 = B64_CHARS:sub(band(rshift(n, 6), 63) + 1, band(rshift(n, 6), 63) + 1)
      out[#out + 1] = q1 .. q2 .. q3 .. "="
    else
      local q3 = B64_CHARS:sub(band(rshift(n, 6), 63) + 1, band(rshift(n, 6), 63) + 1)
      local q4 = B64_CHARS:sub(band(n, 63) + 1, band(n, 63) + 1)
      out[#out + 1] = q1 .. q2 .. q3 .. q4
    end
  end
  return table.concat(out)
end

---
-- Decode Base64 STRICT:
--   - panjang kelipatan 4 (padding wajib lengkap);
--   - hanya alfabet A-Za-z0-9+/ dan '=' padding maksimal 2 di posisi akhir;
--   - tanpa whitespace / karakter asing.
-- @return string biner, atau nil bila format tidak valid.
function _M.b64_decode(s)
  if type(s) ~= "string" then
    return nil
  end
  local len = #s
  if len < 4 or len % 4 ~= 0 then
    return nil
  end

  local npad = 0
  local body_end = len
  local first_pad = s:find("=", 1, true)
  if first_pad then
    npad = len - first_pad + 1
    if npad > 2 then
      return nil
    end
    -- setelah '=' pertama semuanya harus '='
    if s:find("[^=]", first_pad) then
      return nil
    end
    body_end = first_pad - 1
  end

  local body = s:sub(1, body_end)
  if body:find("[^A-Za-z0-9%+/]") then
    return nil
  end

  local acc, accbits = 0, 0
  local out = {}
  for i = 1, #body do
    -- Mask 16 bit agar nilai akumulator tidak tumbuh tanpa batas
    -- (presisi float) dan hanya bit rendah yang relevan (accbits <= 12).
    acc = bit.band(bit.lshift(acc, 6) + B64_INV[body:byte(i)], 0xFFFF)
    accbits = accbits + 6
    if accbits >= 8 then
      accbits = accbits - 8
      out[#out + 1] = string.char(bit.band(bit.rshift(acc, accbits), 255))
    end
  end

  local decoded = table.concat(out)
  -- Panjang hasil harus konsisten dengan padding (tolak trailing bits liar)
  if #decoded ~= math.floor(len / 4) * 3 - npad then
    return nil
  end
  return decoded
end

local HEX_CHARS = "0123456789abcdef"

--- Encode hex huruf kecil (untuk kunci replay).
function _M.hex(data)
  if type(data) ~= "string" then
    return nil
  end
  local out = {}
  for i = 1, #data do
    local b = string.byte(data, i)
    local hi = math.floor(b / 16)
    out[i] = HEX_CHARS:sub(hi + 1, hi + 1) .. HEX_CHARS:sub((b % 16) + 1, (b % 16) + 1)
  end
  return table.concat(out)
end

return _M
