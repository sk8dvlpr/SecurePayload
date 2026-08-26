---
-- Adapter lua-resty-redis untuk proteksi replay (SET NX EX).
--
-- Kontrak fungsi yang dikembalikan sama dengan conf.replay_store_fn:
--   fn(key, ttl) -> true  : nonce baru berhasil dicatat;
--                    false: kunci sudah ada (REPLAY);
--                    nil, err: kegagalan infrastruktur (fail-closed).
--
-- Modul ini hanya di-load saat konfigurasi replay_store diisi, sehingga
-- deployment tanpa Redis tidak butuh lua-resty-redis.

local _M = {}

function _M.build_fn(store_conf)
  store_conf = store_conf or {}
  local host = store_conf.host or "127.0.0.1"
  local port = store_conf.port or 6379

  return function(key, ttl)
    local has_redis, redis = pcall(require, "resty.redis")
    if not has_redis then
      return nil, "lua-resty-redis tidak tersedia"
    end

    local red = redis:new()
    red:set_timeout(1000) -- ms

    local ok_conn, conn_err = red:connect(host, port)
    if not ok_conn then
      return nil, conn_err
    end

    -- SET key val EX ttl NX: true hanya bila kunci BELUM ada.
    local res, set_err = red:set(key, "1", "EX", ttl, "NX")

    if res == nil then
      -- Error command/koneksi
      pcall(red.set_keepalive, red, 60000, 100)
      return nil, set_err
    end

    local is_fresh = (res ~= ngx.null)
    pcall(red.set_keepalive, red, 60000, 100)

    if not is_fresh then
      return false -- kunci sudah terdaftar => replay
    end
    return true
  end
end

return _M
