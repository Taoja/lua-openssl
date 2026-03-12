local ffi = require("ffi")
local err = require("openssl.err_print")
ffi.cdef [[
  unsigned char *ossl_buf2hexstr_sep(const char *str, long buflen,
    const char sep);
  unsigned char *ossl_hexstr2buf_sep(const char *str, long *buflen,
    const char sep);
]]

local openssl = ffi.load("crypto", true)
local sep = ffi.cast("const char", "")
local _M = {}

function _M.encode(data)
  local input = ffi.cast("const unsigned char*", data)
  local sep = ffi.cast("const char", "")
  local c_str = openssl.ossl_buf2hexstr_sep(input, #data, sep)
  return ffi.string(c_str)
end

function _M.decode(data)
  local out_len = ffi.new("long[1]")
  local input = ffi.cast("const char*", data)
  local out_buf = openssl.ossl_hexstr2buf_sep(input, out_len, sep)
  return ffi.string(out_buf, out_len[0])
end

return _M
