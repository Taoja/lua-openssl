-- sm3.lua
local ffi = require("ffi")
local err = require("openssl.err_print")

ffi.cdef [[
    typedef struct evp_md_st EVP_MD;

    const EVP_MD *EVP_sm3(void);
    int EVP_Digest(const void *data, size_t count, unsigned char *md, unsigned int *size,
                   const EVP_MD *type, void *impl);
]]

local openssl = ffi.load("crypto")

local _M = {}

_M.DIGEST_LENGTH = 32

function _M.hash(data)
  if type(data) ~= "string" then
    return nil, "the input must be string"
  end

  local out_buf = ffi.new("unsigned char[?]", _M.DIGEST_LENGTH)
  local out_len = ffi.new("unsigned int[1]")

  if openssl.EVP_Digest(data, #data, out_buf, out_len, openssl.EVP_sm3(), nil) ~= 1 then
    return nil, "Failed do digest:" .. err()
  end

  return ffi.string(out_buf, out_len[0]), nil
end

return _M
