local ffi = require "ffi"
local err = require("openssl.err_print")
ffi.cdef [[
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct engine_st ENGINE;
typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;
typedef struct ec_key_st EC_KEY;

void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid);
int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
EVP_PKEY *d2i_PrivateKey(int type, EVP_PKEY **a, const unsigned char **pp,
    long length);
int i2d_PKCS8PrivateKey(const EVP_PKEY *a, unsigned char **pp);
EVP_PKEY *d2i_PUBKEY(EVP_PKEY **a, const unsigned char **in, long len);
int i2d_PUBKEY(const EVP_PKEY *a, unsigned char **out);
int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
    unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen);
int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
    unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen);

EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *libctx,
    const char *name,
    const char *propquery);
int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx);

EVP_PKEY *EVP_PKEY_new(void);
EC_KEY *EC_KEY_new_by_curve_name(int nid);
int EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key);
EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
]]

local NID_sm2 = ffi.cast("int", 1172)
local EVP_PKEY_SM2 = NID_sm2
local openssl = ffi.load("crypto")

local _M = { Version = '3.5.5' }
_M.__index = _M

function _M:new()
  self.key = ffi.new("EVP_PKEY*[1]")
  return setmetatable({}, self)
end

function _M:generate_key()
  local genctx = openssl.EVP_PKEY_CTX_new_from_name(nil, "SM2", nil)

  if genctx == nil then
    return "generate key fail"
  end

  if openssl.EVP_PKEY_paramgen_init(genctx) <= 0 then
    return "generate key fail"
  end

  if openssl.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(genctx, NID_sm2) <= 0 then
    return "generate key fail"
  end

  if openssl.EVP_PKEY_keygen_init(genctx) <= 0 then
    return "generate key fail"
  end

  if openssl.EVP_PKEY_keygen(genctx, self.key) <= 0 then
    return "generate key fail"
  end
  openssl.EVP_PKEY_CTX_free(genctx)
  return nil
end

function _M:export_public_to_der()
  local len = openssl.i2d_PUBKEY(self.key[0], nil)
  local buf = ffi.new("unsigned char[?]", len)
  local buf_ptr = ffi.new("unsigned char*[1]", buf)
  openssl.i2d_PUBKEY(self.key[0], buf_ptr)
  return ffi.string(buf, len)
end

function _M:export_private_to_der()
  local len = openssl.i2d_PKCS8PrivateKey(self.key[0], nil)
  local buf = ffi.new("unsigned char[?]", len)
  local buf_ptr = ffi.new("unsigned char*[1]", buf)
  openssl.i2d_PKCS8PrivateKey(self.key[0], buf_ptr)
  return ffi.string(buf, len)
end

function _M:import_public_from_der(str)
  local input = ffi.cast("const unsigned char*", str)
  local input_ptr = ffi.new("const unsigned char*[1]", input)
  local key = openssl.d2i_PUBKEY(nil, input_ptr, #str)
  self.key[0] = key
end

function _M:import_private_from_der(str)
  local input = ffi.cast("const unsigned char*", str)
  local input_ptr = ffi.new("const unsigned char*[1]", input)
  local key = openssl.d2i_PrivateKey(EVP_PKEY_SM2, nil, input_ptr, #str)
  self.key[0] = key
end

function _M:encrypt(str)
  local ctx = openssl.EVP_PKEY_CTX_new(self.key[0], nil)
  local out_len = ffi.new("size_t[1]")
  local input = ffi.cast("const unsigned char*", str)
  if openssl.EVP_PKEY_encrypt_init(ctx) <= 0 then
    return nil, "encrypt init fail"
  end
  if openssl.EVP_PKEY_encrypt(ctx, nil, out_len, input, #str) <= 0 then
    return nil, "get encrypt len fail"
  end
  local out = ffi.new("unsigned char[?]", out_len[0])
  if openssl.EVP_PKEY_encrypt(ctx, out, out_len, input, #str) <= 0 then
    return nil, "encrypt fail"
  end
  return ffi.string(out, out_len[0]), nil
end

function _M:decrypt(str)
  local ctx = openssl.EVP_PKEY_CTX_new(self.key[0], nil)
  local out_len = ffi.new("size_t[1]")
  local input = ffi.cast("const unsigned char*", str)
  if openssl.EVP_PKEY_decrypt_init(ctx) <= 0 then
    return nil, "decrypt init fail:"..err()
  end
  if openssl.EVP_PKEY_decrypt(ctx, nil, out_len, input, #str) <= 0 then
    return nil, "get decrypt len fail:"..err()
  end
  local out = ffi.new("unsigned char[?]", out_len[0])
  if openssl.EVP_PKEY_decrypt(ctx, out, out_len, input, #str) <= 0 then
    return nil, "decrypt fail:"..err()
  end
  return ffi.string(out, out_len[0]), nil
end

return _M