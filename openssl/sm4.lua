local ffi = require "ffi"
local err = require("openssl.err_print")

ffi.cdef [[
// 基本类型定义
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;

// EVP_CIPHER_CTX 相关函数
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *ctx);

// SM4 相关函数
const EVP_CIPHER *EVP_sm4_ecb(void);
const EVP_CIPHER *EVP_sm4_cbc(void);
const EVP_CIPHER *EVP_sm4_cfb128(void);
const EVP_CIPHER *EVP_sm4_ofb(void);
const EVP_CIPHER *EVP_sm4_ctr(void);
const EVP_CIPHER *EVP_sm4_gcm(void);
const EVP_CIPHER *EVP_sm4_ccm(void);
const EVP_CIPHER *EVP_sm4_xts(void);

// 加解密操作函数
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                       void *engine, const unsigned char *key,
                       const unsigned char *iv);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                     int *outl, const unsigned char *in, int inl);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                       void *engine, const unsigned char *key,
                       const unsigned char *iv);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                     int *outl, const unsigned char *in, int inl);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

// AEAD 模式（GCM/CCM）相关函数
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

// 参数获取函数
int EVP_CIPHER_CTX_get_iv_length(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_get_key_length(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_get_tag_length(const EVP_CIPHER_CTX *ctx);

// 随机数生成
int RAND_bytes(unsigned char *buf, int num);

// 常量定义
int EVP_CTRL_INIT;
int EVP_CTRL_SET_KEY_LENGTH;
int EVP_CTRL_GET_IVLEN;
int EVP_CTRL_GCM_SET_IVLEN;
int EVP_CTRL_GCM_GET_TAG;
int EVP_CTRL_GCM_SET_TAG;
int EVP_CTRL_CCM_SET_IVLEN;
int EVP_CTRL_CCM_GET_TAG;
int EVP_CTRL_CCM_SET_TAG;
int EVP_CTRL_CCM_SET_L;
int EVP_CTRL_AEAD_SET_IVLEN;
int EVP_CTRL_AEAD_GET_TAG;
int EVP_CTRL_AEAD_SET_TAG;
]]

-- OpenSSL 常量定义
local EVP_CTRL_INIT = 0x0
local EVP_CTRL_SET_KEY_LENGTH = 0x1
local EVP_CTRL_GET_IVLEN = 0x2
local EVP_CTRL_GCM_SET_IVLEN = 0x8
local EVP_CTRL_GCM_GET_TAG = 0x10
local EVP_CTRL_GCM_SET_TAG = 0x11
local EVP_CTRL_CCM_SET_IVLEN = 0x12
local EVP_CTRL_CCM_GET_TAG = 0x13
local EVP_CTRL_CCM_SET_TAG = 0x14
local EVP_CTRL_CCM_SET_L = 0x15
local EVP_CTRL_AEAD_SET_IVLEN = 0x16
local EVP_CTRL_AEAD_GET_TAG = 0x17
local EVP_CTRL_AEAD_SET_TAG = 0x18

local openssl = ffi.load("crypto")

local _M = { Version = '3.5.5' }
_M.__index = _M

-- SM4 模式枚举
local MODE = {
  ECB = "ecb",
  CBC = "cbc",
  CFB = "cfb",
  OFB = "ofb",
  CTR = "ctr",
  GCM = "gcm",
  CCM = "ccm",
  XTS = "xts"
}

_M.MODE = MODE

-- 获取 SM4 密码对象
local function get_sm4_cipher(mode)
  if mode == MODE.ECB then
    return openssl.EVP_sm4_ecb()
  elseif mode == MODE.CBC then
    return openssl.EVP_sm4_cbc()
  elseif mode == MODE.CFB then
    return openssl.EVP_sm4_cfb128()
  elseif mode == MODE.OFB then
    return openssl.EVP_sm4_ofb()
  elseif mode == MODE.CTR then
    return openssl.EVP_sm4_ctr()
  elseif mode == MODE.GCM then
    return openssl.EVP_sm4_gcm()
  elseif mode == MODE.CCM then
    return openssl.EVP_sm4_ccm()
  elseif mode == MODE.XTS then
    return openssl.EVP_sm4_xts()
  else
    error("Unsupported mode: " .. tostring(mode))
  end
end

--- 生成随机秘钥
--- @param length number? 秘钥长度，默认16
--- @return string 私钥字符串
--- @return string 错误信息
function _M.generate_key(length)
  if not length then length = 16 end
  if length ~= 16 and length ~= 24 and length ~= 32 then
    return nil, "SM4 key length must be 16, 24 or 32 bytes"
  end
  local key = ffi.new("unsigned char[?]", length)
  if openssl.RAND_bytes(key, length) <= 0 then
    return nil, "Failed to generate random key:" .. err()
  end
  return ffi.string(key, length), nil
end

--- 生成随机iv
--- @param length number? iv长度，默认16
--- @return string iv字符串
--- @return string 错误信息
function _M.generate_iv(length)
  if not length then length = 16 end
  local iv = ffi.new("unsigned char[?]", length)
  if openssl.RAND_bytes(iv, length) <= 0 then
    return nil, "Failed to generate random IV"
  end
  return ffi.string(iv, length), nil
end

--- 构造函数
--- @param key string 私钥
--- @param mode string? 模式枚举
--- @param iv string? iv
--- @param tag_len string? tag
function _M:new(key, mode, iv, tag_len)
  mode = mode or MODE.CBC
  iv = iv or ""

  local obj = {
    key = key,
    mode = mode,
    iv = iv,
    tag_len = tag_len or 16,     -- GCM/CCM 标签长度，默认 16 字节
    cipher = nil
  }

  return setmetatable(obj, self)
end

function _M:encrypt_init()
  local ctx = openssl.EVP_CIPHER_CTX_new()
  local cipher = get_sm4_cipher(self.mode)
  local key_data = ffi.cast("const unsigned char*", self.key)
  local iv_data = nil
  if #self.iv > 0 then
    iv_data = ffi.cast("const unsigned char*", self.iv)
  end

  -- 初始化加密上下文
  if openssl.EVP_EncryptInit_ex(ctx, cipher, nil, key_data, iv_data) <= 0 then
    openssl.EVP_CIPHER_CTX_free(ctx)
    return "Failed to initialize encryption context:" .. err()
  end

  self.ctx_enc = ctx
  return nil
end

function _M:encrypt_finalize()
  local outl = ffi.new("int[1]")
  local out_buf = ffi.new("unsigned char[?]", 16)
  if openssl.EVP_EncryptFinal_ex(self.ctx_enc, out_buf, outl) <= 0 then
    openssl.EVP_CIPHER_CTX_free(self.ctx_enc)
    return nil, "Failed to finalize encryption:" .. err()
  end
  local cipher = ffi.string(out_buf, outl[0])
  openssl.EVP_CIPHER_CTX_free(self.ctx_enc)
  return cipher, nil
end

-- 内部加密函数
function _M:encrypt_internal(plaintext)
  local outl = ffi.new("int[1]")
  local in_data = ffi.cast("const unsigned char*", plaintext)
  local in_len = #plaintext
  local out_buf = ffi.new("unsigned char[?]", in_len + 16)

  -- 加密
  if openssl.EVP_EncryptUpdate(self.ctx_enc, out_buf, outl, in_data, in_len) <= 0 then
    openssl.EVP_CIPHER_CTX_free(self.ctx_enc)
    return nil, "Failed to encrypt data:" .. err()
  end
  local cipher = ffi.string(out_buf, outl[0])
  return cipher, nil
end

function _M:decrypt_init()
  local ctx = openssl.EVP_CIPHER_CTX_new()
  local cipher = get_sm4_cipher(self.mode)
  local key_data = ffi.cast("const unsigned char*", self.key)
  local iv_data = nil
  if #self.iv > 0 then
    iv_data = ffi.cast("const unsigned char*", self.iv)
  end
  
  -- 初始化加密上下文
  if openssl.EVP_DecryptInit_ex(ctx, cipher, nil, key_data, iv_data) <= 0 then
    openssl.EVP_CIPHER_CTX_free(ctx)
    return "Failed to initialize decryption context:" .. err()
  end

  self.ctx_dec = ctx
  return nil
end

function _M:decrypt_finalize()
  local outl = ffi.new("int[1]")
  local out_buf = ffi.new("unsigned char[?]", 16)
  if openssl.EVP_DecryptFinal_ex(self.ctx_dec, out_buf, outl) <= 0 then
    openssl.EVP_CIPHER_CTX_free(self.ctx_dec)
    return nil, "Failed to finalize encryption:" .. err()
  end
  local plain = ffi.string(out_buf, outl[0])
  openssl.EVP_CIPHER_CTX_free(self.ctx_dec)
  return plain, nil
end

-- 内部解密函数
function _M:decrypt_internal(ciphertext)
  local outl = ffi.new("int[1]")
  local in_data = ffi.cast("const unsigned char*", ciphertext)
  local in_len = #ciphertext
  local out_buf = ffi.new("unsigned char[?]", in_len)
  
  -- 解密
  if openssl.EVP_DecryptUpdate(self.ctx_dec, out_buf, outl, in_data, in_len) <= 0 then
    openssl.EVP_CIPHER_CTX_free(self.ctx_dec)
    return nil, "Failed to decrypt data:" .. err()
  end

  local plain = ffi.string(out_buf, outl[0])
  return plain
end

--- sm4加密
--- @param plaintext string 需要加密的明文字符串
--- @param aad string? aad GCM/CCM附加认证信息
--- @return string 加密后的密文信息
--- @return string 错误信息
function _M:encrypt(plaintext, aad)
  -- 初始化加密上下文
  if not self.ctx_enc then
    local errorMsg = self:encrypt_init()
    if errorMsg then
      return nil, errorMsg
    end
  end

  -- 加密
  local ciphertext, errorMsg = self:encrypt_internal(plaintext)
  if errorMsg then
    return nil, errorMsg
  end

  -- 结束
  if self.mode ~= MODE.CTR then
    local finaltext, errorMsg = self:encrypt_finalize()
    if errorMsg then
      return nil, errorMsg
    end
    ciphertext = ciphertext .. finaltext
  end

  return ciphertext, nil
end

--- sm4解密
--- @param ciphertext string 需要解密的密文字符串
--- @return string 解密后的明文信息
--- @return string 错误信息
function _M:decrypt(ciphertext)
  -- 初始化解密上下文
  if not self.ctx_dec then
    local errorMsg = self:decrypt_init()
    if errorMsg then
      return nil, errorMsg
    end
  end

  -- 加密
  local plaintext, errorMsg = self:decrypt_internal(ciphertext)
  if errorMsg then
    return nil, errorMsg
  end

  -- 结束
  if self.mode ~= MODE.CTR then
    local finaltext, errorMsg = self:decrypt_finalize()
    if errorMsg then
      return nil, errorMsg
    end
    plaintext = plaintext .. finaltext
  end

  return plaintext, nil
end

function _M:finish()
  if self.ctx_enc then
    openssl.EVP_CIPHER_CTX_free(self.ctx_enc)
    self.ctx_enc = nil
  end
  if self.ctx_dec then
    openssl.EVP_CIPHER_CTX_free(self.ctx_dec)
    self.ctx_dec = nil
  end
end

return _M
