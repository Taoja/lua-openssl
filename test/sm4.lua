local sm4 = require("openssl.sm4")
local function test_ecb()
  local data = "hello world"
  local key = sm4.generate_key(16)
  local ctx = sm4:new(key, "ecb")
  local cipher = ctx:encrypt(data)
  local plain = ctx:decrypt(cipher)
  print("Test ECB:", plain == data)
end

local function test_cbc()
  local data = "hello world"
  local key = sm4.generate_key(16)
  local iv = sm4.generate_iv(16)
  local ctx = sm4:new(key, "cbc", iv)
  local cipher = ctx:encrypt(data)
  local plain = ctx:decrypt(cipher)
  print("Test CBC:", plain == data)
end

local function test_ctr()
  local data1 = "hell"
  local data2 = "o w"
  local data3 = "orld"
  local key = sm4.generate_key(16)
  local ctx1 = sm4:new(key, "ctr")
  local cipher1 = ctx1:encrypt(data1)
  local cipher2 = ctx1:encrypt(data2)
  local cipher3 = ctx1:encrypt(data3)
  ctx1:finish()
  local ctx2 = sm4:new(key, "ctr")
  local plain = ctx2:decrypt(cipher1..cipher2..cipher3)
  ctx2:finish()
  print("Test CTR:", plain == data1..data2..data3)
end

local function test_cfb()
  local data = "hello world"
  local key = sm4.generate_key(16)
  local ctx = sm4:new(key, "cfb")
  local cipher = ctx:encrypt(data)
  local plain = ctx:decrypt(cipher)
  print("Test CFB:", plain == data)
end

local function test_ofb()
  local data = "hello world"
  local key = sm4.generate_key(16)
  local iv = sm4.generate_iv(16)
  local ctx = sm4:new(key, "ofb", iv)
  local cipher = ctx:encrypt(data)
  local plain = ctx:decrypt(cipher)
  print("Test OFB:", plain == data)
end

test_ecb()
test_cbc()
test_ctr()
test_cfb()
test_ofb()


local function test_gcm()
  local data1 = "hello world, "
  local data2 = "this is a test message"
  local data3 = " for GCM mode"
  local key = sm4.generate_key(16)
  local iv = sm4.generate_iv(12)  -- GCM 推荐使用 12 字节 IV
  local aad = "additional authenticated data"
  -- 加密
  local ctx = sm4:new(key, "gcm", iv, aad)
  local cipher1 = ctx:encrypt(data1)
  local cipher2 = ctx:encrypt(data2)
  local cipher3 = ctx:encrypt(data3)
  local tag = ctx:finish()
  -- 解密
  local ctx2 = sm4:new(key, "gcm", iv, aad)
  local plain = ctx2:decrypt(cipher1..cipher2..cipher3)
  local err = ctx2:finish(tag)
  if err then
    print("Tag Error:", err)
  else
    print("Test GCM:", plain == data1..data2..data3)
  end
end

test_gcm()