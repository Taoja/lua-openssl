local sm4 = require("openssl.sm4")
local function test_ecb()
  local data = "hello world"
  local key = sm4.generate_key(16)
  local ctx = sm4:new(key, "ecb")
  local cipher = ctx:encrypt(data)
  local plain = ctx:decrypt(cipher)
  print("test_ecb:", plain == data)
end

local function test_cbc()
  local data = "hello world"
  local key = sm4.generate_key(16)
  local iv = sm4.generate_iv(16)
  local ctx = sm4:new(key, "cbc", iv)
  local cipher = ctx:encrypt(data)
  local plain = ctx:decrypt(cipher)
  print("test_cbc:", plain == data)
end

local function test_ctr()
  local data1 = "hell"
  local data2 = "o w"
  local data3 = "orld"
  local key = sm4.generate_key(16)
  local ctx = sm4:new(key, "ctr")
  local cipher1 = ctx:encrypt(data1)
  local cipher2 = ctx:encrypt(data2)
  local cipher3 = ctx:encrypt(data3)
  local plain = ctx:decrypt(cipher1..cipher2..cipher3)
  ctx:finish()
  print("test_ctr:", plain == data1..data2..data3)
end

local function test_cfb()
  local data = "hello world"
  local key = sm4.generate_key(16)
  local ctx = sm4:new(key, "cfb")
  local cipher = ctx:encrypt(data)
  local plain = ctx:decrypt(cipher)
  print("test_cfb:", plain == data)
end

local function test_ofb()
  local data = "hello world"
  local key = sm4.generate_key(16)
  local iv = sm4.generate_iv(16)
  local ctx = sm4:new(key, "ofb", iv)
  local cipher = ctx:encrypt(data)
  local plain = ctx:decrypt(cipher)
  print("test_ofb:", plain == data)
end

test_ecb()
test_cbc()
test_ctr()
test_cfb()
test_ofb()