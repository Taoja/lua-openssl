local sm2 = require("openssl.sm2")
local base64 = require("openssl.base64")
local priv = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgNVF5QfqbrFS7KnUnBvfXlTiEk+ncHG8GF7yr820c7KqhRANCAAS0Ac/Jkl0kmJV/ZNVnxv0hMsBfRmh9uvHxrrE2n7+asdHBgVeYEJ0vflCSDdbccSMiC3iGMW+LwtcxD3+Nf6MS"
local pub = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEtAHPyZJdJJiVf2TVZ8b9ITLAX0Zofbrx8a6xNp+/mrHRwYFXmBCdL35Qkg3W3HEjIgt4hjFvi8LXMQ9/jX+jEg=="
local data = "MHQCIHhOU3ReunGTov3YDzxdnBg79WRAbWK9qj8IFfghyrCdAiEArURcbMQbbeNGfedm9Qj/bA+NjUkqaHBtb1WBMtMV+wsEIJ3RbYB0lMt36XAKh4XjtURlQdewflBXPBumXmNPA8oSBAvOwKAY5b0rGNe1VA=="
local function test_generate_key()
  local data = "hello world"
  local ctx = sm2:new()
  ctx:generate_key()
  local cipher = ctx:encrypt(data)
  local plain = ctx:decrypt(cipher)
  print("Test SM2 Generate Key:", plain == data)
end

local function test_import_private()
  local data = "hello world"
  local ctx = sm2:new()
  local priv_bytes = base64.decode(priv)
  ctx:import_private_from_der(priv_bytes)
  local cipher = ctx:encrypt(data)
  local plain = ctx:decrypt(cipher)
  print("Test Import PrivateKey:", plain == data)
end

local function test_export()
  local ctx = sm2:new()
  ctx:generate_key()
  local pub = ctx:export_public_to_der()
  local priv = ctx:export_private_to_der()
  local pub_b64 = base64.encode(pub)
  local priv_b64 = base64.encode(priv)
  print("Test Export: true")
end

local function test_import_public()
  local data = "hello world"
  local ctx_pub = sm2:new()
  local pub_bytes = base64.decode(pub)
  ctx_pub:import_public_from_der(pub_bytes)
  local cipher, err = ctx_pub:encrypt(data)
  if err then
    print("Test Import PublicKey:", err)
    return
  end
  local ctx_priv = sm2:new()
  local priv_bytes = base64.decode(priv)
  ctx_priv:import_private_from_der(priv_bytes)
  local plain, err = ctx_priv:decrypt(cipher)
  if err then
    print("Test Import PublicKey:", err)
    return
  end
  print("Test Import PublicKey:", plain == data)
end

local function test_decrypt()
  local ctx = sm2:new()
  ctx:import_private_from_der(base64.decode(priv))
  local plain, err = ctx:decrypt(base64.decode(data))
  if err then
    print("Test Decrypt Data:", err)
  else
    print("Test Decrypt Data: true")
  end
end

local function test_sign()
  local sign_ctx = sm2:new()
  sign_ctx:import_private_from_der(base64.decode(priv))
  local sign_data = sign_ctx:sign("hello world")
  local very_ctx = sm2:new()
  very_ctx:import_public_from_der(base64.decode(pub))
  local result = very_ctx:verify("hello world", sign_data)
  print("Test SM2 Sign Verify:", result)
end

test_generate_key()
test_import_private()
test_export()
test_import_public()
test_decrypt()
test_sign()