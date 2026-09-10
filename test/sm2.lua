local sm2 = require("openssl.sm2")

local self_plain = "hello-from-lua-sm2"

local self_priv_b64 = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgEcpp9QNfhQ01tkStACIBVSycmC/ifctjY08dap+/I1ChRANCAATV6CT4JjCeV6CDXFkY56nO0V1irwZrsQvBKMomO3au0sD7rvAMbltclWr0MwDQksiaZzQoV/hb+AK//heaQzdI"
local self_pub_b64 = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE1egk+CYwnlegg1xZGOepztFdYq8Ga7ELwSjKJjt2rtLA+67wDG5bXJVq9DMA0JLImmc0KFf4W/gCv/4XmkM3SA=="
-- local self_cipher_b64 = "MHsCIHOb3RL9/Nqw0BBe8TaJLmZfVBP6BYeY0kpfHsgMAW5GAiEA4JCySJdp7Jy9QHoFP1EN/A9jEFW5HKJMahoz0zuHLq8EIBnKb/OVz9Rloe+PCCMHLteqhPektfjv0RO1uAJmYWH4BBL+MjdVR9+akdpY/0m3XeGUY4U="
local self_cipher_b64 = "MHoCIFtCDvYepY5izRNSoAFxcdyRJCWJKaTgSNp/stIAGzZSAiAcYPhz6n31ivhcCZK5H2CNIbJ3uzEEI21LhSqUkUaqqwQgA766vdbpYjVXjSVo655mwkoznnAEyt20BJv4ym+jLMAEEsPeETWYW24GKFGROGYgYu2Ufw=="
local function assert_true(label, cond)
  print(label .. ":", cond and "true" or "false")
  if not cond then
    error(label .. " failed")
  end
end

local function test_generate_key()
  local data = "hello world"
  local ctx = sm2:new()
  local err = ctx:generate_key()
  assert_true("Test SM2 Generate Key", err == nil)
  local cipher, cerr = ctx:encrypt(data)
  local plain, derr = ctx:decrypt(cipher)
  assert_true("Test SM2 Encrypt/Decrypt", cerr == nil and derr == nil and plain == data)
end

local function test_export()
  local ctx = sm2:new()
  local err = ctx:generate_key()
  assert_true("Test Generate Key for Export", err == nil)

  local pub_b64, pub_err = ctx:export_public()
  local priv_b64, priv_err = ctx:export_private()
  assert_true("Test Export Base64", pub_err == nil and priv_err == nil and type(pub_b64) == "string" and type(priv_b64) == "string")
end

local function test_import_private()
  local ctx = sm2:new()
  local err = ctx:import_private(self_priv_b64)
  assert_true("Test Import PrivateKey Base64", err == nil)
  local plain, derr = ctx:decrypt(self_cipher_b64)
  assert_true("Test Import PrivateKey Base64 decrypt", derr == nil and plain == self_plain)
end

local function test_import_public()
  local ctx = sm2:new()
  local err = ctx:import_public(self_pub_b64)
  assert_true("Test Import PublicKey Base64", err == nil)
  local cipher, cerr = ctx:encrypt(self_plain)
  assert_true("Test Import PublicKey Base64 encrypt", cerr == nil and type(cipher) == "string")
end

local function test_sign()
  local sign_ctx = sm2:new()
  local err = sign_ctx:import_private(self_priv_b64)
  assert_true("Test Sign import", err == nil)

  local sign_data, sign_err = sign_ctx:sign(self_plain)
  assert_true("Test Sign", sign_err == nil and type(sign_data) == "string")

  local very_ctx = sm2:new()
  local verify_err = very_ctx:import_public(self_pub_b64)
  assert_true("Test Verify import", verify_err == nil)
  local result, verify_info = very_ctx:verify(self_plain, sign_data)
  assert_true("Test SM2 Sign Verify", result == true and verify_info == nil)
end

test_generate_key()
test_export()
test_import_private()
test_import_public()
test_sign()