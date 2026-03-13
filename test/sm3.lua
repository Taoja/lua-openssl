local sm3 = require("openssl.sm3")
local hex = require("openssl.hex")
local function test_hash()
  local data = "Hello, SM3!"
  local hex_hash = sm3.hash(data)
  print("Test sm3 hash: true")
end

test_hash()