local base64 = require("openssl.base64")
local hex = require("openssl.hex")

local data = "hello world"
local data_base64 = base64.encode(data)
local data_hex = hex.encode(data)
-- print("base64: ", data_base64)
-- print("hex: ", data_hex)

local data_base64_plain = base64.decode(data_base64)
local data_hex_plain = hex.decode(data_hex)
print("base64: ", data_base64_plain == data)
print("hex: ", data_hex_plain == data)