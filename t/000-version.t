use Test::Nginx::Socket 'no_plan';
run_tests();
__DATA__
=== TEST 1: which openssl does Lua see
--- config
location = /t { content_by_lua_block {
  local ffi = require "ffi"
  ffi.cdef[[const char *OpenSSL_version(int t);]]
  local ok, lib = pcall(ffi.load, "crypto")
  if not ok then ngx.say("ffi.load failed: ", tostring(lib)); return end
  ngx.say("LUA SEES: ", ffi.string(lib.OpenSSL_version(0)))
  ngx.say("SM4-GCM: ", tostring(ffi.new("const void*")) ~= nil and "" or "")
}}
--- request
GET /t
--- response_body_like
LUA SEES: OpenSSL 3