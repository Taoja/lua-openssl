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
}}
--- request
GET /t
--- response_body_like
LUA SEES: OpenSSL 3

=== TEST 2: which openssl version does ffi output
--- config
location = /t { content_by_lua_block {
  local sm2 = require "resty.gmsm.sm2"
  local version = sm2.Openssl_Version
  ngx.say(version)
}}
--- request
GET /t
--- response_body_like
3.6