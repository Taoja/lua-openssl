use Test::Nginx::Socket 'no_plan';

no_shuffle();
run_tests();

__DATA__

=== TEST 1: which openssl does Lua see
--- http_config
    lua_package_path "$prefix/../../lib/?.lua;;";
--- config
    location = /t {
        content_by_lua_block {
            local ffi = require "ffi"
            ffi.cdef[[const char *OpenSSL_version(int t);]]
            local ok, lib = pcall(ffi.load, "crypto")
            if not ok then
                ngx.say("LOAD FAILED: ", tostring(lib))
            else
                ngx.say("LUA SEES: ", ffi.string(lib.OpenSSL_version(0)))
            end
        }
    }
--- request
GET /t
--- response_body_like
^LUA SEES: OpenSSL 3\.6\.3

=== TEST 2: which openssl version does ffi output
--- http_config
    lua_package_path "$prefix/../../lib/?.lua;;";
--- config
    location = /t {
        content_by_lua_block {
            local ok, mod = pcall(require, "resty.gmsm.sm2")
            if not ok then
                ngx.say("REQUIRE FAILED: ", tostring(mod))
                return
            end
            ngx.say(mod.Openssl_Version)
        }
    }
--- request
GET /t
--- response_body_like
^3\.6