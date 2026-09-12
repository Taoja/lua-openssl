use strict;
use warnings;

use Test::Nginx::Socket::Lua;

repeat_each(1);
plan tests => repeat_each() * blocks();
no_shuffle();
run_tests();

__DATA__

=== TEST 1: base64 and hex round trips
--- http_config
    lua_package_path "$prefix/lib/?.lua;$prefix/../../lib/?.lua;;";
--- config
    location /t {
        content_by_lua_block {
            local base64 = require "resty.gmsm.base64"
            local hex = require "resty.gmsm.hex"
            local data = "hello world"

            local encoded_b64 = base64.encode(data)
            local decoded_b64, b64_err = base64.decode(encoded_b64)
            local encoded_hex = hex.encode(data)
            local decoded_hex = hex.decode(encoded_hex)

            if b64_err or decoded_b64 ~= data or decoded_hex ~= data then
                ngx.say("round trip failed")
                return
            end

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
