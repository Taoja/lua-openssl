use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: SM3 hash
--- http_config
    lua_package_path "$prefix/lib/?.lua;$prefix/../../lib/?.lua;;";
--- config
    location /t {
        content_by_lua_block {
            local sm3 = require "resty.gmsm.sm3"
            local hex = require "resty.gmsm.hex"
            local digest, err = sm3.hash("Hello, SM3!")

            if err or not digest
                or hex.encode(digest) ~= "21:B9:37:FE:D6:1E:68:5B:8A:C0:8C:67:FE:9A:33:00:43:7F:2C:A4:45:47:DE:A0:6E:0C:FE:30:21:9F:DC:4C" then
                ngx.say("SM3 hash failed")
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
