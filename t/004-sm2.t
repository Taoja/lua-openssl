use strict;
use warnings;

use Test::Nginx::Socket::Lua;

repeat_each(1);
plan tests => repeat_each() * blocks();
no_shuffle();
run_tests();

__DATA__

=== TEST 1: SM2 generate key and encrypt/decrypt
--- http_config
    lua_package_path "$prefix/lib/?.lua;$prefix/../../lib/?.lua;;";
--- config
    location /t {
        content_by_lua_block {
            local sm2 = require "resty.gmsm.sm2"
            local ctx = sm2:new()
            local data = "hello world"
            local generate_err = ctx:generate_key()
            local cipher, encrypt_err = ctx:encrypt(data)
            local plain, decrypt_err = ctx:decrypt(cipher)
            if generate_err or encrypt_err or decrypt_err or plain ~= data then
                ngx.say("SM2 encrypt/decrypt failed")
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

=== TEST 2: SM2 export and import keys
--- http_config
    lua_package_path "$prefix/lib/?.lua;$prefix/../../lib/?.lua;;";
--- config
    location /t {
        content_by_lua_block {
            local sm2 = require "resty.gmsm.sm2"
            local source = sm2:new()
            local generate_err = source:generate_key()
            local public_key, public_err = source:export_public()
            local private_key, private_err = source:export_private()
            local public_ctx = sm2:new()
            local private_ctx = sm2:new()
            local public_import_err = public_ctx:import_public(public_key)
            local private_import_err = private_ctx:import_private(private_key)

            if generate_err or public_err or private_err
                or public_import_err or private_import_err
                or type(public_key) ~= "string" or type(private_key) ~= "string" then
                ngx.say("SM2 key import/export failed")
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

=== TEST 3: SM2 fixed key decrypt and public key encrypt
--- http_config
    lua_package_path "$prefix/lib/?.lua;$prefix/../../lib/?.lua;;";
--- config
    location /t {
        content_by_lua_block {
            local sm2 = require "resty.gmsm.sm2"
            local private_key = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgEcpp9QNfhQ01tkStACIBVSycmC/ifctjY08dap+/I1ChRANCAATV6CT4JjCeV6CDXFkY56nO0V1irwZrsQvBKMomO3au0sD7rvAMbltclWr0MwDQksiaZzQoV/hb+AK//heaQzdI"
            local public_key = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE1egk+CYwnlegg1xZGOepztFdYq8Ga7ELwSjKJjt2rtLA+67wDG5bXJVq9DMA0JLImmc0KFf4W/gCv/4XmkM3SA=="
            local cipher = "MHoCIFtCDvYepY5izRNSoAFxcdyRJCWJKaTgSNp/stIAGzZSAiAcYPhz6n31ivhcCZK5H2CNIbJ3uzEEI21LhSqUkUaqqwQgA766vdbpYjVXjSVo655mwkoznnAEyt20BJv4ym+jLMAEEsPeETWYW24GKFGROGYgYu2Ufw=="
            local private_ctx = sm2:new()
            local private_err = private_ctx:import_private(private_key)
            local plain, decrypt_err = private_ctx:decrypt(cipher)
            local public_ctx = sm2:new()
            local public_err = public_ctx:import_public(public_key)
            local encrypted, encrypt_err = public_ctx:encrypt("hello-from-lua-sm2")

            if private_err or decrypt_err or plain ~= "hello-from-lua-sm2"
                or public_err or encrypt_err or type(encrypted) ~= "string" then
                ngx.say("SM2 fixed key test failed")
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

=== TEST 4: SM2 sign and verify
--- http_config
    lua_package_path "$prefix/lib/?.lua;$prefix/../../lib/?.lua;;";
--- config
    location /t {
        content_by_lua_block {
            local sm2 = require "resty.gmsm.sm2"
            local private_key = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgEcpp9QNfhQ01tkStACIBVSycmC/ifctjY08dap+/I1ChRANCAATV6CT4JjCeV6CDXFkY56nO0V1irwZrsQvBKMomO3au0sD7rvAMbltclWr0MwDQksiaZzQoV/hb+AK//heaQzdI"
            local public_key = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE1egk+CYwnlegg1xZGOepztFdYq8Ga7ELwSjKJjt2rtLA+67wDG5bXJVq9DMA0JLImmc0KFf4W/gCv/4XmkM3SA=="
            local data = "hello-from-lua-sm2"
            local signer = sm2:new()
            local verifier = sm2:new()
            local import_private_err = signer:import_private(private_key)
            local import_public_err = verifier:import_public(public_key)
            local signature, sign_err = signer:sign(data)
            local valid, verify_err = verifier:verify(data, signature)

            if import_private_err or import_public_err or sign_err
                or verify_err or valid ~= true or type(signature) ~= "string" then
                ngx.say("SM2 sign/verify failed")
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
