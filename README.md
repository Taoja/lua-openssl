# lua-openssl

基于OpenSSL3.5.5版本的国密实现

当前支持sm2、sm3、sm4

其中sm4支持ecb、cbc、cfb、ofb、ctr、gcm，并且都只支持pkcs7补位

SM2 公钥、私钥和密文的外部输入输出统一使用 Base64 文本格式，不再支持 PEM。

## SM2

### 引入
```lua
local sm2 = require("openssl.sm2")
```

### 初始化上下文
```lua
local ctx = sm2:new()
```

### 创建秘钥
```lua
local err = ctx:generate_key()
```

### 导出 Base64 格式秘钥
```lua
local pub_b64, err = ctx:export_public()
local priv_b64, err = ctx:export_private()
```

### 导入 Base64 格式秘钥
```lua
local err = ctx:import_public(pub_b64)
local err = ctx:import_private(priv_b64)
```

### 加解密
```lua
local cipher, err = ctx:encrypt(plaintext)
local plain, err = ctx:decrypt(cipher)
```

### 加签验签
```lua
local err = ctx:set_sm2_id(id) -- 不设置使用默认的 1234567812345678
local signtext, err = ctx:sign(data, id?)
local boolean, err = ctx:verify(data, signtext, id?)
```

## SM3

### 引入
```lua
local sm3 = require("openssl.sm3")
```

### 获取哈希
```lua
local hash, err = sm3.hash(data)
```

## SM4

### 引入
```lua
local sm4 = require("openssl.sm4")
```

### 生成秘钥/iv
```lua
local key, err = sm4.generate_key(16)
local iv, err = sm4.generate_iv(16) -- gcm iv长度一般为12
```

### ECB、CFB
```lua
local ctx = sm4:new(key, "cfb") -- 或者ecb
local cipher, err = ctx:encrypt(data)
local plain, err = ctx:decrypt(cipher)
```

### CBC、OFB
```lua
local ctx = sm4:new(key, "cbc", iv) -- 或者ofb
local cipher, err = ctx:encrypt(data)
local plain, err = ctx:decrypt(cipher)
```

### CTR

encrypt和decrypt方法兼容流式调用，不论使用CTR是否使用流式加解密在完成时都必须调用finish方法

```lua
local ctx_enc = sm4:new(key, "ctr")
local cipher1, err = ctx_enc:encrypt(data1)
local cipher2, err = ctx_enc:encrypt(data2)
local cipher3, err = ctx_enc:encrypt(data3)
ctx_enc:finish()

local ctx_dec = sm4:new(key, "ctr")
local plain, err = ctx_dec:decrypt(cipher1..cipher2..cipher3)
ctx_dec:finish()
```

### GCM
和CTR类似，在完成时需要调用finish，加密上下文调用finish会返回tag信息。 解密上下文调用finish时要传入tag进行完整性验证

```lua
local ctx_enc = sm4:new(key, "gcm", iv, aad)
local cipher1, err = ctx_enc:encrypt(data1)
local cipher2, err = ctx_enc:encrypt(data2)
local cipher3, err = ctx_enc:encrypt(data3)
local tag, err = ctx_enc:finish()

local ctx_dec = sm4:new(key, "gcm", iv, aad)
local plain, err = ctx_dec:decrypt(cipher1..cipher2..cipher3)
local err = ctx_dec:finish(tag) -- 报错则表示完整性验证失败
```

## 编码

### base64
```lua
local base64 = require("openssl.base64")
local encode = base64.encode(data)
local deocde, err = base64.decode(encode)
```

### hex
```lua
local hex = require("openssl.hex")
local encode = hex.encode(data)
local decode = hex.decode(encode)
```