-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

-- Note: The underlying ChaCha20-Poly1305 implementation is pure Lua.
-- Constant-time tag comparison cannot be guaranteed at the Lua level.
-- This is acceptable here because the sealed box construction uses
-- ephemeral keys, making tag forgery attacks impractical.

local Blake2b512 = require("routex-client.crypto.blake2b_512")
local ChaCha20Poly1305 = require("routex-client.vendor.tls13.crypto.cipher.chacha20-poly1305").chacha20Poly1305
local HKDF = require("routex-client.crypto.hkdf").HKDF
local hmac = require("routex-client.vendor.tls13.crypto.hmac")
local util = require("routex-client.util")
local x25519 = require("routex-client.crypto.x25519")

---Generate cipher
---@param recipientPublicKey YAXI.Crypto.X25519PublicKey
---@param secretKey YAXI.Crypto.X25519PrivateKey
---@param info binary
---@return table
local function genCipher(recipientPublicKey, secretKey, info)
  local sharedSecret = secretKey:exchange(recipientPublicKey)
  local hmacBlake2b512 = hmac.hmac(Blake2b512)
  local hkdfBlake2b = HKDF:new(hmacBlake2b512, 32, "", info)
  assert(hkdfBlake2b, "HKDF-Blake2b should be valid")
  local sharedKey = hkdfBlake2b:derive(sharedSecret)
  local cipher = ChaCha20Poly1305(sharedKey)
  return cipher
end

---Compose the nonce
---@param ephemeralPk YAXI.Crypto.X25519PublicKey
---@param recipientPublicKey YAXI.Crypto.X25519PublicKey
---@return binary
local function getSealNonce(ephemeralPk, recipientPublicKey)
  local message = ephemeralPk:publicBytesRaw() .. recipientPublicKey:publicBytesRaw()
  local res = Blake2b512:new(12):update(message):finish()
  assert(res, "Blake2b should produce a digest")
  return res
end

---Compose the info
---@param ephemeralPk YAXI.Crypto.X25519PublicKey
---@param recipientPublicKey YAXI.Crypto.X25519PublicKey
---@return binary
local function getInfo(ephemeralPk, recipientPublicKey)
  return ephemeralPk:publicBytesRaw() .. recipientPublicKey:publicBytesRaw()
end

---Create a sealed box
---@param recipientPublicKey YAXI.Crypto.X25519PublicKey
---@param plaintext binary
---@return string
local function seal(recipientPublicKey, plaintext)
  local ephemeralSecretKey = x25519.X25519PrivateKey.generate()
  local ephemeralPublicKey = ephemeralSecretKey:publicKey()
  local nonce = getSealNonce(ephemeralPublicKey, recipientPublicKey)
  local cipher = genCipher(recipientPublicKey, ephemeralSecretKey, getInfo(ephemeralPublicKey, recipientPublicKey))
  local ciphertext = cipher:encrypt(plaintext, nonce, "")
  local chachaBox = ephemeralPublicKey:publicBytesRaw() .. ciphertext
  return chachaBox
end

---Unseal a sealed box
---@param secretKey YAXI.Crypto.X25519PrivateKey
---@param chachaBox binary
---@return binary
local function unseal(secretKey, chachaBox)
  assert(#chachaBox >= 32, "passed `chachaBox` has insufficient bytes")
  local ephemeralPublicKey = x25519.X25519PublicKey:fromPublicBytes(string.sub(chachaBox, 1, 32))
  local ciphertext = string.sub(chachaBox, 33)
  local publicKey = secretKey:publicKey()
  local nonce = getSealNonce(ephemeralPublicKey, publicKey)
  local info = getInfo(ephemeralPublicKey, publicKey)
  local cipher = genCipher(ephemeralPublicKey, secretKey, info)
  local plaintext = cipher:decrypt(ciphertext, nonce, "")
  return plaintext
end

---@class YAXI.Crypto.PublicKey: YAXI.ClassBase
---@field private _key YAXI.Crypto.X25519PublicKey
---@field private __index table
local PublicKey = util.class()

---Create PublicKey from raw bytes
---@param data binary
---@return YAXI.Crypto.PublicKey
function PublicKey:fromPublicBytes(data)
  local obj = setmetatable({}, self)
  obj._key = x25519.X25519PublicKey:fromPublicBytes(data)
  return obj
end

---Size of the public key in bytes
---@return integer @bytes
function PublicKey.size()
  return 32
end

---Raw public bytes
---@return binary
function PublicKey:publicBytesRaw()
  return self._key:publicBytesRaw()
end

---Seal the given `plaintext` data
---@param plaintext binary
---@return binary
function PublicKey:seal(plaintext)
  return seal(self._key, plaintext)
end

---@class YAXI.Crypto.SecretKey
---@field private _key YAXI.Crypto.X25519PrivateKey
---@field private __index table
local SecretKey = {}
SecretKey.__index = SecretKey

---Generate a new random secret key
---@return YAXI.Crypto.SecretKey
function SecretKey.generate()
  local self = setmetatable({}, SecretKey)
  self._key = x25519.X25519PrivateKey.generate()
  return self
end

---Raw secret key bytes
---@return binary
function SecretKey:bytes()
  return self._key:privateBytesRaw()
end

---Get the corresponding public key
---@return YAXI.Crypto.PublicKey
function SecretKey:publicKey()
  return PublicKey:fromPublicBytes(self._key:publicKey():publicBytesRaw())
end

---Unseal the given `chachaBox`
---@param chachaBox binary
---@return binary
function SecretKey:unseal(chachaBox)
  return unseal(self._key, chachaBox)
end

return {
  seal = seal,
  unseal = unseal,
  SecretKey = SecretKey,
  PublicKey = PublicKey,
}
