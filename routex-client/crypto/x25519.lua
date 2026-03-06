-- A wrapper around ec25519 to provide a Python cryptography-like interface
--
-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

local curve25519 = require("routex-client.vendor.tls13.crypto.curve25519")
local random = require("routex-client.crypto.random")

---@class YAXI.Crypto.X25519PublicKey
---@field private _rawKey binary
---@field private __index table
local X25519PublicKey = {}
X25519PublicKey.__index = X25519PublicKey

---Create [X25519PublicKey](lua://YAXI.Crypto.X25519PublicKey) from bytes
---@param data binary
---@return YAXI.Crypto.X25519PublicKey
function X25519PublicKey:fromPublicBytes(data)
  assert(#data == 32, "data must be 32 bytes")
  local obj = setmetatable({}, self)
  obj._rawKey = data
  return obj
end

---Get the raw public bytes
---@return binary
function X25519PublicKey:publicBytesRaw()
  return self._rawKey
end

---@class YAXI.Crypto.X25519PrivateKey
---@field private _rawKey binary
local X25519PrivateKey = {}
X25519PrivateKey.__index = X25519PrivateKey

---Create [X25519PrivateKey](lua://YAXI.Crypto.X25519PrivateKey) from bytes
---@param data binary
---@return YAXI.Crypto.X25519PrivateKey
function X25519PrivateKey.fromPrivateBytes(data)
  assert(#data == 32, "data must be 32 bytes")
  local self = setmetatable({}, X25519PrivateKey)
  self._rawKey = data
  return self
end

---Generate a [X25519PrivateKey](lua://YAXI.Crypto.X25519PrivateKey) from random bytes
---@return YAXI.Crypto.X25519PrivateKey
function X25519PrivateKey.generate()
  local secret = random.urandom(32)
  return X25519PrivateKey.fromPrivateBytes(secret)
end

---Get public key
---@return YAXI.Crypto.X25519PublicKey
function X25519PrivateKey:publicKey()
  local pkRaw = curve25519.x25519PublicKeyFromPrivate(self._rawKey)
  return X25519PublicKey:fromPublicBytes(pkRaw)
end

---Exchange a shared key with a peer
---@param peerPublicKey YAXI.Crypto.X25519PublicKey
---@return binary
function X25519PrivateKey:exchange(peerPublicKey)
  local sk = { private = self._rawKey }
  local pk = { public = peerPublicKey:publicBytesRaw() }
  local sharedSecret, err = curve25519.deriveSharedSecret(sk, pk)
  if sharedSecret == nil then
    error(("Failed to exchange shared secret: %s"):format(err))
  end
  return sharedSecret
end

---Get the raw private bytes
---@return binary
function X25519PrivateKey:privateBytesRaw()
  return self._rawKey
end

return {
  X25519PublicKey = X25519PublicKey,
  X25519PrivateKey = X25519PrivateKey,
}
