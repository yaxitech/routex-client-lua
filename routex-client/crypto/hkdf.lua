-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

local hkdf = require("routex-client.vendor.tls13.crypto.hkdf")
local util = require("routex-client.util")

---@class YAXI.Crypto.HKDF: YAXI.ClassBase
---@field private _hkdf table
---@field private _salt string
---@field private _length integer
---@field private _info string
local HKDF = util.class()

---Create a new instance
---@param hmac table
---@param length integer
---@param salt binary
---@param info binary
---@return YAXI.Crypto.HKDF
function HKDF:new(hmac, length, salt, info)
  local obj = setmetatable({}, self)

  obj._hkdf = hkdf.hkdf(hmac)
  obj._length = length
  obj._salt = salt
  obj._info = info

  return obj
end

---@param keyMaterial binary
---@return binary
function HKDF:_extract(keyMaterial)
  return self._hkdf:extract(keyMaterial, self._salt)
end

---@param prk binary pseudo random key
---@return binary
function HKDF:_expand(prk)
  return self._hkdf:expand(self._info, self._length, prk)
end

---Derive a key
---@param keyMaterial binary
---@return binary
function HKDF:derive(keyMaterial)
  local prk = self:_extract(keyMaterial)
  return self:_expand(prk)
end

return { HKDF = HKDF }
