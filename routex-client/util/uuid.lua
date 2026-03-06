-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

local random = require("routex-client.crypto.random")
local util = require("routex-client.vendor.tls13.util")

local function generateUuidV4()
  local bytes = random.urandom(16)
  local hex = util.toHex(bytes)

  -- Set UUID version (4) and variant (10xx)
  -- Version (4 bits) in 7th byte: clear high nibble and set to 4
  local b7 = tonumber(hex:sub(13, 14), 16)
  b7 = (b7 & 0x0F) | 0x40
  hex = hex:sub(1, 12) .. string.format("%02x", b7) .. hex:sub(15)

  -- Variant (2 bits) in 9th byte: clear top two bits, set to 10xxxxxx
  local b9 = tonumber(hex:sub(17, 18), 16)
  b9 = (b9 & 0x3F) | 0x80
  hex = hex:sub(1, 16) .. string.format("%02x", b9) .. hex:sub(19)

  -- Insert hyphens: 8-4-4-4-12
  local uuid =
    string.format("%s-%s-%s-%s-%s", hex:sub(1, 8), hex:sub(9, 12), hex:sub(13, 16), hex:sub(17, 20), hex:sub(21, 32))

  return uuid
end

return {
  uuid4 = generateUuidV4,
}
