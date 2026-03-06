-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

local base64 = require("routex-client.vendor.plc.base64")

---Encode with URL-safe Base64 with no padding and no wrap
---@param data binary
---@return string
local function base64Urlsafe(data)
  local res = base64
    .encode(data, true) ---@diagnostic disable-line: redundant-parameter
    :gsub("\n", "")
  return res
end

---Encode with standard Base64 with padding and no wrap
---@param data binary
---@return string
local function base64Encode(data)
  local res = base64
    .encode(data, false) ---@diagnostic disable-line: redundant-parameter
    :gsub("\n", "")
  return res
end

return {
  encode = base64Encode,
  encodeWrap = base64.encode,
  encodeUrlsafe = base64Urlsafe,
  decode = base64.decode,
}
