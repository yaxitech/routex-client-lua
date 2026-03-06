-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

---Read random bytes from /dev/urandom
---@param nbytes number number of bytes to read
---@return binary
local function urandom(nbytes)
  local f = io.open("/dev/urandom", "rb")
  assert(f, "Failed to open /dev/urandom")
  local bytes = f:read(nbytes) ---@diagnostic disable-line: param-type-mismatch
  f:close()
  assert(#bytes == nbytes, "Failed to read enough bytes")
  return bytes
end

return {
  urandom = urandom,
}
