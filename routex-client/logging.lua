-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

---Try to load `logging` from LUA_PATH first and fallback to our vendored version, if necessary
---@return table
local function findLoggingModule()
  local ok, logging = pcall(require, "logging")
  if not ok then
    logging = require("routex-client.vendor.logging")
    local consoleLogger = require("routex-client.vendor.logging.console")()
    consoleLogger:setLevel("WARN")
    assert(logging.defaultLogger, "logging module missing defaultLogger")(consoleLogger)
  end
  return logging --[[@as table]]
end

return findLoggingModule()
