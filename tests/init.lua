-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

-- Logging setup
require("routex-client.logging").defaultLogger():setLevel(os.getenv("LUA_LOG") or "WARN")
