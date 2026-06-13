-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

-- Entry point of the `routex-client` package, re-exporting the interactive
-- client module. See `routex-client.refresh` for the non-interactive
-- `RoutexRefreshClient`.

return require("routex-client.client")
