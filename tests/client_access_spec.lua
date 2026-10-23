-- SPDX-License-Identifier: MIT

require("tests.init")

local routexClient = require("routex-client")

-- The access check happens before any request, so these need no routex.
context("RoutexClient access", function()
  local client = routexClient.RoutexClient:new("http://127.0.0.1:1/")

  local credentials = { connectionId = "connection-96386142-60e5-4ca9-abcf-944efce5bc1e" }
  local accounts = { { iban = "DE02120300000000202051", currency = "EUR" } }

  ---@type table<string, fun(options: table): YAXI.RoutexClient.OBResponse>
  local services = {
    accounts = function(options)
      return client:accounts(options)
    end,
    balances = function(options)
      return client:balances(options)
    end,
    transactions = function(options)
      return client:transactions(options)
    end,
  }

  for _, service in ipairs({ "accounts", "balances", "transactions" }) do
    local call = services[service]

    test(service .. " rejects credentials together with connection data", function()
      local ok, err = pcall(call, {
        credentials = credentials,
        connectionData = "\1\2\3",
        accounts = accounts,
        ticket = "not-a-ticket",
      })

      assert.is_true(not ok)
      assert.is_true(tostring(err):find("mutually exclusive", 1, true) ~= nil)
    end)

    test(service .. " rejects neither credentials nor connection data", function()
      local ok, err = pcall(call, {
        accounts = accounts,
        ticket = "not-a-ticket",
      })

      assert.is_true(not ok)
      assert.is_true(tostring(err):find("must be given", 1, true) ~= nil)
    end)
  end
end)
