-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

require("tests.init")

local YAXI_DEMO_CONNECTION_ID = "connection-96386142-60e5-4ca9-abcf-944efce5bc1e"
local YAXI_DEMO_IBAN = "DE02120300000000202051"

local KeySettlement = require("routex-client.settlement")
local helpers = require("tests.helpers")
local refresh = require("routex-client.refresh")
local routexClient = require("routex-client")
local ticket = require("tests.ticket")
local uuid = require("routex-client.util.uuid")

local RoutexRefreshClient = refresh.RoutexRefreshClient
local AccountField = refresh.AccountField
local AccountType = refresh.AccountType
local SupportedService = refresh.SupportedService

local Result = routexClient.Result
local InterruptError = routexClient.InterruptError
local NotFoundError = routexClient.NotFoundError

---@return YAXI.RoutexClient.RoutexClient
---@return YAXI.RoutexRefreshClient
---@return YAXI.Ticket.Generator
local function setup()
  local config = helpers.getConfig()

  local client = routexClient.RoutexClient:new(config.url)
  local refreshClient = RoutexRefreshClient:new(config.url)

  if config.testSigningKeys then
    for _, c in ipairs({ client, refreshClient }) do
      ---@diagnostic disable-next-line: invisible
      c._settlement = KeySettlement:new(string.format("%s/key-settlement", config.url), config.testSigningKeys)
    end
  end

  local ticketGenerator = ticket.Generator:new(config.keyId, config.key)

  return client, refreshClient, ticketGenerator
end

context("RoutexRefreshClient #online", function()
  local client, refreshClient, ticketGenerator = setup()

  local accountFields = {
    AccountField.Iban,
    AccountField.Bic,
    AccountField.Name,
    AccountField.DisplayName,
    AccountField.OwnerName,
    AccountField.Currency,
  }

  ---@type YAXI.RoutexClient.AccountFilter
  local accountFilter = {
    all = {
      { notEq = { AccountField.Iban, nil } },
      {
        any = {
          { eq = { AccountField.Type, AccountType.Current } },
          { eq = { AccountField.Type, nil } },
        },
      },
      { supports = SupportedService.CollectPayment },
    },
  }

  ---Latest transactions range that does not trigger SCA on non-interactive sessions (< 90 days)
  ---@return YAXI.Ticket.Payload.Transactions.Range
  local function transactionsRange()
    return {
      from = os.date("!%Y-%m-%d", os.time() - 89 * 24 * 60 * 60) --[[@as string]],
    }
  end

  ---Run an interactive accounts flow once to obtain reference data
  ---and the connection data required for non-interactive calls.
  local interactive = nil
  ---@return { accounts: YAXI.RoutexClient.Result.Account[], connectionData: binary }
  local function interactiveAccounts()
    if interactive then
      return interactive
    end

    local response = client:accounts({
      credentials = {
        connectionId = YAXI_DEMO_CONNECTION_ID,
        userId = "result",
      },
      ticket = ticketGenerator:accounts(uuid.uuid4()),
      fields = accountFields,
      filter = accountFilter,
    })

    assert(response:isInstanceOf(Result), "Expected a Result")
    local result = response --[[@as YAXI.RoutexClient.Result]]
    assert(result.connectionData, "Expected connection data on the interactive result")

    interactive = {
      accounts = helpers.jwtDecodeUnverified(result.jwt).data.data,
      connectionData = result.connectionData,
    }
    return interactive
  end

  test("Accounts, balances and transactions match interactive results", function()
    local reference = interactiveAccounts()
    assert.same({
      {
        bic = "BYLADEM1001",
        iban = YAXI_DEMO_IBAN,
        currency = "EUR",
        ownerName = "Dr. Peter Steiger",
      },
    }, reference.accounts)

    -- Non-interactive accounts with the same fields and filter
    local accountsResponse = refreshClient:accounts({
      ticket = ticketGenerator:accounts(uuid.uuid4()),
      connectionData = reference.connectionData,
      fields = accountFields,
      filter = accountFilter,
    })
    assert.same(reference.accounts, accountsResponse.result)

    -- Non-interactive balances, continuing the session returned by the accounts call.
    -- The unknown account additionally has to get reported as missing.
    local balancesResponse = refreshClient:balances({
      ticket = ticketGenerator:balances(uuid.uuid4()),
      connectionData = accountsResponse.connectionData or reference.connectionData,
      session = accountsResponse.session,
      accounts = {
        { iban = YAXI_DEMO_IBAN, currency = "EUR" },
        { iban = "NL58YAXI1234567890", currency = "EUR" },
      },
    })
    for _, account in ipairs(balancesResponse.result.balances) do
      for _, balance in ipairs(account.balances) do
        assert.is_not_nil(balance.dateTime)
        balance.dateTime = nil
      end
    end

    assert.same({
      balances = {
        {
          account = { iban = YAXI_DEMO_IBAN, currency = "EUR" },
          balances = {
            {
              amount = "8877.78",
              balanceType = "Booked",
              currency = "EUR",
              creditLimitIncluded = false,
            },
            {
              amount = "8947.64",
              balanceType = "Available",
              currency = "EUR",
              creditLimitIncluded = false,
            },
          },
        },
      },
      missingAccounts = { { iban = "NL58YAXI1234567890", currency = "EUR" } },
    }, balancesResponse.result)

    -- Non-interactive transactions; the demo account has none within the range
    local transactionsResponse = refreshClient:transactions({
      ticket = ticketGenerator:transactions(uuid.uuid4(), {
        account = { iban = YAXI_DEMO_IBAN, currency = "EUR" },
        range = transactionsRange(),
      }),
      connectionData = reference.connectionData,
    })
    assert.same({}, transactionsResponse.result)
  end)

  test("Transactions requiring SCA raise InterruptError", function()
    local reference = interactiveAccounts()

    local ok, err = pcall(function()
      -- Transactions older than 90 days require SCA on non-interactive sessions
      return refreshClient:transactions({
        ticket = ticketGenerator:transactions(uuid.uuid4(), {
          account = { iban = YAXI_DEMO_IBAN, currency = "EUR" },
          range = { from = "2019-01-13" },
        }),
        connectionData = reference.connectionData,
      })
    end)

    assert.is_false(ok)
    assert(err, "Expected an error object")
    assert.is_true(err:isInstanceOf(InterruptError))
  end)

  test("Transactions for an unknown account raise NotFoundError", function()
    local reference = interactiveAccounts()

    local ok, err = pcall(function()
      return refreshClient:transactions({
        ticket = ticketGenerator:transactions(uuid.uuid4(), {
          account = { iban = "NL31YAXI1234567891", currency = "EUR" },
          range = transactionsRange(),
        }),
        connectionData = reference.connectionData,
      })
    end)

    assert.is_false(ok)
    assert(err, "Expected an error object")
    assert.is_true(err:isInstanceOf(NotFoundError))
  end)
end)
