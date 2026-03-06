-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

require("tests.init")

local YAXI_DEMO_CONNECTION_ID = "connection-96386142-60e5-4ca9-abcf-944efce5bc1e"

local log = require("routex-client.logging").defaultLogger()

local helpers = require("tests.helpers")
local random = require("routex-client.crypto.random")
local uuid = require("routex-client.util.uuid")
local jwtDecodeUnverified = helpers.jwtDecodeUnverified
local base64 = require("routex-client.util.base64")

local routexClient = require("routex-client")
local AccountField = routexClient.AccountField
local AccountType = routexClient.AccountType
local ConnectionType = routexClient.ConnectionType
local SupportedService = routexClient.SupportedService
local PaymentProduct = routexClient.PaymentProduct
-- Response types
local OBResponse = routexClient.OBResponse
local DialogContext = routexClient.DialogContext
local Dialog = routexClient.Dialog
local InputType = routexClient.InputType
local SecrecyLevel = routexClient.SecrecyLevel
local Result = routexClient.Result
local Field = routexClient.Field
local Confirmation = routexClient.Confirmation
local Redirect = routexClient.Redirect
local RedirectHandle = routexClient.RedirectHandle
-- Errors
local Error = routexClient.Error
local TicketError = routexClient.TicketError
local TicketErrorCode = routexClient.TicketErrorCode
local NotFoundError = routexClient.NotFoundError

local KeySettlement = require("routex-client.settlement")

local ticket = require("tests.ticket")

local Request = require("routex-client.http").Request

---@return YAXI.RoutexClient.RoutexClient
---@return YAXI.Ticket.Generator
---@return string
local function setup()
  -- Configuration from environment
  local config = helpers.getConfig()
  log:debug("routex URL: %s", config.url)
  log:debug("API key ID: %s", config.keyId)
  log:debug("API key secret: %s (%s bytes)", string.rep("*", #config.key), #config.key)
  log:debug("Test signing keys: %s", config.testSigningKeys and "yes" or "no")

  local client = routexClient.RoutexClient:new(config.url)
  if config.testSigningKeys then
    local keySettlement = KeySettlement:new(string.format("%s/key-settlement", config.url), config.testSigningKeys)
    ---@diagnostic disable-next-line: invisible
    client._settlement = keySettlement
  end

  local ticketGenerator = ticket.Generator:new(config.keyId, config.key)

  local apiKeySecret = base64.decode(config.key)
  assert(apiKeySecret ~= nil, "Failed to Base64-decode API key secret")

  return client, ticketGenerator, apiKeySecret
end

context("RoutexClient #online", function()
  local json = require("routex-client.vendor.json")
  local client, ticketGenerator, apiKeySecret = setup()

  test("Service CollectPayment", function()
    local accountsTicket = ticketGenerator:accounts(uuid.uuid4())

    log:debug("Accounts ticket: %s", accountsTicket)

    local ok, response = pcall(function()
      return client:accounts({
        credentials = {
          connectionId = YAXI_DEMO_CONNECTION_ID,
          userId = "input",
        },
        ticket = accountsTicket,
        fields = {
          AccountField.Iban,
          AccountField.Bic,
          AccountField.Name,
          AccountField.DisplayName,
          AccountField.OwnerName,
          AccountField.Currency,
        },
        filter = {
          all = {
            { notEq = { AccountField.Iban, nil } },
            {
              any = {
                { eq = { AccountField.Type, AccountType.Savings } },
                { eq = { AccountField.Type, AccountType.Current } },
                { eq = { AccountField.Type, nil } },
              },
            },
            { supports = SupportedService.CollectPayment },
          },
        },
      })
    end)

    if not ok then
      local err = response --[[@as YAXI.RoutexClient.Error]]
      local msg = string.format("%s: %s", err.name, err.message)
      if err.options then
        local opts = err.options
        msg = string.format(
          "%s (caused by %s:%s:%s):%s",
          msg,
          opts.fileName,
          opts.lineNumber,
          opts.functionName,
          opts.stackTrace
        )
      end
      error(msg)
    end

    assert(response:isInstanceOf(Dialog), "Expected a Dialog")
    local dialog = response --[[@as YAXI.RoutexClient.Dialog]]
    assert(dialog.context == DialogContext.Sca)
    assert(dialog.input, "Expected an input")
    assert(dialog.input:isInstanceOf(Field), "Expected an input of type Field")
    local fieldInput = dialog.input --[[@as YAXI.RoutexClient.Dialog.Input.Field]]

    local context = fieldInput.context
    response = client:respondAccounts({
      ticket = accountsTicket,
      context = context,
      response = "133742",
    })

    assert(response:isInstanceOf(Result), "Expected a Result")
    local result = response --[[@as YAXI.RoutexClient.Result]]

    local jwtPayload = jwtDecodeUnverified(result.jwt)
    local firstAccount = jwtPayload.data.data[1]
    assert.same({
      bic = "BYLADEM1001",
      iban = "DE02120300000000202051",
      currency = "EUR",
      ownerName = "Dr. Peter Steiger",
    }, firstAccount)

    assert(
      jwtPayload.data.ticketId == ticket.getId(accountsTicket),
      "Expected ID of result JWT to be equal to the accounts ticket ID"
    )

    local session = result.session
    local connectionData = result.connectionData

    local ownerNames = {}
    for _, account in pairs(jwtPayload.data.data) do
      table.insert(ownerNames, account.ownerName)
    end
    assert.same({ "Dr. Peter Steiger" }, ownerNames)

    local selectedAccount = firstAccount.iban
    local paymentTicket = ticketGenerator:collectPayment(uuid.uuid4(), {
      amount = {
        amount = "100",
        currency = "EUR",
      },
      creditorAccount = {
        iban = "DE79430609671288143100",
      },
      creditorName = "YAXI GmbH",
      remittance = "Sign-up fee routex 123456789",
    })

    response = client:collectPayment({
      credentials = {
        connectionData = connectionData,
        connectionId = YAXI_DEMO_CONNECTION_ID,
        userId = "confirmation",
      },
      session = session,
      ticket = paymentTicket,
      account = {
        iban = selectedAccount,
      },
    })

    assert(response:isInstanceOf(Dialog), "Expected a Dialog")
    dialog = response --[[@as YAXI.RoutexClient.Dialog]]
    assert(dialog.input:isInstanceOf(Confirmation), "Expected a Confirmation")
    assert.same(1, dialog.input.pollingDelaySecs)
    local confirmationInput = dialog.input --[[@as YAXI.RoutexClient.Dialog.Input.Confirmation]]

    response = client:confirmCollectPayment({
      ticket = paymentTicket,
      context = confirmationInput.context,
    })

    assert(response:isInstanceOf(Result), "Expected a Result")
    result = response --[[@as YAXI.RoutexClient.Result]]

    jwtPayload = jwtDecodeUnverified(result.jwt)
    assert.same(jwtPayload.data.data, {}, "Expected no Result data")
  end)

  test("Service CollectPayment with debtor identification", function()
    local paymentTicket = ticketGenerator:collectPayment(uuid.uuid4(), {
      amount = {
        amount = "100",
        currency = "EUR",
      },
      creditorAccount = {
        iban = "DE79430609671288143100",
      },
      creditorName = "YAXI GmbH",
      remittance = "Sign-up fee routex 123456789",
      fields = { "debtorIban", "debtorName" },
    })

    local response = client:collectPayment({
      credentials = {
        connectionId = YAXI_DEMO_CONNECTION_ID,
        userId = "result",
      },
      ticket = paymentTicket,
      account = {
        iban = "DE02120300000000202051",
      },
    })

    assert(response:isInstanceOf(Result), "Expected a Result")
    local result = response --[[@as YAXI.RoutexClient.Result]]

    local jwtPayload = jwtDecodeUnverified(result.jwt)
    assert.same({
      debtorName = "Dr. Peter Steiger",
      debtorIban = "DE02120300000000202051",
    }, jwtPayload.data.data, "Expected debtor name and IBAN in Result data")
  end)

  test("Service CollectPayment with encrypted IBAN", function()
    local encrypt = function(plaintext, secret)
      local HKDF = require("routex-client.crypto.hkdf").HKDF
      local Blake2b512 = require("routex-client.crypto.blake2b_512")
      local hmac = require("routex-client.vendor.tls13.crypto.hmac")
      local ChaCha20Poly1305 = require("routex-client.vendor.tls13.crypto.cipher.chacha20-poly1305").chacha20Poly1305

      local hmacBlake2b512 = hmac.hmac(Blake2b512)
      local hkdf_blake2b = HKDF:new(hmacBlake2b512, 32, "", "on-file-data")
      local shared_key = hkdf_blake2b:derive(secret)
      local cipher = ChaCha20Poly1305(shared_key)
      local nonce = random.urandom(12)
      local ciphertext = cipher:encrypt(plaintext, nonce, "")

      return nonce .. ciphertext
    end

    local paymentTicket = ticketGenerator:collectPayment(uuid.uuid4(), {
      amount = {
        amount = "100",
        currency = "EUR",
      },
      creditorAccount = {
        iban = "DE79430609671288143100",
      },
      creditorName = "YAXI GmbH",
      remittance = "Sign-up fee routex 123456789",
      fields = { "debtorIban", "debtorName" },
    })

    local debtorIbanEncrypted = base64.encode(encrypt("DE02120300000000202051", apiKeySecret))

    local response = client:collectPayment({
      credentials = {
        connectionId = YAXI_DEMO_CONNECTION_ID,
        userId = "result",
      },
      ticket = paymentTicket,
      account = {
        encryptedIban = debtorIbanEncrypted,
        currency = "EUR",
      },
    })

    assert(response:isInstanceOf(Result), "Expected a Result")
    local result = response --[[@as YAXI.RoutexClient.Result]]

    local jwtPayload = jwtDecodeUnverified(result.jwt)
    assert.same({
      debtorName = "Dr. Peter Steiger",
      debtorIban = "DE02120300000000202051",
    }, jwtPayload.data.data, "Expected debtor name and IBAN in Result data")
  end)

  context("AccountFilter", function()
    local function fetchAccounts(filter)
      local accountsTicket = ticketGenerator:accounts(uuid.uuid4())
      local response = client:accounts({
        credentials = {
          connectionId = YAXI_DEMO_CONNECTION_ID,
          userId = "result",
        },
        ticket = accountsTicket,
        fields = { AccountField.Iban },
        filter = filter,
      })
      assert(response:isInstanceOf(Result), "Expected a Result")
      local result = response --[[@as YAXI.RoutexClient.Result]]
      return jwtDecodeUnverified(result.jwt).data.data
    end

    test("all with 0 elements (always true)", function()
      local accounts = fetchAccounts({ all = {} })
      assert.is_not.equal(0, #accounts)
    end)

    test("any with 0 elements (always false)", function()
      local accounts = fetchAccounts({ any = {} })
      assert.same(0, #accounts)
    end)

    test("all with 1 element", function()
      local accounts = fetchAccounts({
        all = { { notEq = { AccountField.Iban, nil } } },
      })
      assert.is_not.equal(0, #accounts)
    end)

    test("all with 1 element (no match)", function()
      local accounts = fetchAccounts({
        all = { { eq = { AccountField.Iban, nil } } },
      })
      assert.same(0, #accounts)
    end)

    test("all with 2 elements", function()
      local accounts = fetchAccounts({
        all = {
          { notEq = { AccountField.Iban, nil } },
          { supports = SupportedService.CollectPayment },
        },
      })
      assert.is_not.equal(0, #accounts)
    end)

    test("all with 2 elements (no match)", function()
      local accounts = fetchAccounts({
        all = {
          { notEq = { AccountField.Iban, nil } },
          { eq = { AccountField.Iban, nil } },
        },
      })
      assert.same(0, #accounts)
    end)

    test("all with more than 2 elements", function()
      local accounts = fetchAccounts({
        all = {
          { notEq = { AccountField.Iban, nil } },
          { supports = SupportedService.CollectPayment },
          { notEq = { AccountField.Bic, nil } },
        },
      })
      assert.is_not.equal(0, #accounts)
    end)

    test("all with more than 2 elements (no match)", function()
      local accounts = fetchAccounts({
        all = {
          { notEq = { AccountField.Iban, nil } },
          { supports = SupportedService.CollectPayment },
          { eq = { AccountField.Iban, nil } },
        },
      })
      assert.same(0, #accounts)
    end)

    test("any with 1 element", function()
      local accounts = fetchAccounts({
        any = { { supports = SupportedService.CollectPayment } },
      })
      assert.is_not.equal(0, #accounts)
    end)

    test("any with 1 element (no match)", function()
      local accounts = fetchAccounts({
        any = { { eq = { AccountField.Iban, nil } } },
      })
      assert.same(0, #accounts)
    end)

    test("any with 2 elements", function()
      local accounts = fetchAccounts({
        any = {
          { eq = { AccountField.Iban, nil } },
          { notEq = { AccountField.Iban, nil } },
        },
      })
      assert.is_not.equal(0, #accounts)
    end)

    test("any with 2 elements (no match)", function()
      local accounts = fetchAccounts({
        any = {
          { eq = { AccountField.Iban, nil } },
          { eq = { AccountField.Bic, nil } },
        },
      })
      assert.same(0, #accounts)
    end)

    test("any with more than 2 elements", function()
      local accounts = fetchAccounts({
        any = {
          { eq = { AccountField.Iban, nil } },
          { eq = { AccountField.Bic, nil } },
          { notEq = { AccountField.Iban, nil } },
        },
      })
      assert.is_not.equal(0, #accounts)
    end)

    test("any with more than 2 elements (no match)", function()
      local accounts = fetchAccounts({
        any = {
          { eq = { AccountField.Iban, nil } },
          { eq = { AccountField.Bic, nil } },
          { eq = { AccountField.Iban, nil } },
        },
      })
      assert.same(0, #accounts)
    end)

    test("nested any inside all", function()
      local accounts = fetchAccounts({
        all = {
          { notEq = { AccountField.Iban, nil } },
          {
            any = {
              { eq = { AccountField.Iban, nil } },
              { supports = SupportedService.CollectPayment },
            },
          },
        },
      })
      assert.is_not.equal(0, #accounts)
    end)

    test("nested any inside all (no match)", function()
      local accounts = fetchAccounts({
        all = {
          { notEq = { AccountField.Iban, nil } },
          {
            any = {
              { eq = { AccountField.Iban, nil } },
              { eq = { AccountField.Bic, nil } },
            },
          },
        },
      })
      assert.same(0, #accounts)
    end)

    test("nested all inside any", function()
      local accounts = fetchAccounts({
        any = {
          { eq = { AccountField.Iban, nil } },
          {
            all = {
              { notEq = { AccountField.Iban, nil } },
              { supports = SupportedService.CollectPayment },
            },
          },
        },
      })
      assert.is_not.equal(0, #accounts)
    end)

    test("nested all inside any (no match)", function()
      local accounts = fetchAccounts({
        any = {
          { eq = { AccountField.Iban, nil } },
          {
            all = {
              { notEq = { AccountField.Iban, nil } },
              { eq = { AccountField.Iban, nil } },
            },
          },
        },
      })
      assert.same(0, #accounts)
    end)
  end)

  test("Service Transfer", function()
    local transferTicket = ticketGenerator:issue(uuid.uuid4(), "Transfer")

    ---@type YAXI.RoutexClient.Credentials
    local credentials = {
      connectionId = YAXI_DEMO_CONNECTION_ID,
      userId = "confirmation",
    }

    local response = client:transfer({
      credentials = credentials,
      ticket = transferTicket,
      product = PaymentProduct.DefaultSepaCreditTransfer,
      details = {
        {
          amount = {
            amount = 1,
            currency = "EUR",
          },
          creditorAccount = {
            iban = "DE79430609671288143100",
          },
          creditorName = "YAXI GmbH",
        },
      },
    })

    assert(response:isInstanceOf(Dialog), "Expected a Dialog")
    local dialog = response --[[@as YAXI.RoutexClient.Dialog]]
    assert(dialog.context == DialogContext.Sca)
    assert(dialog.input, "Expected an input")
    assert(dialog.input:isInstanceOf(Confirmation), "Expected an input of type Confirmation")
    assert.same(1, dialog.input.pollingDelaySecs)
    local confirmationInput = dialog.input --[[@as YAXI.RoutexClient.Dialog.Input.Confirmation]]

    response = client:confirmTransfer({
      ticket = transferTicket,
      context = confirmationInput.context,
    })

    assert(response:isInstanceOf(Result), "Expected a Result")
    local result = response --[[@as YAXI.RoutexClient.Result]]

    local jwtPayload = jwtDecodeUnverified(result.jwt)
    assert.equal(jwtPayload.data.ticketId, ticket.getId(transferTicket))
    assert.same(jwtPayload.data.data, {}, "Expected no Result data")
  end)

  test("Service Balances", function()
    local balancesTicket = ticketGenerator:issue(uuid.uuid4(), "Balances")
    ---@type YAXI.RoutexClient.Credentials
    local credentials = {
      connectionId = YAXI_DEMO_CONNECTION_ID,
      userId = "confirmation",
    }

    local response = client:balances({
      credentials = credentials,
      ticket = balancesTicket,
      accounts = {
        {
          iban = "DE02120300000000202051",
          currency = "EUR",
        },
      },
    })

    assert(response:isInstanceOf(Dialog), "Expected a Dialog")
    local dialog = response --[[@as YAXI.RoutexClient.Dialog]]
    assert(dialog.context == DialogContext.Sca)
    assert(dialog.input, "Expected an input")
    assert(dialog.input:isInstanceOf(Confirmation), "Expected an input of type Confirmation")
    assert.same(1, dialog.input.pollingDelaySecs)
    local confirmationInput = dialog.input --[[@as YAXI.RoutexClient.Dialog.Input.Confirmation]]

    response = client:confirmBalances({
      ticket = balancesTicket,
      context = confirmationInput.context,
    })

    assert(response:isInstanceOf(Result), "Expected a Result")
    local result = response --[[@as YAXI.RoutexClient.Result]]

    local jwtPayload = jwtDecodeUnverified(result.jwt)
    assert(
      jwtPayload.data.ticketId == ticket.getId(balancesTicket),
      "Expected ID of result JWT to be equal to the balances ticket ID"
    )
    assert.same({
      balances = {
        {
          account = {
            currency = "EUR",
            iban = "DE02120300000000202051",
          },
          balances = {
            { amount = "8877.78", balanceType = "Booked", currency = "EUR" },
            { amount = "8947.64", balanceType = "Available", currency = "EUR" },
          },
        },
      },
    }, jwtPayload.data.data)
  end)

  test("Connection info", function()
    local userInput = "sparkasse stadt"

    -- Split input at whitespace for improved name matching
    ---@type YAXI.RoutexClient.SearchFilter[]
    local filters = {}
    for match in userInput:gmatch("%S+") do
      table.insert(filters, {
        term = match,
      })
    end

    local accountsTicket = ticketGenerator:accounts(uuid.uuid4())

    local connectionInfos = client:search({
      ticket = accountsTicket,
      filters = filters,
      ibanDetection = true,
      limit = 20,
    })

    assert.same({
      {
        id = "connection-6eb60518-dc4c-4d09-aa42-e38453d5c366",
        countries = { "DE" },
        displayName = "Stadtsparkasse Schwedt",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-8af40d65-8393-41c4-8c78-09cc652a8f26",
        countries = { "DE" },
        displayName = "Stadtsparkasse Wedel",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-8d762a37-df3d-44c3-ba0f-c928a263b360",
        countries = { "DE" },
        displayName = "Stadtsparkasse Cuxhaven",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-0c02cd7e-2164-43b4-bafd-96b18251058c",
        countries = { "DE" },
        displayName = "Stadtsparkasse Barsinghausen",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-3c871e2a-1e64-40c8-9648-94e9414f3f6e",
        countries = { "DE" },
        displayName = "Stadtsparkasse Burgdorf",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-a997832f-a868-45e5-8229-d0fb66af8e46",
        countries = { "DE" },
        displayName = "Stadtsparkasse Bad Pyrmont",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-3c0ec6db-f1e0-4bfb-be0b-4e5af8a7ad4e",
        countries = { "DE" },
        displayName = "Sparkasse Duderstadt",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-889582a7-49b7-4b04-8095-ec82d3e820aa",
        countries = { "DE" },
        displayName = "Stadtsparkasse Düsseldorf",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-0bfa12a2-ebf2-4adb-b8d1-735e33095022",
        countries = { "DE" },
        displayName = "Stadt-Sparkasse Haan (Rheinland)",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-500e6951-dcbe-45a7-b8d7-ba1a1961af1e",
        countries = { "DE" },
        displayName = "Stadtsparkasse Mönchengladbach",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-1d4e32aa-6d1c-4ab1-81ff-7f6d1870af4e",
        countries = { "DE" },
        displayName = "Stadtsparkasse Wuppertal",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-41c751be-16dd-4527-9ba8-98ccf65f1520",
        countries = { "DE" },
        displayName = "Stadtsparkasse Remscheid",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-95d9780e-18f7-42f0-8ad9-04d243769578",
        countries = { "DE" },
        displayName = "Stadtsparkasse Wermelskirchen",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-51ecdf0f-6984-4d6c-9420-ec9ba66a01c8",
        countries = { "DE" },
        displayName = "Stadt-Sparkasse Solingen",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-931f52d1-b108-4914-a75a-5b3d0715332f",
        countries = { "DE" },
        displayName = "Stadtsparkasse Oberhausen",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-24570ecb-a2c0-4e2b-9448-1a1eef9c4009",
        countries = { "DE" },
        displayName = "Stadt-Sparkasse Langenfeld",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-8eca5600-89aa-487b-b766-a2a8c9bf6e07",
        countries = { "DE" },
        displayName = "Stadtsparkasse Lengerich",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-099c2821-a46e-4d88-a0c1-5feda0ab63e2",
        countries = { "DE" },
        displayName = "Stadtsparkasse Rheine",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-499673bd-9907-4c26-88fc-172af8c8032c",
        countries = { "DE" },
        displayName = "Stadtsparkasse Bocholt",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
      {
        id = "connection-ddc4826a-2b93-4d70-92d0-0b5cf53163ab",
        countries = { "DE" },
        displayName = "Sparkasse Attendorn-Lennestadt-Kirchhundem",
        credentials = { full = true, userId = false, none = true },
        logoId = "sparkasse",
        userId = "Anmeldename",
        password = "Online-Banking-PIN",
      },
    }, connectionInfos)
  end)

  test("Public search", function()
    local result = client:search({
      filters = {
        {
          types = { ConnectionType.Production },
        },
        {
          name = "C24 Bank",
        },
      },
    })

    for _, info in ipairs(result) do
      assert(info.displayName == "C24 Bank")
    end
  end)

  test("System version", function()
    local systemVersion = client:systemVersion()
    assert.is_not_nil(systemVersion)
    assert.is_string(systemVersion.kind)
    assert.is_number(systemVersion.generation)
    assert.is_string(systemVersion.createdAt)
    assert.is_string(systemVersion.ref)
    assert.is_string(systemVersion.launchMeasurement)
  end)

  test("Service Transactions", function()
    local transactionsTicket = ticketGenerator:transactions(uuid.uuid4(), {
      account = {
        iban = "DE02120300000000202051",
        currency = "EUR",
      },
      range = {
        from = "2019-01-13",
      },
    })

    local credentials = {
      connectionId = "connection-96386142-60e5-4ca9-abcf-944efce5bc1e",
      userId = "confirmation",
    }

    local response = client:transactions({
      credentials = credentials,
      ticket = transactionsTicket,
    })

    assert(response:isInstanceOf(Dialog), "Expected a Dialog")
    local dialog = response --[[@as YAXI.RoutexClient.Dialog]]
    assert(dialog.context == DialogContext.Sca)
    assert(dialog.input, "Expected an input")
    assert(dialog.input:isInstanceOf(Confirmation), "Expected an input of type Confirmation")
    assert.same(1, dialog.input.pollingDelaySecs)
    local confirmationInput = dialog.input --[[@as YAXI.RoutexClient.Dialog.Input.Confirmation]]

    response = client:confirmTransactions({
      ticket = transactionsTicket,
      context = confirmationInput.context,
    })

    assert(response:isInstanceOf(Result), "Expected a Result")
    local result = response --[[@as YAXI.RoutexClient.Result]]

    local jwtPayload = jwtDecodeUnverified(result.jwt)
    assert(
      jwtPayload.data.ticketId == ticket.getId(transactionsTicket),
      "Expected ID of result JWT to be equal to the transactionsTicket ticket ID"
    )
    assert.same(63, #jwtPayload.data.data)
    assert.same({
      amount = { amount = "-0.95", currency = "EUR" },
      bankTransactionCodes = {
        { iso = { domain = "PMNT", family = "ICDT", subFamily = "STDO" } },
        { swift = "DDT" },
        { national = { code = "106", country = "DE" } },
      },
      bookingDate = "2025-07-29",
      creditor = { iban = "DE96120300009005290904", name = "DHL.K53VEV55WWVE/BONN" },
      debtor = { iban = "DE02120300000000202051", name = "ISSUER" },
      endToEndId = "485209459755938",
      purposeCode = "DCRD",
      remittanceInformation = {
        "VISA Debitkartenumsatz",
      },
      status = "Booked",
      valueDate = "2025-07-29",
    }, jwtPayload.data.data[1])
  end)

  context("Redirect dialogs", function()
    ---@diagnostic disable-next-line: invisible
    local httpClient = client._httpClient

    ---@type YAXI.RoutexClient.Credentials
    local redirectCredentials = {
      connectionId = YAXI_DEMO_CONNECTION_ID,
      userId = "redirect",
    }

    ---Manually handle the redirect to remux
    ---@param url string
    ---@return string
    local function handleRedirect(url)
      local redirectBaseUrl = "https://redirect.yaxi.tech"
      if url:find(redirectBaseUrl) == 1 then
        local redirectQuery = url:sub(#redirectBaseUrl + 1 + 2) -- also skip the '/?'
        local request = Request:builder("https://remux.yaxi.tech/redirect"):method("POST"):data(redirectQuery):build()
        local response, request = httpClient:request(request)
        local res = response.body
        if response.status ~= 200 or res == nil or res == "" then
          error(
            string.format("Expected response status 200 with a body\nRequest:\n%s\nResponse:\n%s", request, response)
          )
        end
        return res
      else
        local response, request = httpClient:request(Request:builder(url):method("GET"):followRedirects(false):build())
        local res = response.headers["location"]
        if response.status ~= 303 or not res then
          error(
            string.format(
              "Expected response status 303, got %s.\nRequest:\n%s\nResponse:\n%s",
              response.status,
              request,
              response
            )
          )
        end
        return res
      end
    end

    test("RedirectHandle", function()
      local accountsTicket = ticketGenerator:accounts(uuid.uuid4())

      local response = client:accounts({
        credentials = redirectCredentials,
        ticket = accountsTicket,
        fields = {},
      })

      assert(response:isInstanceOf(RedirectHandle), "Expected a RedirectHandle")
      local redirectHandle = response --[[@as YAXI.RoutexClient.RedirectHandle]]

      local handle = redirectHandle.handle

      local redirectUrl = client:registerRedirectUri({
        ticket = accountsTicket,
        handle = handle,
        redirectUri = "myapp://redirect?context=signup",
      })

      local finalRedirectUrl = handleRedirect(redirectUrl)
      local expectedUrl = "myapp://redirect?context=signup"
      assert(
        finalRedirectUrl == expectedUrl,
        string.format("Expected a redirect to %s, got: %s", expectedUrl, finalRedirectUrl)
      )

      response = client:confirmAccounts({
        ticket = accountsTicket,
        context = redirectHandle.context,
      })

      assert(response:isInstanceOf(Result), "Expected a Result")
    end)

    test("setRedirectUri", function()
      client:setRedirectUri("myapp://redirect?context=signup")

      local accountsTicket = ticketGenerator:accounts(uuid.uuid4())

      local response = client:accounts({
        credentials = redirectCredentials,
        ticket = accountsTicket,
        fields = {},
      })

      assert(response:isInstanceOf(Redirect), "Expected a Redirect")
      local redirect = response --[[@as YAXI.RoutexClient.Redirect]]

      local finalRedirectUrl = handleRedirect(redirect.url)
      local expectedUrl = "myapp://redirect?context=signup"
      assert(
        finalRedirectUrl == expectedUrl,
        string.format("Expected a redirect to %s, got: %s", expectedUrl, finalRedirectUrl)
      )

      response = client:confirmAccounts({
        ticket = accountsTicket,
        context = redirect.context,
      })

      assert(response:isInstanceOf(Result), "Expected a Result")
    end)
  end)

  context("Errors", function()
    test("Error expired ticket", function()
      -- Issue already expired ticket
      local accountsTicket = ticketGenerator:accounts(uuid.uuid4(), os.time() - 5 * 60)
      ---@type boolean, YAXI.RoutexClient.OBResponse?
      local ok, response = pcall(function()
        client:info({
          ticket = accountsTicket,
          connectionId = YAXI_DEMO_CONNECTION_ID,
        })
      end)

      assert(not ok, "Expected an unsuccessful client:info() call")
      assert(response, "Expected an error object")
      assert(response:isInstanceOf(Error))
      assert(response:isInstanceOf(TicketError))

      local ticketError = response --[[@as YAXI.RoutexClient.Error.Ticket]]
      assert(ticketError.name == "TicketError")
      assert(ticketError.message == "Ticket is expired")
      assert(ticketError.code == TicketErrorCode.Expired)
    end)
  end)

  context("Traces", function()
    test("Retrieve trace", function()
      local traceId = client:traceId()

      local accountsTicket = ticketGenerator:accounts(uuid.uuid4())
      local connectionInfo = client:info({
        ticket = accountsTicket,
        connectionId = YAXI_DEMO_CONNECTION_ID,
      })
      assert(connectionInfo.id == YAXI_DEMO_CONNECTION_ID)

      assert(traceId ~= client:traceId(), "Expected a new trace ID after calling the service")
      traceId = client:traceId()
      assert(traceId ~= nil)

      local trace = client:trace(accountsTicket, traceId)
      assert(trace, "Expected a trace")
      if trace:find("^-----BEGIN AGE ENCRYPTED FILE-----") then
        -- traces are encrypted
        assert(trace:find("-----END AGE ENCRYPTED FILE-----\n$"), "Expected Age-encrypted trace")
      else
        -- traces are plain text
        local traceData = json.decode(trace)
        local firstElem = traceData.data and traceData.data[1]
        assert(firstElem, "Expected a trace element")
        assert(firstElem.traceID, "Expected the element to contain a trace ID")
      end
    end)

    test("Settles key", function()
      local client, ticketGenerator = setup()
      assert.is_nil(client._settlement._serverKey)

      local accountsTicket = ticketGenerator:accounts(uuid.uuid4())
      local ok, res = pcall(function()
        client:trace(accountsTicket, "wurzeltrace")
      end)
      assert.is_false(ok)
      assert.is_true(res:isInstanceOf(NotFoundError))

      assert.is_not_nil(client._settlement._serverKey)
    end)
  end)
end)

context("fromJSON/toJSON", function()
  local base64Data = "YWJjCg=="
  local binaryData = string.char(97, 98, 99, 10)

  test("Result", function()
    local json = {
      Result = { "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", base64Data, base64Data },
    }
    -- fromJSON
    local response = OBResponse.fromJSON(json)
    assert(response:isInstanceOf(Result), "Expected result to be instance of Result")
    local result = response --[[@as YAXI.RoutexClient.Result]]
    assert(result.jwt == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "Expected result.jwt to be the JWT value")
    assert(result.session == binaryData, "Expected result.session to be the decoded binary data")
    assert(result.connectionData == binaryData, "Expected result.connectionData to be the decoded binary data")
    -- toJSON
    assert.same(result:toJSON(), json)
  end)

  test("Dialog", function()
    local json = {
      Dialog = {
        context = "Sca",
        message = "Moep",
        image = { mimeType = "image/png", data = base64Data, hhdUcData = nil },
        input = {
          Field = {
            type = "Text",
            secrecyLevel = "Plain",
            minLength = 6,
            maxLength = 6,
            context = base64Data,
          },
        },
      },
    }
    -- fromJSON
    local response = OBResponse.fromJSON(json)
    assert(response:isInstanceOf(Dialog), "Expected dialog to be instance of Dialog")
    local dialog = response --[[@as YAXI.RoutexClient.Dialog]]
    assert(dialog.context == DialogContext.Sca, "Expected dialog.context to be Sca")
    assert(dialog.message == "Moep", "Expected dialog.message to be Moep")
    assert(dialog.image.mimeType == "image/png", "Expected dialog.image.mimeType to be image/png")
    assert(dialog.image.data == binaryData, "Expected dialog.image.data to be binary data")
    assert(getmetatable(dialog.input) == Field, "Expected dialog.input to be instance of Field")
    assert(dialog.input.type == InputType.Text, "Expected dialog.input.type to be Text")
    assert(dialog.input.secrecyLevel == SecrecyLevel.Plain, "Expected dialog.input.secrecyLevel to be Plain")
    assert(dialog.input.minLength == 6, "Expected dialog.input.minLength to be 6")
    assert(dialog.input.maxLength == 6, "Expected dialog.input.maxLength to be 6")
    assert(dialog.input.context == binaryData, "Expected dialog.input.context to be binary data")
    -- toJSON
    assert.same(dialog:toJSON(), json)
  end)

  test("Redirect", function()
    -- Create the JSON object
    local json = {
      Redirect = {
        url = "http://example.com/",
        context = base64Data,
      },
    }
    -- fromJSON
    local response = OBResponse.fromJSON(json)
    assert(response:isInstanceOf(Redirect), "Expected dialog to be instance of Redirect")
    local redirect = response --[[@as YAXI.RoutexClient.Redirect]]
    -- Assertions
    assert(redirect:isInstanceOf(Redirect), "Expected redirect to be instance of Redirect")
    assert(redirect.url == "http://example.com/", "Expected redirect.url to be 'http://example.com/'")
    assert(redirect.context == binaryData, "Expected redirect.context to be the decoded binary data")
    -- toJSON
    assert.same(redirect:toJSON(), json)
  end)

  test("RedirectHandle", function()
    -- Create the JSON object
    local json = {
      RedirectHandle = {
        handle = "wurzelpfropf",
        context = base64Data,
      },
    }
    -- fromJSON
    local response = OBResponse.fromJSON(json)
    assert(response:isInstanceOf(RedirectHandle), "Expected dialog to be instance of RedirectHandle")
    local redirectHandle = response --[[@as YAXI.RoutexClient.RedirectHandle]]
    -- Assertions
    assert(redirectHandle:isInstanceOf(RedirectHandle), "Expected redirectHandle to be instance of RedirectHandle")
    assert(redirectHandle.handle == "wurzelpfropf", "Expected redirectHandle.handle to be 'wurzelpfropf'")
    assert(redirectHandle.context == binaryData, "Expected redirectHandle.context to be the decoded binary data")
    -- toJSON
    assert.same(redirectHandle:toJSON(), json)
  end)
end)
