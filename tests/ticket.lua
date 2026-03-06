-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

local base64 = require("routex-client.util.base64")
local jwt = require("routex-client.jwt")

---@class YAXI.Ticket.Header
---@field typ "JWT"
---@field alg "HS256"
---@field kid string

---@class YAXI.Ticket.Payload
---@field data { id: string, service: string, data: table<string, any>? }
---@field exp integer ticket validaty date as a POSIX timestamp

---@class YAXI.Ticket.Generator
---@field private _apiKeyId string YAXI key ID
---@field private _apiKeySecret binary Raw API key secret
local Generator = {}
Generator.__index = Generator

---Create a new instance
---@param apiKeyId string YAXI key ID
---@param apiKeySecret string Base64-encoded key secret
---@return YAXI.Ticket.Generator
function Generator:new(apiKeyId, apiKeySecret)
  ---@type YAXI.Ticket.Generator
  local obj = setmetatable({}, self)

  obj._apiKeyId = apiKeyId
  obj._apiKeySecret = base64.decode(apiKeySecret) or error("Failed to Base64-decode the API key secret")

  return obj
end

---Issue a new YAXI service ticket
---@param ticketId string A UUIDv4 in its string representation
---@param service "Accounts"|"CollectPayment"|"Balances"|"Transactions"|string YAXI service for which you want to issue the ticket
---@param data table? Additional data specific to the `service`
---@param exp integer? Expiration date as a POSIX timestamp; defaults to now + 5min
---@return string @YAXI ticket JWT
function Generator:issue(ticketId, service, data, exp)
  if #ticketId ~= 36 then
    error("Invalid ticket ID: expected 36 bytes UUID")
  end

  local headers = {
    kid = self._apiKeyId,
  }

  local nullValue = "__NULL__"
  local payload = {
    exp = exp or os.time() + (5 * 60),
    data = {
      id = ticketId,
      service = service,
      data = data or nullValue,
    },
  }

  local ticket = jwt.encode(payload, self._apiKeySecret, "HS256", headers, nullValue)

  return ticket
end

--#region Issue Accounts ticket

---Issue a ticket for the accounts service
---@param ticketId string A UUIDv4 in its string representation; generates an ID if not given
---@param exp integer? Expiration date as a POSIX timestamp; defaults to now + 5min
---@return string @YAXI ticket JWT
function Generator:accounts(ticketId, exp)
  return self:issue(ticketId, "Accounts", nil, exp)
end

--#endregion Issue Accounts ticket

--#region Issue Balances ticket

---Issue a ticket for the balances service
---@param ticketId string A UUIDv4 in its string representation; generates an ID if not given
---@param exp integer? Expiration date as a POSIX timestamp; defaults to now + 5min
---@return string @YAXI ticket JWT
function Generator:balances(ticketId, exp)
  return self:issue(ticketId, "Balances", nil, exp)
end

--#endregion Issue Balances ticket

--#region Issue Transactions ticket

---@class YAXI.Ticket.Payload.Transactions
---@field account YAXI.Ticket.Payload.Transactions.Account Account to gather transactions for. This could be provided by the user, known from a different source or from a different service like the Accounts service.
---@field range YAXI.Ticket.Payload.Transactions.Range Range of accounts to gather.
---@field webhook string? Webhook URL. If provided, the result JWT is delivered to it and no data gets returned to the client.

---@class YAXI.Ticket.Payload.Transactions.Range
---@field from string Date in format YYYY-MM-DD
---@field to string? Date in format YYYY-MM-DD

---@class YAXI.Ticket.Payload.Transactions.Account
---@field iban string IBAN.
---@field currency string? ISO 4217 Alpha 3 currency code for the account. The currency might be necessary to identify a sub account, so it should always be provided if known.

---Issue a ticket for the transactions service
---@param ticketId string A UUIDv4 in its string representation; generates an ID if not given
---@param data YAXI.Ticket.Payload.Transactions
---@param exp integer? Expiration date as a POSIX timestamp; defaults to now + 5min
---@return string @YAXI ticket JWT
function Generator:transactions(ticketId, data, exp)
  return self:issue(ticketId, "Transactions", data, exp)
end

--#endregion Issue Transactions ticket

--#region Issue CollectPayment ticket

--- Restrictions on remittance and creditor name:
--- - Some banks require a minimum remittance of a few characters.
--- - Long texts may be truncated, typically with a limit of 140 characters for remittance and 70 for the creditor name.
--- - Providers accept different character sets for the creditor name and remittance. The safe baseline is:
---   ```
---   abcdefghijklmnopqrstuvwxyz
---   ABCDEFGHIJKLMNOPQRSTUVWXYZ
---   0123456789
---   /-?:().,' +
---   Space
---   ```
---   Other characters may be accepted, rejected, stripped or replaced.
---@class YAXI.Ticket.Payload.CollectPayment
---@field amount YAXI.Ticket.Payload.CollectPayment.Amount
---@field creditorAccount YAXI.Ticket.Payload.CollectPayment.CreditorAccount
---@field creditorName string Mind the character set restrictions.
---@field remittance string Mind the character set restrictions.
---@field instant boolean? Whether to force instant or non-instant payments. If set to true, an instant payment will be requested. If set to false, a non-instant payment will be requested. If not provided, an instant payment will be requested if supported, with a fallback to a non-instant payment.
---@field fields YAXI.Ticket.Payload.CollectPayment.Field[]? Request additional fields to include in a result.

---@class YAXI.Ticket.Payload.CollectPayment.Amount
---@field amount number|string Numeric amount. Both a floating point value or a string, containing a floating point value are supported. Keep in mind floating point precession errors.
---@field currency string ISO 4217 Alpha 3 currency code.

---@class YAXI.Ticket.Payload.CollectPayment.CreditorAccount
---@field iban string IBAN.

---@alias YAXI.Ticket.Payload.CollectPayment.Field
---| "debtorIban"
---| "debtorName"

---Issue a ticket for the collect payment service
---@param ticketId string A UUIDv4 in its string representation; generates an ID if not given
---@param data YAXI.Ticket.Payload.CollectPayment
---@param exp integer? Expiration date as a POSIX timestamp; defaults to now + 5min
---@return string @YAXI ticket JWT
function Generator:collectPayment(ticketId, data, exp)
  return self:issue(ticketId, "CollectPayment", data, exp)
end

--#endregion Issue CollectPayment ticket

---Issue a YAXI service ticket
---@param apiKeyId string YAXI key ID
---@param apiKeySecret binary Raw API key secret
---@param ticketId string A UUIDv4 in its string representation
---@param service "Accounts"|"CollectPayment"|"Balances"|"Transactions"|string YAXI service for which you want to issue the ticket
---@param data table? Additional data specific to the `service`
---@param exp integer? Expiration date as a POSIX timestamp; defaults to now + 5min
---@return string @YAXI ticket JWT
local function issue(apiKeyId, apiKeySecret, ticketId, service, data, exp)
  return Generator:new(apiKeyId, apiKeySecret):issue(ticketId, service, data, exp)
end

---Get the ID property of a ticket.
---**WARNING:** This function does not verify the ticket.
---@param ticket string A YAXI service ticket
local function getId(ticket)
  local claims = jwt.decode(ticket, nil, nil, {
    verifySignature = false,
    verifyExp = false,
  })

  local ticketId = claims and claims.data and claims.data.id or error("The ticket doesn't have a `data.id` claim")

  return ticketId
end

return {
  Generator = Generator,
  issue = issue,
  getId = getId,
}
