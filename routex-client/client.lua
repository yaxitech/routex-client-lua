-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

-- Client for the interactive YAXI Open Banking services. Service calls return
-- an [`OBResponse`](lua://YAXI.RoutexClient.OBResponse) (see
-- `routex-client.response`): either a [`Result`](lua://YAXI.RoutexClient.Result)
-- or an [interrupt](https://docs.yaxi.tech/interrupts.html) that requires user
-- action before the flow can continue.

local core = require("routex-client.core")
local dateutil = require("routex-client.util.date")
local responses = require("routex-client.response")
local util = require("routex-client.util")
local super = util.super
local class = util.class

local Core = core.Core
local NULL_MARKER = core.NULL_MARKER

-- Response types
local OBResponse = responses.OBResponse
local Confirmation = responses.Confirmation
local Dialog = responses.Dialog
local DialogContext = responses.DialogContext
local Field = responses.Field
local InputType = responses.InputType
local Redirect = responses.Redirect
local RedirectHandle = responses.RedirectHandle
local Result = responses.Result
local SecrecyLevel = responses.SecrecyLevel
local Selection = responses.Selection

-- Shared enums
local AccountField = core.AccountField
local AccountStatus = core.AccountStatus
local AccountType = core.AccountType
local ConnectionDetails = core.ConnectionDetails
local ConnectionType = core.ConnectionType
local SupportedService = core.SupportedService

local errors = require("routex-client.errors")
-- Error classes
local Error = errors.Error
local AccessExceededError = errors.AccessExceededError
local CanceledError = errors.CanceledError
local InterruptError = errors.InterruptError
local InvalidCredentialsError = errors.InvalidCredentialsError
local InvalidRedirectUriError = errors.InvalidRedirectUriError
local NotFoundError = errors.NotFoundError
local PaymentFailedError = errors.PaymentFailedError
local PeriodOutOfBoundsError = errors.PeriodOutOfBoundsError
local ProviderError = errors.ProviderError
local RequestError = errors.RequestError
local ResponseError = errors.ResponseError
local ServiceBlockedError = errors.ServiceBlockedError
local TicketError = errors.TicketError
local UnauthorizedError = errors.UnauthorizedError
local UnexpectedError = errors.UnexpectedError
local UnexpectedValueError = errors.UnexpectedValueError
local UnsupportedProductError = errors.UnsupportedProductError
-- Error codes
local PaymentFailedCode = errors.PaymentFailedCode
local ProviderErrorCode = errors.ProviderErrorCode
local ServiceBlockedCode = errors.ServiceBlockedCode
local TicketErrorCode = errors.TicketErrorCode
local UnsupportedProductReason = errors.UnsupportedProductReason

local KeySettlement = require("routex-client.settlement")

local base64Encode = require("routex-client.util.base64").encode

local _VERSION = core._VERSION

---@class YAXI.RoutexClient.Credentials
---@field connectionId string
---@field userId string?
---@field password string?
---@field connectionData binary?

---@class YAXI.RoutexClient.ServiceOptions
---@field credentials YAXI.RoutexClient.Credentials
---@field ticket string
---@field recurringConsents boolean? Defaults to false
---@field session binary?

---@class YAXI.RoutexClient.AccountsOptions: YAXI.RoutexClient.ServiceOptions
---@field fields YAXI.RoutexClient.AccountField[]?
---@field filter YAXI.RoutexClient.AccountFilter?

---@class YAXI.RoutexClient.AccountReference
---@field iban string? ISO 20022 IBAN2007Identifier.
---@field number string? Account number that is not an IBAN, e.g. ISO 20022 BBANIdentifier.
---@field currency string?

---@class YAXI.RoutexClient.BalancesOptions: YAXI.RoutexClient.ServiceOptions
---@field accounts YAXI.RoutexClient.AccountReference[]

---@alias YAXI.RoutexClient.TransactionsOptions YAXI.RoutexClient.ServiceOptions

---@class YAXI.RoutexClient.DebtorAccountReferenceEncrypted
---@field encryptedIban string
---@field currency string?

---@class YAXI.RoutexClient.DebtorAccountReferencePlain
---@field iban string
---@field currency string?

---@alias YAXI.RoutexClient.DebtorAccountReference YAXI.RoutexClient.DebtorAccountReferencePlain | YAXI.RoutexClient.DebtorAccountReferenceEncrypted

---@class YAXI.RoutexClient.CollectPaymentOptions: YAXI.RoutexClient.ServiceOptions
---@field account YAXI.RoutexClient.DebtorAccountReference

---@enum YAXI.RoutexClient.PaymentProduct
local PaymentProduct = {
  ---SEPA Credit Transfer (SCT) in EUR
  SepaCreditTransfer = "SepaCreditTransfer",
  ---SEPA Instant Credit Transfer (SCT Inst) in EUR
  SepaInstantCreditTransfer = "SepaInstantCreditTransfer",
  ---Default SEPA Credit Transfer in EUR
  ---
  ---Tries SCT Inst with a fallback to SCT if this is supported.
  ---Otherwise, SCT is used.
  DefaultSepaCreditTransfer = "DefaultSepaCreditTransfer",
  ---International credit transfer outside of SEPA (typically SWIFT)
  CrossBorderCreditTransfer = "CrossBorderCreditTransfer",
  ---Domestic credit transfer in the domestic, non-EUR currency
  DomesticCreditTransfer = "DomesticCreditTransfer",
  ---Instant domestic credit transfer in the domestic, non-EUR currency
  DomesticInstantCreditTransfer = "DomesticInstantCreditTransfer",
}

---@enum YAXI.RoutexClient.ChargeBearer
local ChargeBearer = {
  BorneByDebtor = "DEBT",
  BorneByCreditor = "CRED",
  Shared = "SHAR",
  FollowingServiceLevel = "SLEV",
}

---@class YAXI.RoutexClient.TransferOptions.Details.Amount
---@field amount string|number Decimal amount, e.g. "123.45".
---@field currency string ISO 4217 Alpha 3 currency code.

---@class YAXI.RoutexClient.TransferOptions.Details.CreditorAccount
---@field iban string

---@class YAXI.RoutexClient.TransferOptions.Details.CreditorAddress
---@field townName string
---@field country string ISO 3166-1 alpha-2 country code.

---@class YAXI.RoutexClient.TransferOptions.Details
---@field endToEndIdentification string?
---@field amount YAXI.RoutexClient.TransferOptions.Details.Amount
---@field creditorAccount YAXI.RoutexClient.TransferOptions.Details.CreditorAccount
---@field creditorAgentBic string?
---@field creditorName string
---@field creditorAddress YAXI.RoutexClient.TransferOptions.Details.CreditorAddress?
---@field remittance string?
---@field chargeBearer YAXI.RoutexClient.ChargeBearer?

---@class YAXI.RoutexClient.TransferOptions: YAXI.RoutexClient.ServiceOptions
---@field product YAXI.RoutexClient.PaymentProduct
---@field debtorAccount YAXI.RoutexClient.DebtorAccountReferencePlain?
---@field debtorName string?
---@field requestedExecutionDate osdate? %Y-%m-%dT%H:%M:%S%.f
---@field details YAXI.RoutexClient.TransferOptions.Details[]

---@class YAXI.RoutexClient.RegisterRedirectOptions
---@field ticket string
---@field handle string
---@field redirectUri string

---@class YAXI.RoutexClient.ResponseOptions
---@field ticket string
---@field context binary
---@field response string

---@class YAXI.RoutexClient.ConfirmationOptions
---@field ticket string
---@field context binary

--#region RoutexClient

---@class YAXI.RoutexClient.RoutexClient: YAXI.RoutexClient.Core
local RoutexClient = class(Core)

---Create a new instance.
---@param url string? A URL to a YAXI routex environment; default to `https://api.yaxi.tech`
---@param httpClient YAXI.Http.IClient? If `nil`, uses a default client based on `lua-http`
---@return YAXI.RoutexClient.RoutexClient
function RoutexClient:new(url, httpClient)
  local obj = super(self).new(self, url, httpClient) --[[@as YAXI.RoutexClient.RoutexClient]]
  return obj
end

---@private
---@param servicePath string
---@param options YAXI.RoutexClient.ResponseOptions
---@return YAXI.RoutexClient.OBResponse
function RoutexClient:_respond(servicePath, options)
  local json = self:_request(options.ticket, string.format("%s/response", servicePath), {
    context = base64Encode(options.context),
    response = options.response,
  })
  return RoutexClient._readOBResponse(json)
end

---@private
---@param servicePath string
---@param options YAXI.RoutexClient.ConfirmationOptions
---@return YAXI.RoutexClient.OBResponse
function RoutexClient:_confirm(servicePath, options)
  local json = self:_request(options.ticket, string.format("%s/confirmation", servicePath), {
    context = base64Encode(options.context),
  })
  return RoutexClient._readOBResponse(json)
end

---@private
---@param response YAXI.Http.Response
---@return YAXI.RoutexClient.OBResponse
function RoutexClient._readOBResponse(response)
  local json = RoutexClient._handleResponse(response)

  local ok, resOrErr = pcall(OBResponse.fromJSON, json --[[@as YAXI.RoutexClient.OBResponseJSON]])
  if ok then
    local res = resOrErr --[[@as YAXI.RoutexClient.OBResponse]]
    return res
  else
    local err = resOrErr --[[@as string]]
    error(ResponseError:new(err, response))
  end
end

--#region RoutexClient:accounts()

---[Accounts service](https://docs.yaxi.tech/accounts.html)
---@param options YAXI.RoutexClient.AccountsOptions
---@return YAXI.RoutexClient.OBResponse
function RoutexClient:accounts(options)
  ---@type string[]
  local fields = {}
  for _, field in ipairs(options.fields or {}) do
    table.insert(fields, field)
  end

  local data = self._prepareData(options.credentials, options.session, options.recurringConsents, {
    fields = fields,
    filter = options.filter and self:_mapFilter(options.filter) or nil,
  })

  local response = self:_request(options.ticket, "accounts/service", data)

  return RoutexClient._readOBResponse(response)
end

---Respond to a [`Dialog`](lua://YAXI.RoutexClient.Dialog) returned while fetching accounts
---@param options YAXI.RoutexClient.ResponseOptions
---@return YAXI.RoutexClient.OBResponse
function RoutexClient:respondAccounts(options)
  return self:_respond("accounts", options)
end

---Confirm a [`Dialog`](lua://YAXI.RoutexClient.Dialog) or [Redirect](lua://YAXI.RoutexClient.Redirect) returned while fetching accounts
---@param options YAXI.RoutexClient.ConfirmationOptions
---@return YAXI.RoutexClient.OBResponse
function RoutexClient:confirmAccounts(options)
  return self:_confirm("accounts", options)
end

--#endregion RoutexClient:accounts()

--#region RoutexClient:balances()

---[Balances service](https://docs.yaxi.tech/balances.html)
---@param options YAXI.RoutexClient.BalancesOptions
---@return YAXI.RoutexClient.OBResponse
function RoutexClient:balances(options)
  local data = self._prepareData(options.credentials, options.session, options.recurringConsents, {
    accounts = options.accounts,
  })
  local response = self:_request(options.ticket, "balances/service", data)
  return RoutexClient._readOBResponse(response)
end

---Respond to a [`Dialog`](lua://YAXI.RoutexClient.Dialog) returned while fetching balances
---@param options YAXI.RoutexClient.ResponseOptions
---@return YAXI.RoutexClient.OBResponse
function RoutexClient:respondBalances(options)
  return self:_respond("balances", options)
end

---Confirm a [`Dialog`](lua://YAXI.RoutexClient.Dialog) or [Redirect](lua://YAXI.RoutexClient.Redirect) returned while fetching balances
---@param options YAXI.RoutexClient.ConfirmationOptions
---@return YAXI.RoutexClient.OBResponse
function RoutexClient:confirmBalances(options)
  return self:_confirm("balances", options)
end

--#endregion RoutexClient:balances()

--#region RoutexClient:transactions()

---[Transactions service](https://docs.yaxi.tech/transactions.html)
---@param options YAXI.RoutexClient.TransactionsOptions
---@return YAXI.RoutexClient.OBResponse
function RoutexClient:transactions(options)
  local data = self._prepareData(options.credentials, options.session, options.recurringConsents, {})
  local response = self:_request(options.ticket, "transactions/service", data)
  return RoutexClient._readOBResponse(response)
end

---Respond to a [`Dialog`](lua://YAXI.RoutexClient.Dialog) returned while fetching transactions
---@param options YAXI.RoutexClient.ResponseOptions
---@return YAXI.RoutexClient.OBResponse
function RoutexClient:respondTransactions(options)
  return self:_respond("transactions", options)
end

---Confirm a [`Dialog`](lua://YAXI.RoutexClient.Dialog) or [Redirect](lua://YAXI.RoutexClient.Redirect) returned while fetching transactions
---@param options YAXI.RoutexClient.ConfirmationOptions
---@return YAXI.RoutexClient.OBResponse
function RoutexClient:confirmTransactions(options)
  return self:_confirm("transactions", options)
end

--#endregion RoutexClient:transactions()

--#region RoutexClient:collectPayment()

---[Collect Payment service](https://docs.yaxi.tech/collect-payment.html)
---@param options YAXI.RoutexClient.CollectPaymentOptions
---@return YAXI.RoutexClient.OBResponse
function RoutexClient:collectPayment(options)
  local data =
    self._prepareData(options.credentials, options.session, options.recurringConsents, { account = options.account })
  local response = self:_request(options.ticket, "collect-payment/service", data)
  return RoutexClient._readOBResponse(response)
end

---Respond to a [`Dialog`](lua://YAXI.RoutexClient.Dialog) returned while initiating the payment
---@param options YAXI.RoutexClient.ResponseOptions
---@return YAXI.RoutexClient.OBResponse
function RoutexClient:respondCollectPayment(options)
  return self:_respond("collect-payment", options)
end

---Confirm a [`Dialog`](lua://YAXI.RoutexClient.Dialog) or [Redirect](lua://YAXI.RoutexClient.Redirect) returned initiating the payment
---@param options YAXI.RoutexClient.ConfirmationOptions
---@return YAXI.RoutexClient.OBResponse
function RoutexClient:confirmCollectPayment(options)
  return self:_confirm("collect-payment", options)
end

--#endregion RoutexClient:collectPayment()

--#region RoutexClient:transfer()

---[Transfer service](https://docs.yaxi.tech/transfer.html)
---@param options YAXI.RoutexClient.TransferOptions
---@return YAXI.RoutexClient.OBResponse
function RoutexClient:transfer(options)
  ---@type string?
  local requestedExecutionDate = nil
  if options.requestedExecutionDate then
    local success, result = pcall(dateutil.formatDate, options.requestedExecutionDate)
    if not success then
      error(UnexpectedValueError:new(string.format("Passed `requestedExecutionDate` is invalid: %s", result)))
    end
    requestedExecutionDate = result
  end

  local data = self._prepareData(options.credentials, options.session, options.recurringConsents, {
    product = options.product,
    debtorAccount = options.debtorAccount,
    debtorName = options.debtorName,
    requestedExecutionDate = requestedExecutionDate,
    details = options.details,
  })
  local response = self:_request(options.ticket, "transfer/service", data)
  return RoutexClient._readOBResponse(response)
end

---Respond to a [`Dialog`](lua://YAXI.RoutexClient.Dialog) returned while initiating the transfer
---@param options YAXI.RoutexClient.ResponseOptions
---@return YAXI.RoutexClient.OBResponse
function RoutexClient:respondTransfer(options)
  return self:_respond("transfer", options)
end

---Confirm a [`Dialog`](lua://YAXI.RoutexClient.Dialog) or [Redirect](lua://YAXI.RoutexClient.Redirect) returned initiating the transfer
---@param options YAXI.RoutexClient.ConfirmationOptions
---@return YAXI.RoutexClient.OBResponse
function RoutexClient:confirmTransfer(options)
  return self:_confirm("transfer", options)
end

--#endregion RoutexClient:transfer()

--#region RoutexClient:registerRedirectUri()

---
--- Register a redirect URI for a given redirect handle.
---
--- Returns the URL that the user is meant to get sent to.
---
---@param options YAXI.RoutexClient.RegisterRedirectOptions
---@return string
function RoutexClient:registerRedirectUri(options)
  local response = self:_request(options.ticket, "redirects", {
    handle = options.handle,
    redirectUri = options.redirectUri,
  })

  local json = RoutexClient._handleResponse(response)
  if not json.redirectUrl then
    local err = ResponseError:new("Expected `redirectUri` in response", response)
    error(err)
  end

  return json.redirectUrl
end

--#endregion RoutexClient:registerRedirectUri()

--#region Private helpers

---@class YAXI.RoutexClient.PreparedData
---@field credentials YAXI.RoutexClient.Credentials
---@field session binary?
---@field recurringConsents boolean

---@private
---@param credentials YAXI.RoutexClient.Credentials
---@param session binary?
---@param recurringConsents boolean?
---@param data table<string, any>?
---@return YAXI.RoutexClient.PreparedData
function RoutexClient._prepareData(credentials, session, recurringConsents, data)
  ---@type YAXI.RoutexClient.PreparedData
  local res = {
    credentials = {
      connectionId = credentials.connectionId,
      connectionData = credentials.connectionData and base64Encode(credentials.connectionData) or NULL_MARKER,
      userId = credentials.userId,
      password = credentials.password,
    },
    session = session and base64Encode(session) or NULL_MARKER,
    recurringConsents = recurringConsents or false,
  }

  if data then
    for k, v in pairs(data) do
      res[k] = v
    end
  end

  return res
end

--#endregion Private helpers

--#endregion RoutexClient

return {
  _VERSION = _VERSION,

  -- Classes
  OBResponse = OBResponse,
  Confirmation = Confirmation,
  Dialog = Dialog,
  Field = Field,
  Redirect = Redirect,
  RedirectHandle = RedirectHandle,
  Result = Result,
  RoutexClient = RoutexClient,
  Selection = Selection,

  -- Enums
  AccountField = AccountField,
  AccountStatus = AccountStatus,
  AccountType = AccountType,
  ChargeBearer = ChargeBearer,
  ConnectionDetails = ConnectionDetails,
  ConnectionType = ConnectionType,
  DialogContext = DialogContext,
  InputType = InputType,
  PaymentProduct = PaymentProduct,
  SecrecyLevel = SecrecyLevel,
  SupportedService = SupportedService,

  -- Error Codes
  PaymentFailedCode = PaymentFailedCode,
  ProviderErrorCode = ProviderErrorCode,
  ServiceBlockedCode = ServiceBlockedCode,
  TicketErrorCode = TicketErrorCode,
  UnsupportedProductReason = UnsupportedProductReason,

  -- Errors
  Error = Error,
  AccessExceededError = AccessExceededError,
  CanceledError = CanceledError,
  InterruptError = InterruptError,
  InvalidCredentialsError = InvalidCredentialsError,
  InvalidRedirectUriError = InvalidRedirectUriError,
  NotFoundError = NotFoundError,
  PaymentFailedError = PaymentFailedError,
  PeriodOutOfBoundsError = PeriodOutOfBoundsError,
  ProviderError = ProviderError,
  RequestError = RequestError,
  ResponseError = ResponseError,
  ServiceBlockedError = ServiceBlockedError,
  TicketError = TicketError,
  UnauthorizedError = UnauthorizedError,
  UnexpectedError = UnexpectedError,
  UnexpectedValueError = UnexpectedValueError,
  UnsupportedProductError = UnsupportedProductError,

  -- Key settlement client
  KeySettlement = KeySettlement,
}
