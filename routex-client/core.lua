-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

-- Shared client core, mirroring the Rust `routex_client_common::RoutexClientCore`.
--
-- It owns the transport concerns (request building, key settlement, sealing,
-- error decoding) and the endpoints common to all clients (`search`, `info`,
-- `systemVersion`, `trace`). The interactive `RoutexClient` (`routex-client`)
-- and the non-interactive `RoutexRefreshClient` (`routex-client.refresh`)
-- derive from the `Core` class defined here.

-- Logging setup
local log = require("routex-client.logging").defaultLogger()
  or error("Failed to get default logger. Did you initialize it?")

local KeySettlement = require("routex-client.settlement")
local base64 = require("routex-client.util.base64")
local errors = require("routex-client.errors")
local http = require("routex-client.http")
local jwt = require("routex-client.jwt")
local util = require("routex-client.util")
local uuid = require("routex-client.util.uuid")

local jsonDecode = require("routex-client.vendor.json").decode
local jsonEncode = require("routex-client.vendor.json").encode

local class = util.class

-- Error classes
local AccessExceededError = errors.AccessExceededError
local CanceledError = errors.CanceledError
local InterruptError = errors.InterruptError
local InvalidCredentialsError = errors.InvalidCredentialsError
local NotFoundError = errors.NotFoundError
local PaymentFailedError = errors.PaymentFailedError
local PeriodOutOfBoundsError = errors.PeriodOutOfBoundsError
local ProviderError = errors.ProviderError
local ResponseError = errors.ResponseError
local ServiceBlockedError = errors.ServiceBlockedError
local TicketError = errors.TicketError
local UnauthorizedError = errors.UnauthorizedError
local UnexpectedError = errors.UnexpectedError
local UnexpectedValueError = errors.UnexpectedValueError
local UnsupportedProductError = errors.UnsupportedProductError

local _VERSION = "0.3.0"
local USER_AGENT = ("RoutexClient/%s (Lua)"):format(_VERSION)

-- routex expects `null` instead of omitting entries entirely
---@alias YAXI.RoutexClient.NULL_MARKER "____NULL_MARKER____"

---@type YAXI.RoutexClient.NULL_MARKER
local NULL_MARKER = "____NULL_MARKER____"

--#region Shared enums

---@enum YAXI.RoutexClient.AccountField
local AccountField = {
  Iban = "Iban",
  Number = "Number",
  Bic = "Bic",
  BankCode = "BankCode",
  Currency = "Currency",
  Name = "Name",
  DisplayName = "DisplayName",
  OwnerName = "OwnerName",
  ProductName = "ProductName",
  Status = "Status",
  Type = "Type",
}

---@enum YAXI.RoutexClient.SupportedService
local SupportedService = {
  CollectPayment = "CollectPayment",
}

---@enum YAXI.RoutexClient.AccountType
local AccountType = {
  --- Account used to post debits and credits.
  --- ISO 20022 ExternalCashAccountType1Code CACC.
  Current = "Current",
  --- Account used for credit card payments.
  --- ISO 20022 ExternalCashAccountType1Code CARD.
  Card = "Card",
  --- Account used for savings.
  --- ISO 20022 ExternalCashAccountType1Code SVGS.
  Savings = "Savings",
  --- Account used for call money.
  --- No dedicated ISO 20022 code (falls into SVGS).
  CallMoney = "CallMoney",
  --- Account used for time deposits.
  --- No dedicated ISO 20022 code (falls into SVGS).
  TimeDeposit = "TimeDeposit",
  --- Account used for loans.
  --- ISO 20022 ExternalCashAccountType1Code LOAN.
  Loan = "Loan",
  Securities = "Securities",
  Insurance = "Insurance",
  Commerce = "Commerce",
  Rewards = "Rewards",
}

---@enum YAXI.RoutexClient.AccountStatus
local AccountStatus = {
  Available = "Available",
  Terminated = "Terminated",
  Blocked = "Blocked",
}

---Type of connections to consider when searching.
---@enum YAXI.RoutexClient.ConnectionType
local ConnectionType = {
  --- Production connections.
  Production = "Production",
  --- Sandbox connections, especially test systems provided by third-parties.
  Sandboxes = "Sandboxes",
}

---Additional data to include in search results.
---@enum YAXI.RoutexClient.ConnectionDetails
local ConnectionDetails = {
  --- Include BICs for each returned result.
  Bics = "bics",
  --- Include national bank codes for each returned result.
  BankCodes = "bankCodes",
}

--#endregion Shared enums

--#region YAXI.RoutexClient.AccountFilter

---@class YAXI.RoutexClient.AccountFilter.Eq
---@field eq [YAXI.RoutexClient.AccountField, string?]

---@class YAXI.RoutexClient.AccountFilter.NotEq
---@field notEq [YAXI.RoutexClient.AccountField, string?]

---@class YAXI.RoutexClient.AccountFilter.All
---@field all YAXI.RoutexClient.AccountFilter[]

---@class YAXI.RoutexClient.AccountFilter.Any
---@field any YAXI.RoutexClient.AccountFilter[]

---@class YAXI.RoutexClient.AccountFilter.Supports
---@field supports YAXI.RoutexClient.SupportedService

---@alias YAXI.RoutexClient.AccountFilter
---| YAXI.RoutexClient.AccountFilter.Eq
---| YAXI.RoutexClient.AccountFilter.NotEq
---| YAXI.RoutexClient.AccountFilter.All
---| YAXI.RoutexClient.AccountFilter.Any
---| YAXI.RoutexClient.AccountFilter.Supports

--#endregion YAXI.RoutexClient.AccountFilter

--#region YAXI.RoutexClient.AccountFilterJSON

---@class YAXI.RoutexClient.AccountFilterJSON.CompOps.Eq
---@field Eq [YAXI.RoutexClient.AccountField, string?]

---@class YAXI.RoutexClient.AccountFilterJSON.CompOps.NotEq
---@field NotEq [YAXI.RoutexClient.AccountField, string?]

---@class YAXI.RoutexClient.AccountFilterJSON.CompOps.Supports
---@field Eq YAXI.RoutexClient.SupportedService

---@alias YAXI.RoutexClient.AccountFilterJSON.CompOps
---| YAXI.RoutexClient.AccountFilterJSON.CompOps.Eq
---| YAXI.RoutexClient.AccountFilterJSON.CompOps.NotEq
---| YAXI.RoutexClient.AccountFilterJSON.CompOps.Supports

---@class YAXI.RoutexClient.AccountFilterJSON.LogicOps.And
---@field And [YAXI.RoutexClient.AccountFilterJSON, YAXI.RoutexClient.AccountFilterJSON]

---@class YAXI.RoutexClient.AccountFilterJSON.LogicOps.Or
---@field Or [YAXI.RoutexClient.AccountFilterJSON, YAXI.RoutexClient.AccountFilterJSON]

---@alias YAXI.RoutexClient.AccountFilterJSON.LogicOps
---| YAXI.RoutexClient.AccountFilterJSON.LogicOps.And
---| YAXI.RoutexClient.AccountFilterJSON.LogicOps.Or

---@alias YAXI.RoutexClient.AccountFilterJSON
---| YAXI.RoutexClient.AccountFilterJSON.CompOps
---| YAXI.RoutexClient.AccountFilterJSON.LogicOps

--#endregion YAXI.RoutexClient.AccountFilterJSON

--#region Search / Info types

---
--- Requirements for user identifier and password.
---
---@class YAXI.RoutexClient.ConnectionInfo.CredentialsModel
---@field full boolean A full set of credentials may be provided to support fully embedded authentication (including scraped redirects).
---@field userId boolean Only a user identifier without a password may be provided. This is typically the case for decoupled authentication where the user e.g. authorizes access in a mobile application. Note that if password-less authentication fails (e.g. as no device for decoupled authentication is set up for the user and a redirect is not supported), an error is returned and the transaction has to get restarted with a full set of credentials.
---@field none boolean Credentials are not required. The user will provide them to the service provider during a redirect.

---
--- Connection meta data
---
---@class YAXI.RoutexClient.ConnectionInfo
---@field id string Unique identifier.
---@field countries string[] ISO 3166-1 ALPHA-2 country codes.
---@field displayName string Display name.
---@field credentials YAXI.RoutexClient.ConnectionInfo.CredentialsModel Credentials model.
---@field userId? string Human-friendly label for the user identifier if relevant.
---@field password? string Human-friendly label for the PIN / password if relevant.
---@field advice? string Advice for the credentials to be displayed.
---@field logoId string Logo identifier.
---@field bics? string[] ISO 20022 BICFIIdentifiers. Note that this is only included in search results if requested.
---@field bankCodes? string[] National bank codes (as used in IBANs). Note that this is only included in search results if requested.

---
--- Filters for the connection lookup
---
--- String filters look for the given value anywhere in the related field, case-insensitive.
---
---@alias YAXI.RoutexClient.SearchFilter
---| { types: YAXI.RoutexClient.ConnectionType[] } List of connection types to consider.
---| { countries: string[] } List of ISO 3166-1 alpha-2 country codes to consider.
---| { name: string } String filter for the provider / product name or any alias.
---| { bic: string } String filter for the BIC.
---| { bankCode: string } String filter for the (national) bank code.
---| { term: string} String filter for any of those fields.

---@class YAXI.RoutexClient.SearchOptions
---@field ticket string?
---@field filters YAXI.RoutexClient.SearchFilter[]?
---@field ibanDetection boolean?
---@field limit integer?
---@field details YAXI.RoutexClient.ConnectionDetails[]?

---@class YAXI.RoutexClient.InfoOptions
---@field ticket string
---@field connectionId string

--#endregion Search / Info types

---Get the ID property of a ticket.
---**WARNING:** This function does not verify the ticket.
---@param ticket string A YAXI service ticket
---@return string
local function getTicketID(ticket)
  local claims = jwt.decode(ticket, nil, nil, {
    verifySignature = false,
    verifyExp = false,
  })

  local ticketId = claims and claims.data and claims.data.id
    or error(UnexpectedError:new("The ticket doesn't have a `data.id` claim"))

  return ticketId --[[@as string]]
end

--#region Core

---Internal base class shared by `RoutexClient` and `RoutexRefreshClient`.
---@class YAXI.RoutexClient.Core: YAXI.ClassBase
---@field MEDIA_TYPE string
---@field private __index table
---@field private _httpClient YAXI.Http.IClient
---@field private _url string
---@field private _settlement YAXI.KeySettlement
---@field private _traceId binary
---@field private _redirectUri string?
local Core = class({
  MEDIA_TYPE = "application/vnd.yaxi.v5",
})

---Create a new instance.
---@protected
---@param url string? A URL to a YAXI routex environment; default to `https://api.yaxi.tech`
---@param httpClient YAXI.Http.IClient? If `nil`, uses a default client based on `lua-http`
---@return YAXI.RoutexClient.Core
function Core:new(url, httpClient)
  local obj = setmetatable({}, self)
  obj._url = url and url:gsub("([/]*)$", "") or "https://api.yaxi.tech" -- remove trailing slashes
  obj._httpClient = httpClient or http.DefaultHttpClient:new()
  obj._settlement = KeySettlement:new(obj._url .. "/key-settlement", nil, obj._httpClient)
  return obj
end

---Send a raw request to routex.
---Allows to pass mapping functions for the pre-request and the post-response payloads.
---
---This function is side-effect free.
---@param request YAXI.Http.Request
---@return YAXI.Http.Response
---@return string? @Trace ID
function Core:sealedRequest(request)
  -- Prepare headers for settlement request
  local settlementHeaders = {}
  for _, name in pairs({ "accept", "yaxi-ticket-id", "user-agent" }) do
    settlementHeaders[name] = request.headers[name]
  end

  -- Retrieve the settlement session ID, establishing a new session if necessary
  local ok, response = pcall(self._settlement.getBase64SessionId, self._settlement, settlementHeaders)
  if ok then
    request.headers["yaxi-session-id"] = response --[[@as string]]
  else
    local err = type(response) == "table" and response
      or UnexpectedError:new(string.format("Key settlement failed: %s", response))
    error(err)
  end

  -- If the `yaxi-ticket-id` header is set, encrypt the `yaxi-ticket` header value
  if request.headers["yaxi-ticket-id"] and request.headers["yaxi-ticket"] then ---@diagnostic disable-line: unnecessary-if
    local ticket = request.headers["yaxi-ticket"] --[[@as string]]
    local ticketSealed = self._settlement:seal(ticket, settlementHeaders)
    local ticketSealedB64 = base64.encode(ticketSealed)
      or error(UnexpectedError:new("Failed to Base64-encode sealed ticket"))
    request.headers["yaxi-ticket"] = ticketSealedB64
  end

  -- Seal the data, if any
  if request.data then
    log:debug("Final pre-sealed request: \n%s", request)
    request.data = self._settlement:seal(request.data, settlementHeaders)
  end

  ---@diagnostic disable-next-line: redefined-local
  local response = self._httpClient:request(request) or error(UnexpectedError:new("Sending request failed"))

  -- Unseal response body
  local responseUnsealed
  if response.status >= 400 then
    responseUnsealed = self:_unsealBody(response, true)
    Core._handleResponse(responseUnsealed)
    log:error("Unhandled error response, raising UnexpectedError")
    error(UnexpectedError:new(responseUnsealed.body))
  else
    responseUnsealed = self:_unsealBody(response, false)
  end
  log:debug("Response: %s", responseUnsealed)

  -- Unseal trace ID, if any
  local traceId
  if response.headers["yaxi-trace-id"] then
    local traceIdSealedB64 = response.headers["yaxi-trace-id"]
    local traceIdSealed = base64.decode(traceIdSealedB64) or error("Could not Base64-decode the sealed trace ID header")
    traceId = self._settlement:unseal(traceIdSealed)
  end

  return responseUnsealed, traceId
end

---@protected
---@param ticket string? YAXI service ticket
---@param path string HTTP URL path
---@param data table<string, any>|string|nil Data to encode and send as JSON body
---@return YAXI.Http.RequestBuilder
function Core:_buildRequest(ticket, path, data)
  local reqBuilder = http.Request
    :builder(("%s/%s"):format(self._url, path))
    :method(data and "POST" or "GET")
    :header("accept", self.MEDIA_TYPE)
    :header("user-agent", USER_AGENT)
    :header("yaxi-redirect-uri", self._redirectUri)
    :header("yaxi-ticket-id", ticket and getTicketID(ticket))
    :header("yaxi-ticket", ticket)

  if data ~= nil then
    if type(data) == "table" then
      reqBuilder:json(data, NULL_MARKER)
    else
      reqBuilder:data(data)
    end
  end

  return reqBuilder
end

---@protected
---@param request YAXI.Http.Request request to send
---@return YAXI.Http.Response
function Core:_sendRequest(request)
  local response, traceId = self:sealedRequest(request)

  if traceId then
    self._traceId = traceId
    local traceIdB64 = traceId and base64.encode(self._traceId)
      or error(UnexpectedError:new("Could not Base64-encode trace ID"))
    log:debug("yaxi-trace-id: %s", traceIdB64)
  end

  return response
end

---@protected
---@param ticket string YAXI service ticket
---@param path string HTTP URL path
---@param data table<string, any>|string|nil Data to encode and send as JSON body
---@return YAXI.Http.Response
function Core:_request(ticket, path, data)
  local request = self:_buildRequest(ticket, path, data):build()
  return self:_sendRequest(request)
end

---Unseal the body of the response
---@private
---@param response YAXI.Http.Response
---@param fallback boolean
---@return YAXI.Http.Response
function Core:_unsealBody(response, fallback)
  if #response.body == 0 then
    -- No body, nothing to unseal
    return response
  end

  local ok, unsealed = pcall(function()
    return self._settlement:unseal(response.body)
  end)

  if not ok and not fallback then
    error(UnexpectedError:new(("Failed to unseal response body: %s"):format(unsealed)))
  end

  response.body = unsealed or response.body
  return response
end

---Decode the response and raises an [`Error`](lua://RoutexClient.Error) if necessary
---@protected
---@param response YAXI.Http.Response
---@return table<string, any>
function Core._handleResponse(response)
  local ok, data = pcall(jsonDecode, response.body)

  ---@type YAXI.RoutexClient.Error?
  local err = nil

  ---@diagnostic disable: need-check-nil, undefined-field, unnecessary-if
  if not ok then
    -- JSON decoding failed
    data = data --[[@as string]]
    err = ResponseError:new(data, response)
  elseif response.status >= 400 then
    data = data --[[@as table<string, any>]]
    if data.UnexpectedError then
      err = UnexpectedError:new(data.UnexpectedError.userMessage)
    elseif data.Canceled then
      err = CanceledError:new()
    elseif data.InvalidCredentials then
      err = InvalidCredentialsError:new(data.InvalidCredentials.userMessage)
    elseif data.ServiceBlocked then
      err = ServiceBlockedError:new(data.ServiceBlocked.code, data.ServiceBlocked.userMessage)
    elseif data.Unauthorized then
      err = UnauthorizedError:new(data.Unauthorized.userMessage)
    elseif data.AccessExceeded then
      err = AccessExceededError:new(data.AccessExceeded.userMessage)
    elseif data.PeriodOutOfBounds then
      err = PeriodOutOfBoundsError:new(data.PeriodOutOfBounds.userMessage)
    elseif data.UnsupportedProduct then
      err = UnsupportedProductError:new(data.UnsupportedProduct.reason, data.UnsupportedProduct.userMessage)
    elseif data.PaymentFailed then
      err = PaymentFailedError:new(data.PaymentFailed.code, data.PaymentFailed.userMessage)
    elseif data.UnexpectedValue then
      err = UnexpectedValueError:new(data.UnexpectedValue.error)
    elseif data.TicketError then
      local msg = string.format(data.TicketError.error)
      if data.TicketError.code == "UnknownKey" then
        msg = msg .. ". Make sure your YAXI API key exists in your environment and that it is Base64 encoded."
      elseif data.TicketError.code == "Invalid" then
        if data.TicketError.error == "InvalidSignature" then
          msg = msg .. ". Make sure to use HMAC-SHA256 to sign the ticket JWT and that it is working properly."
        elseif data.TicketError.error == 'Invalid "yaxi-ticket" header' then
          msg = msg .. ". Make sure to use a matching ticket for the called service."
        end
      end

      err = TicketError:new(data.TicketError.code, msg)
    elseif data.ProviderError then
      err = ProviderError:new(data.ProviderError.code, data.ProviderError.userMessage)
    elseif data.InterruptError then
      err = InterruptError:new()
    end
  end

  if response.status == 404 then
    err = NotFoundError:new()
  end

  if err then
    log:debug("HTTP response error: %s", response.body)
    error(err)
  end

  ---@diagnostic enable: need-check-nil, undefined-field, unnecessary-if
  return data --[[@as table<string, any>]]
end

---System version for the currently established session.
---@return YAXI.KeySettlement.SettlementResponse.SystemVersion?
function Core:systemVersion()
  return self._settlement:systemVersion()
end

---
--- Search for service connections (banks and other providers)
---
--- The result is a list of connections that match all the {@link SearchFilter}s.
--- If IBAN detection is enabled and the first value of a term filter is detected
--- to be a possible prefix of an IBAN that contains a national bank code,
--- the result might contain additional connections that match that bank code.
---
---@param options YAXI.RoutexClient.SearchOptions
---@return YAXI.RoutexClient.ConnectionInfo[]
function Core:search(options)
  local reqBuilder = self:_buildRequest(options.ticket, "search", {
    ibanDetection = options.ibanDetection or false,
    filters = options.filters,
    limit = options.limit,
    details = options.details,
  })

  local usePublicSearch = options.ticket == nil
  if usePublicSearch then
    reqBuilder:header("yaxi-ticket-id", uuid.uuid4())
  end

  local response = self:_sendRequest(reqBuilder:build())

  local infos = Core._handleResponse(response) --[[@as YAXI.RoutexClient.ConnectionInfo[] ]]
  return infos
end

---
--- Get information for a service connection
---
---@param options YAXI.RoutexClient.InfoOptions
---@return YAXI.RoutexClient.ConnectionInfo
function Core:info(options)
  local response = self:_request(options.ticket, string.format("info/%s", options.connectionId), nil)
  local info = Core._handleResponse(response) --[[@as YAXI.RoutexClient.ConnectionInfo]]
  return info
end

---Trace identifier returned with the last request
---@return binary?
function Core:traceId()
  return self._traceId
end

---Retrieve trace data
---@param ticket string YAXI service ticket
---@param traceId binary
---@return string
function Core:trace(ticket, traceId)
  local traceIdSealed = self._settlement:seal(traceId, {
    ["accept"] = self.MEDIA_TYPE,
    ["user-agent"] = USER_AGENT,
    ["yaxi-ticket-id"] = getTicketID(ticket),
  })
  local traceIdSealedB64 = base64.encodeUrlsafe(traceIdSealed)
  local response = self:_request(ticket, string.format("traces/%s", traceIdSealedB64))
  if response.status >= 400 then
    Core._handleResponse(response)
    error(UnexpectedError:new(string.format("Failed to retrieve trace for ID %s", traceId)))
  end
  return response.body --[[@as string]]
end

---
--- Set a redirect URI for subsequent service requests.
---
--- Redirects will eventually forward to that URI.
--- It can be used to redirect back to a web application or to jump
--- back into the context of a desktop or mobile application.
--- If no redirect URI is set, {@link RedirectHandle}s will get returned instead of {@link Redirect}s.
---
---@param redirectUri string
function Core:setRedirectUri(redirectUri)
  self._redirectUri = redirectUri
end

--#region Account filter mapping

---@private
---@param data [YAXI.RoutexClient.AccountField, string|YAXI.RoutexClient.AccountStatus|YAXI.RoutexClient.AccountType|nil]
---@return [string, string|YAXI.RoutexClient.NULL_MARKER]
function Core._mapFieldFilter(data)
  local field = data[1] or error("Expected array with account field")

  local value = data[2]
  if field == AccountField.Status then
    local status = data[2] --[[@as YAXI.RoutexClient.AccountStatus?]]
    value = status
  elseif field == AccountField.Type then
    local type = data[2] --[[@as YAXI.RoutexClient.AccountType?]]
    value = type
  end

  return { field, value or NULL_MARKER }
end

---@protected
---@param filter YAXI.RoutexClient.AccountFilter
---@return YAXI.RoutexClient.AccountFilterJSON
function Core:_mapFilter(filter)
  if filter.eq then
    ---@cast filter YAXI.RoutexClient.AccountFilter.Eq
    return {
      Eq = self._mapFieldFilter(filter.eq),
    } --[[@as YAXI.RoutexClient.AccountFilterJSON]]
  elseif filter.notEq then
    ---@cast filter YAXI.RoutexClient.AccountFilter.NotEq
    return {
      NotEq = self._mapFieldFilter(filter.notEq),
    } --[[@as YAXI.RoutexClient.AccountFilterJSON]]
  elseif filter.all then
    if #filter.all == 0 then
      local tautology = { any = { { eq = { AccountField.Iban } }, { notEq = { AccountField.Iban } } } }
      return self:_mapFilter(tautology)
    elseif #filter.all == 1 then
      return self:_mapFilter(filter.all[1])
    end
    local other
    if #filter.all > 2 then
      ---@cast filter YAXI.RoutexClient.AccountFilter.All
      other = { all = { table.unpack(filter.all, 2) } }
    else
      ---@cast filter YAXI.RoutexClient.AccountFilter
      other = filter.all[2]
    end
    return {
      And = {
        self:_mapFilter(filter.all[1] --[[@as YAXI.RoutexClient.AccountFilter]]),
        self:_mapFilter(other --[[@as YAXI.RoutexClient.AccountFilter]]),
      },
    } --[[@as YAXI.RoutexClient.AccountFilterJSON]]
  elseif filter.any then ---@diagnostic disable-line: unnecessary-if
    ---@cast filter YAXI.RoutexClient.AccountFilter.Any
    if #filter.any == 0 then
      local contradiction = { all = { { eq = { AccountField.Iban } }, { notEq = { AccountField.Iban } } } }
      return self:_mapFilter(contradiction)
    elseif #filter.any == 1 then
      return self:_mapFilter(filter.any[1])
    end
    local other
    if #filter.any > 2 then
      ---@type YAXI.RoutexClient.AccountFilter.Any
      other = { any = { table.unpack(filter.any, 2) } }
    else
      ---@type YAXI.RoutexClient.AccountFilter.Any
      other = filter.any[2]
    end
    return {
      Or = {
        self:_mapFilter(filter.any[1] --[[@as YAXI.RoutexClient.AccountFilter]]),
        self:_mapFilter(other --[[@as YAXI.RoutexClient.AccountFilter]]),
      },
    } --[[@as YAXI.RoutexClient.AccountFilterJSON]]
  elseif filter.supports then
    ---@cast filter YAXI.RoutexClient.AccountFilter.Supports
    return {
      Supports = filter.supports,
    } --[[@as YAXI.RoutexClient.AccountFilterJSON]]
  end

  error(string.format("Unknown filter: %s", jsonEncode(filter)))
end

--#endregion Account filter mapping

--#endregion Core

return {
  _VERSION = _VERSION,
  NULL_MARKER = NULL_MARKER,

  Core = Core,

  -- Enums
  AccountField = AccountField,
  AccountStatus = AccountStatus,
  AccountType = AccountType,
  ConnectionDetails = ConnectionDetails,
  ConnectionType = ConnectionType,
  SupportedService = SupportedService,
}
