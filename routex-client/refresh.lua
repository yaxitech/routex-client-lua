-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

local core = require("routex-client.core")
local errors = require("routex-client.errors")
local util = require("routex-client.util")
local super = util.super
local class = util.class

local Core = core.Core
local UnexpectedError = errors.UnexpectedError

local base64Encode = require("routex-client.util.base64").encode
local base64Decode = require("routex-client.util.base64").decode

--#region Options

---Inputs shared by all non-interactive service requests.
---@class YAXI.RoutexRefreshClient.ServiceOptions
---@field ticket string YAXI service ticket.
---@field connectionData binary Opaque connection data returned by a successful interactive flow (see [`Result.connectionData`](lua://YAXI.RoutexClient.Result)).
---@field session binary? Session returned by a previous call in the same flow.

---@class YAXI.RoutexRefreshClient.AccountsOptions: YAXI.RoutexRefreshClient.ServiceOptions
---@field fields YAXI.RoutexClient.AccountField[]? Fields to populate on each returned account.
---@field filter YAXI.RoutexClient.AccountFilter? Filter to apply to the returned accounts.

---@class YAXI.RoutexRefreshClient.BalancesOptions: YAXI.RoutexRefreshClient.ServiceOptions
---@field accounts YAXI.RoutexClient.AccountReference[] Accounts to fetch balances for.

---@alias YAXI.RoutexRefreshClient.TransactionsOptions YAXI.RoutexRefreshClient.ServiceOptions

--#endregion Options

--#region Responses

---Response from a non-interactive service call.
---
---Unlike the interactive [`Result`](lua://YAXI.RoutexClient.Result), the data is
---returned directly in `result` without a JWT envelope.
---@class YAXI.RoutexRefreshClient.Response
---@field session binary? Pass to a subsequent request in the same flow.
---@field connectionData binary? Updated connection data to persist for future refreshes.

---@class YAXI.RoutexRefreshClient.AccountsResponse: YAXI.RoutexRefreshClient.Response
---@field result YAXI.RoutexClient.Result.Account[]

---@class YAXI.RoutexRefreshClient.BalancesResponse: YAXI.RoutexRefreshClient.Response
---@field result YAXI.RoutexClient.Result.Balances

---@class YAXI.RoutexRefreshClient.TransactionsResponse: YAXI.RoutexRefreshClient.Response
---@field result YAXI.RoutexClient.Result.Transaction[]? `nil` if the result got delivered to a webhook.

--#endregion Responses

--#region UserInSession

---Indicates that a user is in session for a non-interactive service call.
---
---When a user is in session, YAXI forwards the user's IP address to their bank. That
---address is either this connection's own source IP (`UserInSession.OnThisConnection`)
---or an IP address the caller provides (`UserInSession.At`).
---
---Without a user in session, banks limit how many requests a caller may make and reject
---excess requests with an [`AccessExceeded`](lua://YAXI.RoutexClient.Error.AccessExceeded)
---error. A user in session lifts that limit.
---@alias YAXI.RoutexRefreshClient.UserInSession string

local UserInSession = {
  ---The user's IP is this connection's own source IP.
  OnThisConnection = "connection",
}

---The user is at the given IP address.
---@param ipAddress string
---@return YAXI.RoutexRefreshClient.UserInSession
function UserInSession.At(ipAddress)
  return ipAddress
end

--#endregion UserInSession

--#region RoutexRefreshClient

---
--- Client for the YAXI Open Banking non-interactive (refresh) services:
--- [`accounts`](lua://YAXI.RoutexRefreshClient.accounts), [`balances`](lua://YAXI.RoutexRefreshClient.balances)
--- and [`transactions`](lua://YAXI.RoutexRefreshClient.transactions), plus the discovery endpoints
--- [`info`](lua://YAXI.RoutexClient.Core.info) and [`search`](lua://YAXI.RoutexClient.Core.search).
---
--- Use this client to refresh data for an already-consented connection without prompting the user.
--- Compared to the interactive [`RoutexClient`](lua://YAXI.RoutexClient.RoutexClient):
---  - **Inputs.** Connection data obtained from a successful interactive flow replaces the credentials
---    (see [Handling sessions](https://docs.yaxi.tech/sessions.html)).
---  - **Outputs.** Each call returns the decoded payload directly: no JWT envelope, no
---    [`Dialog`](lua://YAXI.RoutexClient.Dialog) / [`Redirect`](lua://YAXI.RoutexClient.Redirect) interrupt branches.
---  - **Surface.** Only the read services are exposed; payment and transfer flows are inherently
---    interactive and live on [`RoutexClient`](lua://YAXI.RoutexClient.RoutexClient).
---
---@class YAXI.RoutexRefreshClient: YAXI.RoutexClient.Core
---@field private _userInSession YAXI.RoutexRefreshClient.UserInSession?
local RoutexRefreshClient = class(Core)

---Create a new instance.
---@param url string? A URL to a YAXI routex environment; default to `https://api.yaxi.tech`
---@param httpClient YAXI.Http.IClient? If `nil`, uses a default client based on `lua-http`
---@return YAXI.RoutexRefreshClient
function RoutexRefreshClient:new(url, httpClient)
  local obj = super(self).new(self, url, httpClient) --[[@as YAXI.RoutexRefreshClient]]
  return obj
end

---Indicates a user is in session for every service call this client makes, lifting the
---bank's limit on requests without one (see
---[`UserInSession`](lua://YAXI.RoutexRefreshClient.UserInSession)). Unset by default.
---@param userInSession YAXI.RoutexRefreshClient.UserInSession
function RoutexRefreshClient:setUserInSession(userInSession)
  self._userInSession = userInSession
end

---Prepare the body of a non-interactive request.
---@private
---@param options YAXI.RoutexRefreshClient.ServiceOptions
---@param userInSession YAXI.RoutexRefreshClient.UserInSession? in-session user to forward
---@param data table<string, any> Service-specific request data
---@return table<string, any>
function RoutexRefreshClient._prepareData(options, userInSession, data)
  local connectionData = options.connectionData or error(UnexpectedError:new("Missing `connectionData`"))

  local res = {
    connectionData = base64Encode(connectionData)
      or error(UnexpectedError:new("Could not Base64-encode connection data")),
    session = options.session
      and (base64Encode(options.session) or error(UnexpectedError:new("Could not Base64-encode session"))),
    userInSession = userInSession,
  }

  for k, v in pairs(data) do
    res[k] = v
  end

  return res
end

---Read a non-interactive response.
---@private
---@param response YAXI.Http.Response
---@return YAXI.RoutexRefreshClient.Response
function RoutexRefreshClient._readResponse(response)
  local json = RoutexRefreshClient._handleResponse(response)

  return {
    result = json.result,
    session = json.session
      and (base64Decode(json.session) or error(UnexpectedError:new("Could not Base64-decode response session"))),
    connectionData = json.connectionData and (base64Decode(json.connectionData) or error(
      UnexpectedError:new("Could not Base64-decode response connection data")
    )),
  }
end

---Refresh the connection's accounts
---([Accounts service](https://docs.yaxi.tech/accounts.html))
---@param options YAXI.RoutexRefreshClient.AccountsOptions
---@return YAXI.RoutexRefreshClient.AccountsResponse
function RoutexRefreshClient:accounts(options)
  local data = self._prepareData(options, self._userInSession, {
    fields = options.fields or {},
    filter = options.filter and self:_mapFilter(options.filter) or nil,
  })
  local response = self:_request(options.ticket, "accounts/non-interactive", data)
  return self._readResponse(response) --[[@as YAXI.RoutexRefreshClient.AccountsResponse]]
end

---Refresh the connection's balances for the given accounts
---([Balances service](https://docs.yaxi.tech/balances.html))
---@param options YAXI.RoutexRefreshClient.BalancesOptions
---@return YAXI.RoutexRefreshClient.BalancesResponse
function RoutexRefreshClient:balances(options)
  local data = self._prepareData(options, self._userInSession, {
    accounts = options.accounts,
  })
  local response = self:_request(options.ticket, "balances/non-interactive", data)
  return self._readResponse(response) --[[@as YAXI.RoutexRefreshClient.BalancesResponse]]
end

---Refresh the connection's transactions for the account defined in the ticket
---([Transactions service](https://docs.yaxi.tech/transactions.html))
---@param options YAXI.RoutexRefreshClient.TransactionsOptions
---@return YAXI.RoutexRefreshClient.TransactionsResponse
function RoutexRefreshClient:transactions(options)
  local data = self._prepareData(options, self._userInSession, {})
  local response = self:_request(options.ticket, "transactions/non-interactive", data)
  return self._readResponse(response) --[[@as YAXI.RoutexRefreshClient.TransactionsResponse]]
end

--#endregion RoutexRefreshClient

return {
  RoutexRefreshClient = RoutexRefreshClient,
  UserInSession = UserInSession,

  -- Shared enums, re-exported for convenience
  AccountField = core.AccountField,
  AccountStatus = core.AccountStatus,
  AccountType = core.AccountType,
  ConnectionDetails = core.ConnectionDetails,
  ConnectionType = core.ConnectionType,
  SupportedService = core.SupportedService,
}
