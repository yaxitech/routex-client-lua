-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

-- Logging setup
local log = require("routex-client.logging").defaultLogger()
  or error("Failed to get default logger. Did you initialize it?")

local dateutil = require("routex-client.util.date")
local util = require("routex-client.util")
local uuid = require("routex-client.util.uuid")
local super = util.super
local class = util.class

local errors = require("routex-client.errors")
-- Error classes
local Error = errors.Error
local AccessExceededError = errors.AccessExceededError
local CanceledError = errors.CanceledError
local ConsentExpiredError = errors.ConsentExpiredError
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
local base64 = require("routex-client.util.base64")
local http = require("routex-client.http")

local jsonDecode = require("routex-client.vendor.json").decode
local jsonEncode = require("routex-client.vendor.json").encode

local base64Encode = require("routex-client.util.base64").encode
local base64Decode = require("routex-client.util.base64").decode

local jwt = require("routex-client.jwt")

local _VERSION = "0.1.0"
local USER_AGENT = ("RoutexClient/%s (Lua)"):format(_VERSION)

-- routex expects `null` instead of omitting entries entirely
---@alias YAXI.RoutexClient.NULL_MARKER "____NULL_MARKER____"

---@type YAXI.RoutexClient.NULL_MARKER
local NULL_MARKER = "____NULL_MARKER____"

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

---@class YAXI.RoutexClient.SearchOptions
---@field ticket string?
---@field filters YAXI.RoutexClient.SearchFilter[]?
---@field ibanDetection boolean?
---@field limit integer?

---@class YAXI.RoutexClient.InfoOptions
---@field ticket string
---@field connectionId string

---@class YAXI.RoutexClient.AccountsOptions: YAXI.RoutexClient.ServiceOptions
---@field fields YAXI.RoutexClient.AccountField[]?
---@field filter YAXI.RoutexClient.AccountFilter?

---@class YAXI.RoutexClient.AccountReference
---@field iban string
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
---@field debtorAccount YAXI.RoutexClient.AccountReference?
---@field debtorName string?
---@field requestedExecutionDate osdate? %Y-%m-%dT%H:%M:%S%.f
---@field details YAXI.RoutexClient.TransferOptions.Details[]

---@class YAXI.RoutexClient.RegisterRedirectOptions
---@field ticket string
---@field handle string
---@field redirectUri string

---@alias YAXI.RoutexClient.ResultJSON { Result: [string, string?, string?] } JWT, session, connection data

---@alias YAXI.RoutexClient.DialogJSON.Image { mimeType: string, data: string, hhdUcData: string? }
---@alias YAXI.RoutexClient.DialogJSON.Input.Confirmation { Confirmation: { context: string, pollingDelaySecs: number? } }
---@alias YAXI.RoutexClient.DialogJSON.Input.Selection.Option {key: string, label: string, explanation: string?}
---@alias YAXI.RoutexClient.DialogJSON.Input.Selection { Selection: { options: YAXI.RoutexClient.DialogJSON.Input.Selection.Option[], context: string } }
---@alias YAXI.RoutexClient.DialogJSON.Input.Field { Field: { type: string, secrecyLevel: string, context: string, minLength: integer?, maxLength: integer? } }
---@alias YAXI.RoutexClient.DialogJSON.Input YAXI.RoutexClient.DialogJSON.Input.Confirmation | YAXI.RoutexClient.DialogJSON.Input.Selection | YAXI.RoutexClient.DialogJSON.Input.Field
---@alias YAXI.RoutexClient.DialogJSON { Dialog: { context: string?, message: string?, image?: YAXI.RoutexClient.DialogJSON.Image, input: YAXI.RoutexClient.DialogJSON.Input.Confirmation | YAXI.RoutexClient.DialogJSON.Input.Selection | YAXI.RoutexClient.DialogJSON.Input.Field } }

---@alias YAXI.RoutexClient.OBResponseJSON YAXI.RoutexClient.ResultJSON | YAXI.RoutexClient.DialogJSON | YAXI.RoutexClient.RedirectJSON | YAXI.RoutexClient.RedirectHandleJSON

---@enum YAXI.RoutexClient.DialogContext
local DialogContext = {
  ---SCA or TAN process.
  ---There are multiple cases, distinguishable by the input type:
  --- - [`Confirmation`](lua://YAXI.RoutexClient.Dialog.Input.Confirmation): Decoupled process (e.g. confirmation in a SCA app).
  --- - [`Selection`](lua://YAXI.RoutexClient.Dialog.Input.Selection): TAN method selection.
  --- - [`Field`](lua://YAXI.RoutexClient.Dialog.Input.Field).: TAN entry.
  Sca = "Sca",

  ---Account selection.
  ---A [`Selection`](lua://YAXI.RoutexClient.Dialog.Input.Selection) gets returned with this context when an account has to be selected.
  ---Note that there might be just a single option that may be chosen automatically without user interaction.
  Accounts = "Accounts",

  ---Pending redirect confirmation.
  ---A [`Confirmation`](lua://YAXI.RoutexClient.Dialog.Input.Confirmation) gets returned with this context when a redirect got confirmed but no result is known yet.
  Redirect = "Redirect",

  ---Pending SCT Inst payment.
  ---A [`Confirmation`](lua://YAXI.RoutexClient.Dialog.Input.Confirmation) gets returned with this context when an SCT Inst payment has been initialized and not reached the final status yet.
  PaymentStatus = "PaymentStatus",

  ---Verification of Payee confirmation.
  ---A [`Confirmation`](lua://YAXI.RoutexClient.Dialog.Input.Confirmation) gets returned with this context when an explicit confirmation of the creditor is required due to a name mismatch.
  ---Note that this confirmation has legal implications, releasing the bank from liabilities in case of the transfer to an unintended receiver due to incorrect creditor data.
  VopConfirmation = "VopConfirmation",

  ---Pending Verification of Payee check.
  ---A [`Confirmation`](lua://YAXI.RoutexClient.Dialog.Input.Confirmation) gets returned with this context when a Verification of Payee check is still pending.
  VopCheck = "VopCheck",
}

---@class YAXI.RoutexClient.Dialog.Image
---@field mimeType string
---@field data binary Binary data in the format defined by mimeType.
---@field hhdUcData binary? HHD_UC data block. In cases where the ASPSP provides HHD_UC data for optical coupling with a HandHeld-Device for the generation of an OTP, especially for an HHD_OPT animated graphic, the raw HHD_UC data stream is provided here. `data` provides a pre-rendered animated GIF to be presented with a width of 62.5 mm.

---Just a primary action to confirm the dialog.
---@class YAXI.RoutexClient.Dialog.Input.Confirmation: YAXI.ClassBase
---@field context binary Context object that can be used to confirm the dialog.
---@field pollingDelaySecs number? If polling is acceptable, a delay in seconds is specified for which the client has to wait before automatically confirming.
local Confirmation = class()

---Create a new instance
---@param context binary
---@param pollingDelaySecs number?
---@return YAXI.RoutexClient.Dialog.Input.Confirmation
function Confirmation:new(context, pollingDelaySecs)
  ---@type YAXI.RoutexClient.Dialog.Input.Confirmation
  local obj = setmetatable({}, self)
  obj.context = context
  obj.pollingDelaySecs = pollingDelaySecs
  return obj
end

---@class YAXI.RoutexClient.Dialog.Input.Selection.Option
---@field key string
---@field label string
---@field explanation string?

---A selection of options the user can choose from.
---@class YAXI.RoutexClient.Dialog.Input.Selection: YAXI.ClassBase
---@field options YAXI.RoutexClient.Dialog.Input.Selection.Option[] Options are meant to be rendered e.g. as radio buttons where the user must select exactly one to for a confirmation button to get enabled. Another example for an implementation is one button per option that immediately confirms the selection.
---@field context binary Context object that can be used to respond to the dialog.
local Selection = class()

---Create a new instance
---@param options YAXI.RoutexClient.Dialog.Input.Selection.Option[]
---@param context binary
---@return YAXI.RoutexClient.Dialog.Input.Selection
function Selection:new(options, context)
  ---@type YAXI.RoutexClient.Dialog.Input.Selection
  local obj = setmetatable({}, self)
  obj.options = options
  obj.context = context
  return obj
end

---@enum YAXI.RoutexClient.InputType
local InputType = {
  Date = "Date",
  Email = "Email",
  Number = "Number",
  Phone = "Phone",
  Text = "Text",
}

---@enum YAXI.RoutexClient.SecrecyLevel Level of secrecy for an input field.
local SecrecyLevel = {
  --- The data is not a secret.
  Plain = "Plain",
  --- The data is a one-time password. This can usually be treated as
  --- no secret but the implementer might still choose to mask the input.
  Otp = "Otp",
  --- The data is a secret password. Input must be masked.
  Password = "Password",
}

---An input field.
---@class YAXI.RoutexClient.Dialog.Input.Field: YAXI.ClassBase
---@field type YAXI.RoutexClient.InputType Type that may be used for showing hints or dedicated keyboard layouts and for applying input restrictions or validation.
---@field secrecyLevel YAXI.RoutexClient.SecrecyLevel Indicates if the input should be masked.
---@field context binary Context object that can be used to respond to the dialog.
---@field minLength number? Minimal length to allow.
---@field maxLength number? Maximum length to allow.
local Field = class()

---Create a new instance
---@return YAXI.RoutexClient.Dialog.Input.Field
---@param type YAXI.RoutexClient.InputType
---@param secrecyLevel YAXI.RoutexClient.SecrecyLevel
---@param context binary
---@param minLength number?
---@param maxLength number?
function Field:new(type, secrecyLevel, context, minLength, maxLength)
  ---@type YAXI.RoutexClient.Dialog.Input.Field
  local obj = setmetatable({}, self)
  obj.type = type
  obj.secrecyLevel = secrecyLevel
  obj.context = context
  obj.minLength = minLength
  obj.maxLength = maxLength
  return obj
end

---@alias YAXI.RoutexClient.RedirectJSON { Redirect: { url: string, context: string } }

---@alias YAXI.RoutexClient.RedirectHandleJSON { RedirectHandle: { handle: string, context: string } }

---@class YAXI.RoutexClient.OBResponse: YAXI.ClassBase Response from YAXI Open Banking services.
---@field private __index table
---@field private _json YAXI.RoutexClient.OBResponseJSON
local OBResponse = class()

---@protected
---@param json YAXI.RoutexClient.OBResponseJSON
---@return table
function OBResponse:new(json)
  local obj = setmetatable({}, self)
  obj._json = json
  return obj
end

---@return YAXI.RoutexClient.OBResponseJSON
function OBResponse:toJSON()
  return self._json
end

---User dialog.
---
---This is meant to be displayed as a dialog in some User Interface and consists of:
--- - A way to cancel the dialog (typically an X symbol and / or a "Cancel" button).
--- - The display part: the `message` and an optional `image`.
--- - The interactive part defined by `input`.
---@class YAXI.RoutexClient.Dialog: YAXI.RoutexClient.OBResponse
---@field input YAXI.RoutexClient.Dialog.Input.Confirmation | YAXI.RoutexClient.Dialog.Input.Selection | YAXI.RoutexClient.Dialog.Input.Field | nil
---@field context YAXI.RoutexClient.DialogContext?
---@field message string?
---@field image YAXI.RoutexClient.Dialog.Image?
local Dialog = class(OBResponse)

---@protected
---@param json YAXI.RoutexClient.DialogJSON
---@return YAXI.RoutexClient.Dialog
function Dialog:new(json)
  if not json then
    error("Given JSON is nil")
  end

  ---@type YAXI.RoutexClient.Dialog
  local obj = super(self).new(self, json)
  setmetatable(obj, self)

  local contextMap = {
    Sca = DialogContext.Sca,
    Accounts = DialogContext.Accounts,
    Redirect = DialogContext.Redirect,
    PaymentStatus = DialogContext.PaymentStatus,
    VopConfirmation = DialogContext.VopConfirmation,
    VopCheck = DialogContext.VopCheck,
  }

  obj.context = contextMap[json.Dialog.context]
  if json.Dialog.context and not obj.context then
    error(string.format("Unexpected Dialog.context: %s", json.Dialog.context))
  end

  obj.message = json.Dialog.message

  if json.Dialog.image then
    obj.image = {
      mimeType = json.Dialog.image.mimeType,
      data = base64Decode(json.Dialog.image.data) or error("Could not Base64-decode Dialog.image.data"),
      hhdUcData = json.Dialog.image.hhdUcData
        and (base64Decode(json.Dialog.image.hhdUcData) or error("Could not Base64-decode Dialog.image.hhdUcData")),
    }
  end

  if json.Dialog.input.Confirmation then ---@diagnostic disable-line: unnecessary-if
    local context = base64Decode(json.Dialog.input.Confirmation.context)
      or error("Could not Base64-decode json.Dialog.input.Confirmation.context")
    local pollingDelaySecs = json.Dialog.input.Confirmation.pollingDelaySecs
    obj.input = Confirmation:new(context, pollingDelaySecs)
  elseif json.Dialog.input.Selection then ---@diagnostic disable-line: unnecessary-if
    local options = json.Dialog.input.Selection.options
    local context = base64Decode(json.Dialog.input.Selection.context)
      or error("Could not Base64-decode json.Dialog.input.Selection.context")
    obj.input = Selection:new(options, context)
  elseif json.Dialog.input.Field then ---@diagnostic disable-line: unnecessary-if
    ---@type YAXI.RoutexClient.InputType
    local type
    ---@type YAXI.RoutexClient.SecrecyLevel
    local secrecyLevel
    ---@type binary
    local context
    ---@type integer?
    local minLength
    ---@type integer?
    local maxLength

    local inputField = json.Dialog.input.Field

    if inputField.type == "Date" then
      type = InputType.Date
    elseif inputField.type == "Email" then
      type = InputType.Email
    elseif inputField.type == "Number" then
      type = InputType.Number
    elseif inputField.type == "Phone" then
      type = InputType.Phone
    elseif inputField.type == "Text" then
      type = InputType.Text
    else
      error(string.format("Unexpected Dialog.input.Field.type: %s", inputField.type))
    end

    if inputField.secrecyLevel == "Plain" then
      secrecyLevel = SecrecyLevel.Plain
    elseif inputField.secrecyLevel == "Otp" then
      secrecyLevel = SecrecyLevel.Otp
    elseif inputField.secrecyLevel == "Password" then
      secrecyLevel = SecrecyLevel.Password
    else
      error(string.format("Unexpected Dialog.input.Field.secrecyLevel: %s", inputField.secrecyLevel))
    end

    minLength = json.Dialog.input.Field.minLength
    maxLength = json.Dialog.input.Field.maxLength
    context = base64Decode(json.Dialog.input.Field.context)
      or error("Could not Base64-decode json.Dialog.input.Field.context")

    obj.input = Field:new(type, secrecyLevel, context, minLength, maxLength)
  end

  return obj
end

---@param json YAXI.RoutexClient.DialogJSON
---@return YAXI.RoutexClient.Dialog
function Dialog:fromJSON(json)
  return self:new(json)
end

--#region Redirect

--- User redirect
---
--- The user is meant to get sent to the url and the context can
--- be used for continuing the process at the service that issued the redirect object afterward.
--- A web application needs to direct the user agent to the returned URL.
--- A desktop or mobile application could either open it in a browser or inside an element like a WebView.
---@class YAXI.RoutexClient.Redirect: YAXI.RoutexClient.OBResponse
---@field url string
---@field context binary
local Redirect = class(OBResponse)

---@protected
---@param json YAXI.RoutexClient.RedirectJSON
---@return YAXI.RoutexClient.Redirect
function Redirect:new(json)
  if not json then
    error("Given JSON is nil")
  end

  ---@type YAXI.RoutexClient.Redirect
  local obj = super(self).new(self, json)
  setmetatable(obj, self)

  obj.url = json.Redirect.url
  obj.context = base64Decode(json.Redirect.context) or error("Could not Base64-decode json.Redirect.context")

  return obj
end

---@param json YAXI.RoutexClient.RedirectJSON
---@return YAXI.RoutexClient.Redirect
function Redirect:fromJSON(json)
  return self:new(json)
end

--#endregion Redirect

--#region RedirectHandle

---
--- Incomplete user redirect.
---
--- A final redirect URI needs to get registered, using the handle, to receive the URL to send the user to.
---
---@class YAXI.RoutexClient.RedirectHandle: YAXI.RoutexClient.OBResponse
---@field handle string
---@field context binary
local RedirectHandle = class(OBResponse)

---@protected
---@param json YAXI.RoutexClient.RedirectHandleJSON
---@return YAXI.RoutexClient.RedirectHandle
function RedirectHandle:new(json)
  if not json then
    error("Given JSON is nil")
  end

  ---@type YAXI.RoutexClient.RedirectHandle
  local obj = super(self).new(self, json)
  setmetatable(obj, self)

  obj.handle = json.RedirectHandle.handle
  obj.context = base64Decode(json.RedirectHandle.context) or error("Could not Base64-decode json.Redirect.context")

  return obj
end

---@param json YAXI.RoutexClient.RedirectHandleJSON
---@return YAXI.RoutexClient.RedirectHandle
function RedirectHandle:fromJSON(json)
  return self:new(json)
end

--#endregion RedirectHandle

--#region Result

---
--- Data returned by YAXI Open Banking services, authenticated with an HMAC
---
--- jwt can be used for transfer to a remote system as [JSON Web Token](https://jwt.io/).
--- The remote system can verify and read the data from the "data" claim.
--- To read the data locally, the frontend can decode the JWT without verification.
---
--- Besides the value itself, it contains a timestamp and a ticket identifier
--- (bound to known input parameters and service type).
---
---@class YAXI.RoutexClient.Result: YAXI.RoutexClient.OBResponse
---@field jwt string
---@field session binary?
---@field connectionData binary?
local Result = class(OBResponse)

---@protected
---@param json YAXI.RoutexClient.ResultJSON
function Result:new(json)
  if not json then
    error("Given JSON is nil")
  end

  ---@type YAXI.RoutexClient.Result
  local obj = super(self).new(self, json)
  setmetatable(obj, self)

  obj.jwt = json.Result[1]
  obj.session = json.Result[2] and (base64Decode(json.Result[2]) or error("Could not Base64-decode Result session"))
  obj.connectionData = json.Result[3]
    and (base64Decode(json.Result[3]) or error("Could not Base64-decode Result connection data"))

  return obj
end

---@param json YAXI.RoutexClient.ResultJSON
---@return YAXI.RoutexClient.Result
function Result:fromJSON(json)
  return self:new(json)
end

--#endregion Result

---Create new instance from a JSON table value
---@param json YAXI.RoutexClient.OBResponseJSON
---@return YAXI.RoutexClient.OBResponse
function OBResponse.fromJSON(json)
  if json.Dialog then
    local dialogJSON = json --[[@as YAXI.RoutexClient.DialogJSON]]
    return Dialog:fromJSON(dialogJSON)
  elseif json.Redirect then
    local redirectJSON = json --[[@as YAXI.RoutexClient.RedirectJSON]]
    return Redirect:fromJSON(redirectJSON)
  elseif json.RedirectHandle then
    local redirectHandleJSON = json --[[@as YAXI.RoutexClient.RedirectHandleJSON]]
    return RedirectHandle:fromJSON(redirectHandleJSON)
  elseif json.Result then
    local resultJSON = json --[[@as YAXI.RoutexClient.ResultJSON]]
    return Result:fromJSON(resultJSON)
  else
    log:error(json)
    error(string.format("Unexpected json: %s", jsonEncode(json)))
  end
end

---@class YAXI.RoutexClient.ResponseOptions
---@field ticket string
---@field context binary
---@field response string

---@class YAXI.RoutexClient.ConfirmationOptions
---@field ticket string
---@field context binary

--#region RoutexClient

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

---@class YAXI.RoutexClient.RoutexClient: YAXI.ClassBase
---@field MEDIA_TYPE string
---@field private __index table
---@field private _httpClient YAXI.Http.IClient
---@field private _url string
---@field private _settlement YAXI.KeySettlement
---@field private _traceId binary
---@field private _redirectUri string?
local RoutexClient = class({
  MEDIA_TYPE = "application/vnd.yaxi.v5",
})

---Create a new instance.
---@param url string? A URL to a YAXI routex environment; default to `https://api.yaxi.tech`
---@param httpClient YAXI.Http.IClient? If `nil`, uses a default client based on `lua-http`
---@return YAXI.RoutexClient.RoutexClient
function RoutexClient:new(url, httpClient)
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
function RoutexClient:sealedRequest(request)
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
    RoutexClient._handleResponse(responseUnsealed)
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
    local traceIdSealed = base64Decode(traceIdSealedB64) or error("Could not Base64-decode the sealed trace ID header")
    traceId = self._settlement:unseal(traceIdSealed)
  end

  return responseUnsealed, traceId
end

---@private
---@param ticket string? YAXI service ticket
---@param path string HTTP URL path
---@param data table<string, any>|string|nil Data to encode and send as JSON body
---@return YAXI.Http.RequestBuilder
function RoutexClient:_buildRequest(ticket, path, data)
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

---@private
---@param request YAXI.Http.Request request to send
---@return YAXI.Http.Response
function RoutexClient:_sendRequest(request)
  local response, traceId = self:sealedRequest(request)

  if traceId then
    self._traceId = traceId
    local traceIdB64 = traceId and base64Encode(self._traceId)
      or error(UnexpectedError:new("Could not Base64-encode trace ID"))
    log:debug("yaxi-trace-id: %s", traceIdB64)
  end

  return response
end

---@private
---@param ticket string YAXI service ticket
---@param path string HTTP URL path
---@param data table<string, any>|string|nil Data to encode and send as JSON body
---@return YAXI.Http.Response
function RoutexClient:_request(ticket, path, data)
  local request = self:_buildRequest(ticket, path, data):build()
  return self:_sendRequest(request)
end

---Unseal the body of the response
---@private
---@param response YAXI.Http.Response
---@param fallback boolean
---@return YAXI.Http.Response
function RoutexClient:_unsealBody(response, fallback)
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

---Decode the response and raises an [`Error`](lua://RoutexClient.Error) if necessary
---@private
---@param response YAXI.Http.Response
---@return table<string, any>
function RoutexClient._handleResponse(response)
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
    elseif data.ConsentExpired then
      err = ConsentExpiredError:new(data.ConsentExpired.userMessage)
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

---System version for the currently established session.
---@return YAXI.KeySettlement.SettlementResponse.SystemVersion?
function RoutexClient:systemVersion()
  return self._settlement:systemVersion()
end

--#region RoutexClient:search() / RoutexClient:info()

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

---Type of connections to consider when searching.
---@enum YAXI.RoutexClient.ConnectionType
local ConnectionType = {
  --- Production connections.
  Production = "Production",
  --- Sandbox connections, especially test systems provided by third-parties.
  Sandboxes = "Sandboxes",
}

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
function RoutexClient:search(options)
  local reqBuilder = self:_buildRequest(options.ticket, "search", {
    ibanDetection = options.ibanDetection or false,
    filters = options.filters,
    limit = options.limit,
  })

  local usePublicSearch = options.ticket == nil
  if usePublicSearch then
    reqBuilder:header("yaxi-ticket-id", uuid.uuid4())
  end

  local response = self:_sendRequest(reqBuilder:build())

  local infos = RoutexClient._handleResponse(response) --[[@as YAXI.RoutexClient.ConnectionInfo[] ]]
  return infos
end

---
--- Get information for a service connection
---
---@param options YAXI.RoutexClient.InfoOptions
---@return YAXI.RoutexClient.ConnectionInfo
function RoutexClient:info(options)
  local response = self:_request(options.ticket, string.format("info/%s", options.connectionId), nil)
  local info = RoutexClient._handleResponse(response) --[[@as YAXI.RoutexClient.ConnectionInfo]]
  return info
end

--#endregion RoutexClient:search() / RoutexClient:info()

--#region RoutexClient:accounts()

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

---@private
---@param data [YAXI.RoutexClient.AccountField, string|YAXI.RoutexClient.AccountStatus|YAXI.RoutexClient.AccountType|nil]
---@return [string, string|YAXI.RoutexClient.NULL_MARKER]
function RoutexClient._mapFieldFilter(data)
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

---@private
---@param filter YAXI.RoutexClient.AccountFilter
---@return YAXI.RoutexClient.AccountFilterJSON
function RoutexClient:_mapFilter(filter)
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

--#region RoutexClient:trace()

---Trace identifier returned with the last request
---@return binary?
function RoutexClient:traceId()
  return self._traceId
end

---Retrieve trace data
---@param ticket string YAXI service ticket
---@param traceId binary
---@return string
function RoutexClient:trace(ticket, traceId)
  local traceIdSealed = self._settlement:seal(traceId, {
    ["accept"] = self.MEDIA_TYPE,
    ["user-agent"] = USER_AGENT,
    ["yaxi-ticket-id"] = getTicketID(ticket),
  })
  local traceIdSealedB64 = base64.encodeUrlsafe(traceIdSealed)
  local response = self:_request(ticket, string.format("traces/%s", traceIdSealedB64))
  if response.status >= 400 then
    RoutexClient._handleResponse(response)
    error(UnexpectedError:new(string.format("Failed to retrieve trace for ID %s", traceId)))
  end
  return response.body --[[@as string]]
end

--#endregion

--#region RoutexClient:setRedirectUri()

---
--- Set a redirect URI for subsequent service requests.
---
--- Redirects will eventually forward to that URI.
--- It can be used to redirect back to a web application or to jump
--- back into the context of a desktop or mobile application.
--- If no redirect URI is set, {@link RedirectHandle}s will get returned instead of {@link Redirect}s.
---
---@param redirectUri string
function RoutexClient:setRedirectUri(redirectUri)
  self._redirectUri = redirectUri
end

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

--#endregion RoutexClient:setRedirectUri()

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
  ConsentExpiredError = ConsentExpiredError,
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
