-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

-- Responses returned by interactive YAXI Open Banking services: the
-- [`Result`](lua://YAXI.RoutexClient.Result) carrying the service data, plus the
-- [interrupts](https://docs.yaxi.tech/interrupts.html) that require user action
-- before the flow can continue ([`Dialog`](lua://YAXI.RoutexClient.Dialog),
-- [`Redirect`](lua://YAXI.RoutexClient.Redirect) and
-- [`RedirectHandle`](lua://YAXI.RoutexClient.RedirectHandle)).

-- Logging setup
local log = require("routex-client.logging").defaultLogger()
  or error("Failed to get default logger. Did you initialize it?")

local util = require("routex-client.util")
local super = util.super
local class = util.class

local jsonEncode = require("routex-client.vendor.json").encode

local base64Decode = require("routex-client.util.base64").decode

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

return {
  -- Classes
  OBResponse = OBResponse,
  Confirmation = Confirmation,
  Dialog = Dialog,
  Field = Field,
  Redirect = Redirect,
  RedirectHandle = RedirectHandle,
  Result = Result,
  Selection = Selection,

  -- Enums
  DialogContext = DialogContext,
  InputType = InputType,
  SecrecyLevel = SecrecyLevel,
}
