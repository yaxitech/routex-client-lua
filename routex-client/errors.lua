-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

local util = require("routex-client.util")
local class = util.class
local super = util.super

---Get file name, line number, function name, and stack trace
---@param level integer?
---@return string? fileName, integer? lineNumber, string? functionName, string? stackTrace
local function getErrorContext(level)
  level = (level or 3)
  local info = debug.getinfo(level, "nSl")
  local fileName = info and info.short_src
  local lineNumber = info and info.currentline
  local functionName = info and (info.name or "<anonymous>")
  local stackTrace = debug.traceback("", level)
  return fileName, lineNumber, functionName, stackTrace
end

---@class YAXI.RoutexClient.Error.Options
---@field fileName string? File or chunk name of the file that raised the error
---@field lineNumber integer? Line number in the file that raised the error
---@field functionName string? Name of the function causing the error
---@field stackTrace string? Stack trace

---@class YAXI.RoutexClient.Error: YAXI.ClassBase
---@field name string Name of the error
---@field message string Error message
---@field options YAXI.RoutexClient.Error.Options
---@field private __index table
local Error = class()

---Create a new instance
---@param name string Name of the error
---@param message string Error message
---@param options YAXI.RoutexClient.Error.Options
---@return YAXI.RoutexClient.Error
function Error:new(name, message, options)
  local obj = setmetatable({}, self)

  local fileName, lineNumber, functionName, stackTrace = getErrorContext(4)
  if not options.fileName then
    options.fileName = fileName
  end
  if not options.lineNumber then
    options.lineNumber = lineNumber
  end
  if not options.functionName then
    options.functionName = functionName
  end
  if not options.stackTrace then
    options.stackTrace = stackTrace
  end

  obj.name = name
  obj.message = message
  obj.options = options

  return obj
end

---String representation of the error
function Error:__tostring()
  local o = self.options or {}
  local location = ""

  if o.fileName then
    location = location .. o.fileName
  end
  if o.lineNumber then
    location = location .. ":" .. o.lineNumber
  end
  if o.functionName then
    location = location .. " (" .. o.functionName .. ")"
  end
  if location ~= "" then
    location = " [" .. location .. "]"
  end

  return string.format("%s: %s%s", self.name, self.message, location)
end

---@class YAXI.RoutexClient.Error.InvalidRedirectUri: YAXI.RoutexClient.Error
local InvalidRedirectUriError = class(Error)

---@param options YAXI.RoutexClient.Error.Options?
---@return YAXI.RoutexClient.Error.InvalidRedirectUri
function InvalidRedirectUriError:new(options)
  ---@type YAXI.RoutexClient.Error.InvalidRedirectUri
  local obj = super(self).new(self, "InvalidRedirectUriError", "Invalid redirect URI", options or {})
  setmetatable(obj, self)
  return obj
end

---@class YAXI.RoutexClient.Error.Request: YAXI.RoutexClient.Error
local RequestError = class(Error)

---@param message string
---@param options YAXI.RoutexClient.Error.Options?
---@return YAXI.RoutexClient.Error.Request
function RequestError:new(message, options)
  ---@type YAXI.RoutexClient.Error.Request
  local obj = super(self).new(self, "RequestError", message, options or {})
  setmetatable(obj, self)
  return obj
end

---@class YAXI.RoutexClient.Error.Unexpected: YAXI.RoutexClient.Error
---@field userMessage string? Description or advice to the user how to deal with the error
local UnexpectedError = class(Error)

---@param userMessage string?
---@param options YAXI.RoutexClient.Error.Options?
---@return YAXI.RoutexClient.Error.Unexpected
function UnexpectedError:new(userMessage, options)
  local message = "Unexpected service error" .. (userMessage and string.format(": %s", userMessage) or "")
  ---@type YAXI.RoutexClient.Error.Unexpected
  local obj = super(self).new(self, "UnexpectedError", message, options or {})
  setmetatable(obj, self)
  obj.userMessage = userMessage
  return obj
end

---@class YAXI.RoutexClient.Error.Canceled: YAXI.RoutexClient.Error
local CanceledError = class(Error)

---@param options YAXI.RoutexClient.Error.Options?
---@return YAXI.RoutexClient.Error.Canceled
function CanceledError:new(options)
  ---@type YAXI.RoutexClient.Error.Canceled
  local obj = super(self).new(self, "CanceledError", "Canceled", options or {})
  setmetatable(obj, self)
  return obj
end

---@class YAXI.RoutexClient.Error.InvalidCredentials: YAXI.RoutexClient.Error
---@field userMessage string? Description or advice to the user how to deal with the error
local InvalidCredentialsError = class(Error)

---@param userMessage string?
---@param options YAXI.RoutexClient.Error.Options?
---@return YAXI.RoutexClient.Error.InvalidCredentials
function InvalidCredentialsError:new(userMessage, options)
  local message = "Invalid credentials" .. (userMessage and string.format(": %s", userMessage) or "")
  ---@type YAXI.RoutexClient.Error.InvalidCredentials
  local obj = super(self).new(self, "InvalidCredentialsError", message, options or {})
  setmetatable(obj, self)
  obj.userMessage = userMessage
  return obj
end

---@class YAXI.RoutexClient.Error.AccessExceeded: YAXI.RoutexClient.Error
---@field userMessage string? Description or advice to the user how to deal with the error
local AccessExceededError = class(Error)

---@param userMessage string?
---@param options YAXI.RoutexClient.Error.Options?
---@return YAXI.RoutexClient.Error.AccessExceeded
function AccessExceededError:new(userMessage, options)
  local message = "Access exceeded" .. (userMessage and string.format(": %s", userMessage) or "")
  ---@type YAXI.RoutexClient.Error.AccessExceeded
  local obj = super(self).new(self, "AccessExceededError", message, options or {})
  setmetatable(obj, self)
  obj.userMessage = userMessage
  return obj
end

---@enum YAXI.RoutexClient.ServiceBlockedCode
local ServiceBlockedCode = {
  --- Something is not set up for the user, e.g., there are no TAN methods.
  MissingSetup = "MISSING_SETUP",
  --- User attention is required via another channel. Typically the user needs to log into the Online Banking.
  ActionRequired = "ACTION_REQUIRED",
}

---@class YAXI.RoutexClient.Error.ServiceBlocked: YAXI.RoutexClient.Error
---@field code YAXI.RoutexClient.ServiceBlockedCode?
---@field userMessage string? Description or advice to the user how to deal with the error
local ServiceBlockedError = class(Error)

---@param code YAXI.RoutexClient.ServiceBlockedCode?
---@param userMessage string?
---@param options YAXI.RoutexClient.Error.Options?
---@return YAXI.RoutexClient.Error.ServiceBlocked
function ServiceBlockedError:new(code, userMessage, options)
  local message = "Service blocked" .. (userMessage and string.format(": %s", userMessage) or "")
  ---@type YAXI.RoutexClient.Error.ServiceBlocked
  local obj = super(self).new(self, "ServiceBlockedError", message, options or {})
  setmetatable(obj, self)
  obj.code = code
  obj.userMessage = userMessage
  return obj
end

---@class YAXI.RoutexClient.Error.Unauthorized: YAXI.RoutexClient.Error
---@field userMessage string? Description or advice to the user how to deal with the error
local UnauthorizedError = class(Error)

---@param userMessage string?
---@param options YAXI.RoutexClient.Error.Options?
---@return YAXI.RoutexClient.Error.Unauthorized
function UnauthorizedError:new(userMessage, options)
  local message = "Unauthorized" .. (userMessage and string.format(": %s", userMessage) or "")
  ---@type YAXI.RoutexClient.Error.Unauthorized
  local obj = super(self).new(self, "UnauthorizedError", message, options or {})
  setmetatable(obj, self)
  obj.userMessage = userMessage
  return obj
end

---@class YAXI.RoutexClient.Error.ConsentExpired: YAXI.RoutexClient.Error
---@field userMessage string? Description or advice to the user how to deal with the error
local ConsentExpiredError = class(Error)

---@param userMessage string?
---@param options YAXI.RoutexClient.Error.Options?
---@return YAXI.RoutexClient.Error.ConsentExpired
function ConsentExpiredError:new(userMessage, options)
  local message = "Consent expired" .. (userMessage and string.format(": %s", userMessage) or "")
  ---@type YAXI.RoutexClient.Error.ConsentExpired
  local obj = super(self).new(self, "ConsentExpiredError", message, options or {})
  setmetatable(obj, self)
  obj.userMessage = userMessage
  return obj
end

---@class YAXI.RoutexClient.Error.PeriodOutOfBounds: YAXI.RoutexClient.Error
---@field userMessage string? Description or advice to the user how to deal with the error
local PeriodOutOfBoundsError = class(Error)

---@param userMessage string?
---@param options YAXI.RoutexClient.Error.Options?
---@return YAXI.RoutexClient.Error.PeriodOutOfBounds
function PeriodOutOfBoundsError:new(userMessage, options)
  local message = "Period out of bounds" .. (userMessage and string.format(": %s", userMessage) or "")
  ---@type YAXI.RoutexClient.Error.PeriodOutOfBounds
  local obj = super(self).new(self, "PeriodOutOfBoundsError", message, options or {})
  setmetatable(obj, self)
  obj.userMessage = userMessage
  return obj
end

---@enum YAXI.RoutexClient.UnsupportedProductReason
local UnsupportedProductReason = {
  ---The amount is not allowed for the payment product.
  Limit = "LIMIT",
  --- The recipient is not capable to receive the payment product.
  Recipient = "RECIPIENT",
  --- Scheduled payments are not supported.
  Scheduled = "SCHEDULED",
}

---@class YAXI.RoutexClient.Error.UnsupportedProduct: YAXI.RoutexClient.Error
---@field reason YAXI.RoutexClient.UnsupportedProductReason?
---@field userMessage string? Description or advice to the user how to deal with the error
local UnsupportedProductError = class(Error)

---@param reason string?
---@param userMessage string?
---@param options YAXI.RoutexClient.Error.Options?
---@return YAXI.RoutexClient.Error.UnsupportedProduct
function UnsupportedProductError:new(reason, userMessage, options)
  local message = "Unsupported product" .. (userMessage and string.format(": %s", userMessage) or "")
  ---@type YAXI.RoutexClient.Error.UnsupportedProduct
  local obj = super(self).new(self, "UnsupportedProductError", message, options or {})
  setmetatable(obj, self)

  local unsupportedProductReasonMap = {
    Limit = UnsupportedProductReason.Limit,
    Recipient = UnsupportedProductReason.Recipient,
    Scheduled = UnsupportedProductReason.Scheduled,
  }
  obj.reason = unsupportedProductReasonMap[reason] or nil
  obj.userMessage = userMessage

  return obj
end

---@enum YAXI.RoutexClient.PaymentFailedCode
local PaymentFailedCode = {
  LimitExceeded = "LIMIT_EXCEEDED",
  InsufficientFunds = "INSUFFICIENT_FUNDS",
}

---@class YAXI.RoutexClient.Error.PaymentFailed: YAXI.RoutexClient.Error
---@field code YAXI.RoutexClient.PaymentFailedCode?
---@field userMessage string? Description or advice to the user how to deal with the error
local PaymentFailedError = class(Error)

---@param code string?
---@param userMessage? string
---@param options? YAXI.RoutexClient.Error.Options
---@return YAXI.RoutexClient.Error.PaymentFailed
function PaymentFailedError:new(code, userMessage, options)
  local message = "Payment failed" .. (userMessage and string.format(": %s", userMessage) or "")
  ---@type YAXI.RoutexClient.Error.PaymentFailed
  local obj = super(self).new(self, "PaymentFailedError", message, options or {})
  setmetatable(obj, self)

  local paymentFailedCodeMap = {
    LimitExceeded = PaymentFailedCode.LimitExceeded,
    InsufficientFunds = PaymentFailedCode.InsufficientFunds,
  }
  obj.code = paymentFailedCodeMap[code] or nil
  obj.userMessage = userMessage

  return obj
end

---@class YAXI.RoutexClient.Error.UnexpectedValue: YAXI.RoutexClient.Error
local UnexpectedValueError = class(Error)

---@param message string
---@param options? YAXI.RoutexClient.Error.Options
---@return YAXI.RoutexClient.Error.UnexpectedValue
function UnexpectedValueError:new(message, options)
  local obj = super(self).new(self, "UnexpectedValueError", message, options or {})
  setmetatable(obj, self)
  return obj
end

---@enum YAXI.RoutexClient.TicketErrorCode
local TicketErrorCode = {
  --- Missing "yaxi-ticket" header.
  Missing = "Missing",
  --- Invalid ticket.
  Invalid = "Invalid",
  --- Ticket token lacks "kid".
  MissingKey = "MissingKey",
  --- Unknown key.
  UnknownKey = "UnknownKey",
  --- Ticket does not match service.
  Mismatch = "Mismatch",
  --- Ticket is expired.
  Expired = "Expired",
  --- Ticket lifetime is too long.
  InvalidLifetime = "InvalidLifetime",
  --- Expired key.
  ExpiredKey = "ExpiredKey",
  --- Environment mismatch between key and routex.
  KeyEnvironmentMismatch = "KeyEnvironmentMismatch",
}

---@class YAXI.RoutexClient.Error.Ticket: YAXI.RoutexClient.Error
---@field code YAXI.RoutexClient.TicketErrorCode
---@field userMessage string? Description or advice to the user how to deal with the error
local TicketError = class(Error)

---@param code string
---@param message string
---@param options YAXI.RoutexClient.Error.Options?
---@return YAXI.RoutexClient.Error.Ticket
function TicketError:new(code, message, options)
  ---@type YAXI.RoutexClient.Error.Ticket
  local obj = super(self).new(self, "TicketError", message, options or {})
  setmetatable(obj, self)
  obj.code = TicketErrorCode[code] or error(string.format("Unknown TicketErrorCode %s", code))

  return obj
end

---@enum YAXI.RoutexClient.ProviderErrorCode
local ProviderErrorCode = {
  Maintenance = "MAINTENANCE",
}

---@class YAXI.RoutexClient.Error.Provider: YAXI.RoutexClient.Error
---@field code YAXI.RoutexClient.ProviderErrorCode?
---@field userMessage string? Description or advice to the user how to deal with the error
local ProviderError = class(Error)

---@param code string?
---@param userMessage string?
---@param options YAXI.RoutexClient.Error.Options?
---@return YAXI.RoutexClient.Error.Provider
function ProviderError:new(code, userMessage, options)
  local message = "The account-servicing provider indicated a technical error"
    .. (userMessage and string.format(": %s", userMessage) or "")
  ---@type YAXI.RoutexClient.Error.Provider
  local obj = super(self).new(self, "ProviderError", message, options or {})
  setmetatable(obj, self)

  local providerErrorCodeMap = {
    Maintenance = ProviderErrorCode.Maintenance,
  }
  obj.code = providerErrorCodeMap[code] or nil
  obj.userMessage = userMessage

  return obj
end

---@class YAXI.RoutexClient.Error.NotFound: YAXI.RoutexClient.Error
local NotFoundError = class(Error)

---@param text string?
---@param options YAXI.RoutexClient.Error.Options?
---@return YAXI.RoutexClient.Error.NotFound
function NotFoundError:new(text, options)
  local msg = "Not found"
  if text then
    msg = string.format("%s: %s", msg, text)
  end
  ---@type YAXI.RoutexClient.Error.NotFound
  local obj = super(self).new(self, "NotFoundError", msg, options or {})
  setmetatable(obj, self)
  return obj
end

---@class YAXI.RoutexClient.Error.Response: YAXI.RoutexClient.Error
---@field response YAXI.Http.Response
local ResponseError = class(Error)

---@param text string
---@param response YAXI.Http.Response
---@param options YAXI.RoutexClient.Error.Options?
---@return YAXI.RoutexClient.Error.Response
function ResponseError:new(text, response, options)
  local message = string.format("Error response: %s %s", response.status, text)
  ---@type YAXI.RoutexClient.Error.Response
  local obj = super(self).new(self, "ResponseError", message, options or {})
  setmetatable(obj, self)
  obj.response = response
  return obj
end

---@class YAXI.RoutexClient.Error.KeySettlementError: YAXI.RoutexClient.Error
local KeySettlementError = class(Error)

---@param message string
---@param options YAXI.RoutexClient.Error.Options?
---@return YAXI.RoutexClient.Error.KeySettlementError
function KeySettlementError:new(message, options)
  ---@type YAXI.RoutexClient.Error.KeySettlementError
  local obj = super(self).new(self, "KeySettlementError", message, options or {})
  setmetatable(obj, self)
  return obj
end

return {
  -- Error Codes
  PaymentFailedCode = PaymentFailedCode,
  ProviderErrorCode = ProviderErrorCode,
  ServiceBlockedCode = ServiceBlockedCode,
  TicketErrorCode = TicketErrorCode,
  UnsupportedProductReason = UnsupportedProductReason,

  Error = Error,
  -- RoutexClient Error classes
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

  -- KeySettlement
  KeySettlementError = KeySettlementError,
}
