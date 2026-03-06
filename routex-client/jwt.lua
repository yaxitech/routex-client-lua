-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

local base64 = require("routex-client.util.base64")
local hmac = require("routex-client.vendor.tls13.crypto.hmac")
local json = require("routex-client.vendor.json")
local sha2 = require("routex-client.vendor.tls13.crypto.hash.sha2")
local hmacSha256 = hmac.hmac(sha2.sha256)
local util = require("routex-client.util")

---Verify the `jwt` token signature and return the token claims.
---
---**WARNING**: This won't verify JWTs beyond its signature and `exp` claim
---@param jwt string The token to be decoded
---@param key binary? The key suitable for the `algorithm`. If `nil`, skips verification
---@param algorithm "HS256"|nil The algorithm to verify with; only HS256 is currently supported
---@param options { verifySignature: boolean, verifyExp: boolean }? Additional options
---@return table<string, any> @JWT claims
local function decode(jwt, key, algorithm, options)
  if algorithm and algorithm ~= "HS256" then ---@diagnostic disable-line: unnecessary-if
    error("Currently only supports HS256")
  end

  local parts = util.split(jwt, ".")
  assert(#parts == 3, "Expected the JWT to consist of three dot-separated parts")

  -- Verify the header data
  local headerJson = base64.decode(parts[1]) or error("Could not Base64-decode the JWT header")
  local headers = json.decode(headerJson)

  if headers.typ ~= "JWT" then
    error(string.format("Expected a token with a header `typ` of `JWT`, got: %s", headers.typ))
  end
  if algorithm and headers.alg ~= algorithm then
    error(string.format("Unsupported or mismatched algorithm in JWT header: %s", headers.alg))
  end

  local verifySignature = true
  if options and options.verifySignature == false then
    verifySignature = false
  end
  if verifySignature and not key then
    error("Requested JWT signature verification but no key given")
  end

  if verifySignature then
    local msg = string.format("%s.%s", parts[1], parts[2])
    local expectedSignature = hmacSha256(msg, key)
    local actualSignature = base64.decode(parts[3]) or error("Could not Base64-decode the JWT signature")
    if actualSignature ~= expectedSignature then
      error("Failed to verify JWT signature")
    end
  end

  local payload = base64.decode(parts[2]) or error("Could not Base64-decode the JWT payload")
  local claims = json.decode(payload)

  local verifyExp = true
  if options and options.verifyExp == false then
    verifyExp = false
  end
  if verifyExp and claims.exp then
    local now = os.time()
    if claims.exp < now then
      error(string.format("JWT has expired: %s < %s", claims.exp, now))
    end
  end

  return claims
end

---Encode the `payload` as JWT
---@param payload table<string, any> JWT claims
---@param key binary Secret key to sign with `algorithm`
---@param algorithm "HS256" Signing algorithm; only HS256 is currently supported
---@param headers table? Extra headers apart from `alg` and `typ`
---@param nullVal string? Lua pattern passed to `gsub` to replace matching values with `null`; may require escaping
---@return string
local function encode(payload, key, algorithm, headers, nullVal)
  if algorithm and algorithm ~= "HS256" then ---@diagnostic disable-line: unnecessary-if
    error("Currently only supports HS256")
  end

  local allHeaders = {
    alg = algorithm,
    typ = "JWT",
  }
  for k, v in pairs(headers or {}) do
    allHeaders[k] = v
  end

  local jwtHeader = json.encode(allHeaders)
  local jwtHeaderB64 = base64.encodeUrlsafe(jwtHeader)

  local jwtPayload = json.encode(payload)
  if nullVal then
    local pattern = string.format('"%s"', nullVal)
    jwtPayload = jwtPayload:gsub(pattern, "null")
  end
  local jwtPayloadB64 = base64.encodeUrlsafe(jwtPayload)

  local msg = string.format("%s.%s", jwtHeaderB64, jwtPayloadB64)
  local signature = hmacSha256(msg, key)
  local signatureB64 = base64.encodeUrlsafe(signature)

  local jwt = string.format("%s.%s", msg, signatureB64)

  return jwt
end

return {
  decode = decode,
  encode = encode,
}
