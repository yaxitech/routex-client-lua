-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

local errors = require("routex-client.errors")
local log = require("routex-client.logging").defaultLogger()
local ResponseError = errors.ResponseError
local KeySettlementError = errors.KeySettlementError

local RemoteAttestation = require("routex-client.attestation").RemoteAttestation

local base64 = require("routex-client.util.base64")
local chachaBoxIetf = require("routex-client.crypto.chacha_box_ietf")
local ed25519 = require("routex-client.vendor.tls13.sigalg").makeEd25519SigAlg()
local http = require("routex-client.http")
local json = require("routex-client.vendor.json")
local sha2 = require("routex-client.vendor.tls13.crypto.hash.sha2")

local util = require("routex-client.util")

---Builtin YAXI system version signing keys
---@type [string, string]
local YaxiSigningKeys = {
  ["AhrUXsV/XAvIE24RQ/Vt/zXoLodvjXoWD2fhLGuRM7U="] = base64.decode("ZbxMIfWbKk/WtX0xRIVX6Htb0RXvJMPXUoygw+xvtOI="),
  ["D30zRYe8Ug9732b4Pe2BAwWAXn/T5Nss2HJOp3kLC1w="] = base64.decode("CMtrYRGMEPAdxWgas3NWAtJJa9MuIlmudcF+1wyFaiU="),
}

---@class YAXI.KeySettlement.SettlementResponse.SystemVersion.Signature
---@field keyId string
---@field value string

---@class YAXI.KeySettlement.SettlementResponse.SystemVersion
---@field kind "release"|string
---@field generation integer
---@field createdAt string
---@field ref string
---@field launchMeasurement string
---@field signature YAXI.KeySettlement.SettlementResponse.SystemVersion.Signature

---@class YAXI.KeySettlement.SettlementResponse
---@field attestationReport string Base64-encoded attestation report
---@field vcek string Base64-encoded VCEK
---@field chachaBox string Base64-encoded ciphertext
---@field systemVersion YAXI.KeySettlement.SettlementResponse.SystemVersion

---@alias YAXI.KeySettlement.ServerKey { publicKey: YAXI.Crypto.PublicKey, base64SessionId: string }

---@class YAXI.KeySettlement: YAXI.ClassBase
---@field private _url string
---@field private _httpClient YAXI.Http.IClient
---@field private _secretKey YAXI.Crypto.SecretKey
---@field private _serverKey YAXI.KeySettlement.ServerKey?
---@field private _systemVersion YAXI.KeySettlement.SettlementResponse.SystemVersion?
---@field private _signingKeys table<string, string> Map from key ID to public key
local KeySettlement = util.class()

---Create a new instance
---@param url string
---@param signingKeys table<string, string>? Map from key ID to public key; defaults to builtin keys
---@param httpClient YAXI.Http.IClient? If `nil`, uses a default client based on `lua-http`
---@return YAXI.KeySettlement
function KeySettlement:new(url, signingKeys, httpClient)
  local obj = setmetatable({}, self)
  obj._url = url
  obj._signingKeys = signingKeys or YaxiSigningKeys
  obj._httpClient = httpClient or http.DefaultHttpClient:new()
  obj._secretKey = chachaBoxIetf.SecretKey.generate()
  obj._serverKey = nil
  obj._systemVersion = nil
  log:debug("Key settlement URL: %s", url)
  return obj
end

---Perform a new key settlement
---@param headers table<string, string>?
function KeySettlement:_settle(headers)
  local payload = { publicKey = base64.encode(self._secretKey:publicKey():publicBytesRaw()) }
  local request = http.Request:builder(self._url):headers(headers or {}):method("POST"):json(payload):build()

  log:debug("Settlement request: \n%s", request)

  local response = self._httpClient:request(request)
  if response.status >= 400 then
    error(ResponseError:new("Key settlement failed", response))
  end

  local ok, r = pcall(json.decode, response.body)
  if not ok then
    error(string.format("Failed to JSON-decode key settlement response: %s\n%s", r, json.encode(response)))
  end

  local keySettlementResponse = r --[[@as YAXI.KeySettlement.SettlementResponse]]
  self._systemVersion = self:_verifySystemVersion(keySettlementResponse)

  local chachaBox = base64.decode(keySettlementResponse.chachaBox)
  assert(chachaBox, "Expected valid chacha box bytes")

  local settlementBoxMessage = json.decode(self._secretKey:unseal(chachaBox))
  local serverPublicKeyRaw = base64.decode(settlementBoxMessage.publicKey)
  assert(serverPublicKeyRaw, "Expected valid server public key bytes")
  self._serverKey = {
    publicKey = chachaBoxIetf.PublicKey:fromPublicBytes(serverPublicKeyRaw),
    base64SessionId = settlementBoxMessage.sessionId,
  }
end

---Retrieve the server key
---@param settlementHeaders table<string, string>?
---@return YAXI.KeySettlement.ServerKey
function KeySettlement:_getServerKey(settlementHeaders)
  if not self._serverKey then
    self:_settle(settlementHeaders)
  end
  assert(self._serverKey, "Expected settled server key")
  return self._serverKey
end

---Get the Base64-encoded session ID
---@param settlementHeaders table<string, string>?
---@return string
function KeySettlement:getBase64SessionId(settlementHeaders)
  local serverKey = self:_getServerKey(settlementHeaders)
  return serverKey.base64SessionId
end

---Seal the plaintext
---@param plaintext binary
---@param settlementHeaders table<string, string>?
---@return binary
function KeySettlement:seal(plaintext, settlementHeaders)
  local serverKey = self:_getServerKey(settlementHeaders)
  local ciphertext = serverKey.publicKey:seal(plaintext)
  return ciphertext
end

function KeySettlement:unseal(ciphertext)
  local plaintext = self._secretKey:unseal(ciphertext)
  return plaintext
end

---@param systemVersion YAXI.KeySettlement.SettlementResponse.SystemVersion
function KeySettlement:_verifySystemVersionSignature(systemVersion)
  local keyId = systemVersion.signature.keyId
  ---@diagnostic disable-next-line undefined-field
  local signingKey = self._signingKeys[keyId]
    or error(KeySettlementError:new(string.format("Could not find a trusted signing key with ID %s", keyId)))
  local measurement = base64.decode(systemVersion.launchMeasurement)
    or error(KeySettlementError:new("Failed to Base64-decode system version launch measurement"))
  local signature = base64.decode(systemVersion.signature.value)
    or error(KeySettlementError:new("Failed to Base64-decode system version signature"))
  local signingPayload = systemVersion.kind
    .. systemVersion.generation
    .. systemVersion.createdAt:gsub("Z", "+00:00")
    .. systemVersion.ref
    .. measurement
  local valid = ed25519:verify(signingKey, signingPayload, signature)
  if not valid then
    error(KeySettlementError:new(string.format("Invalid system version signature (key %s)", keyId)))
  end
end

---@param response YAXI.KeySettlement.SettlementResponse
---@return YAXI.Attestation.RemoteAttestation
function KeySettlement._verifyMeasurement(response)
  -- Verify VCEK and attestation report
  local reportBytes = base64.decode(response.attestationReport)
    or error(KeySettlementError:new("Failed to Base64-decode attestation report"))
  local ok, res = pcall(function()
    return RemoteAttestation:new(response.vcek, reportBytes)
  end)
  if not ok then
    error(KeySettlementError:new(("Failed to verify remote attestation: %s"):format(res)))
  end
  local attestation = res

  -- Make sure system version measurement and report measurement match
  local launchMeasurement = base64.decode(response.systemVersion.launchMeasurement)
    or error(KeySettlementError:new("Failed to Base64-decode system version launch measurement"))
  local report = attestation.report or error(KeySettlementError:new("Attestation is missing report"))
  if launchMeasurement ~= report.measurement then
    error(
      KeySettlementError:new(
        string.format(
          "Failed to verify YAXI routex measurement. Expected %s, got: %s",
          launchMeasurement,
          report.measurement
        )
      )
    )
  end
  log:debug("Verified launch measurement in system version matches report's launch measurement")

  return attestation --[[@as YAXI.Attestation.RemoteAttestation]]
end

---Verify the system version (signature, measurement)
---@param response YAXI.KeySettlement.SettlementResponse
---@return YAXI.KeySettlement.SettlementResponse.SystemVersion
function KeySettlement:_verifySystemVersion(response)
  local systemVersion = response.systemVersion
    or error(KeySettlementError:new("Settlement response lacks system version"))

  self:_verifySystemVersionSignature(systemVersion)
  local attestation = self._verifyMeasurement(response)

  -- Verify attestation report data
  local chachaBox = base64.decode(response.chachaBox)
    or error(KeySettlementError:new("Failed to Base64-decode chacha box"))
  local chachaBoxSha256 = sha2.sha256():update(chachaBox):finish()
  if chachaBoxSha256 ~= attestation.report.reportData:sub(1, sha2.sha256.HASH_SIZE) then
    error(KeySettlementError:new("Attestation report doesn't match the SHA-256 digest of chacha box"))
  end

  KeySettlement._logInfo(systemVersion, attestation)

  return systemVersion
end

---Log infos about a successfully verified key settlement
---@param systemVersion YAXI.KeySettlement.SettlementResponse.SystemVersion
---@param attestation YAXI.Attestation.RemoteAttestation
function KeySettlement._logInfo(systemVersion, attestation)
  local committedVersion = ("%s.%s.%s"):format(
    attestation.report.committed.major,
    attestation.report.committed.minor,
    attestation.report.committed.build
  )

  local msg = util.propsToMsg({
    { ["created at"] = systemVersion.createdAt },
    { ["measurement"] = systemVersion.launchMeasurement },
    { ["SEV-SNP generation"] = attestation.vcek.vcekGeneration },
    {
      ["patch level"] = {
        ["version"] = committedVersion,
        ["TCB"] = util.sortKeyValueTable(attestation.report.committedTcb),
      },
    },
  })
  log:info("YAXI routex system version verified: " .. msg)
end

---System version for the currently established session.
---@return YAXI.KeySettlement.SettlementResponse.SystemVersion?
function KeySettlement:systemVersion()
  return self._systemVersion
end

return KeySettlement
