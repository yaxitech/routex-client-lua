-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

require("tests.init")
local helpers = require("tests.helpers")
local uuid = require("routex-client.util.uuid")
local KeySettlement = require("routex-client").KeySettlement
local base64 = require("routex-client.util.base64")

context("Key settlement #online", function()
  local config = helpers.getConfig()

  test("Basic", function()
    local url = ("%s/key-settlement"):format(config.url)
    local settlement = KeySettlement:new(url, config.testSigningKeys)
    local sessionId = settlement:getBase64SessionId({
      ["yaxi-ticket-id"] = uuid.uuid4(),
    })

    assert(
      sessionId and #sessionId == 44 and #base64.decode(sessionId) == 32,
      string.format("Expected 32 bytes Base64-encoded session ID, got: %s", sessionId)
    )
    assert(settlement:systemVersion(), "Expected a system version")
  end)

  test("Rejects invalid report data", function()
    local RemoteAttestation = require("routex-client.attestation").RemoteAttestation
    RemoteAttestation._verifySignature = function()
      return true
    end
    local realVerify = RemoteAttestation.verify
    RemoteAttestation.verify = function(self)
      self.report.reportData = ("\x00"):rep(64)
      realVerify(self)
    end

    local url = ("%s/key-settlement"):format(config.url)
    local settlement = KeySettlement:new(url, config.testSigningKeys)
    local headers = {
      ["yaxi-ticket-id"] = uuid.uuid4(),
    }

    local ok, err = pcall(function()
      settlement:getBase64SessionId(headers)
    end)
    assert.is_false(ok)
    assert.same("KeySettlementError", err.name)
    assert.same("Attestation report doesn't match the SHA-256 digest of chacha box", err.message)
  end)
end)
