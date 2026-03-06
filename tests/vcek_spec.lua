-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

require("tests.init")

local base64 = require("routex-client.util.base64")
local util = require("routex-client.util")

local Vcek = require("routex-client.attestation.vcek").Vcek
local VcekGeneration = require("routex-client.attestation.vcek").VcekGeneration

context("VCEK parsing", function()
  for _, name in ipairs({ VcekGeneration.Milan, VcekGeneration.Genoa, VcekGeneration.Turin }) do
    local vcekChainFile = ("tests/data/vcek-chain-%s.pem"):format(name:lower())
    local f = io.open(vcekChainFile, "r") or error(("Failed open file %s"):format(vcekChainFile))
    local pem = f:read("a")

    test("Verify " .. name, function()
      local sevVcek = Vcek:new(pem)
      assert.is_nil(sevVcek.verifiedAt)
      sevVcek:verify()
      assert.is_not_nil(sevVcek.verifiedAt)

      assert.same("SEV-VCEK", sevVcek.commonName)
      assert.same(VcekGeneration[name], sevVcek.vcekGeneration)
      assert.is_table(sevVcek:getPublicKey())
    end)
  end

  test("Rejects invalid SEV-VCEK", function()
    local vcekDerGenoaWithTurinProduct = base64.decode(
      "MIIFPzCCAvOgAwIBAgIBADBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAgUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATAwezEUMBIGA1UECwwLRW5naW5lZXJpbmcxCzAJBgNVBAYTAlVTMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExHzAdBgNVBAoMFkFkdmFuY2VkIE1pY3JvIERldmljZXMxEjAQBgNVBAMMCVNFVi1HZW5vYTAeFw0yNTA3MjAyMjE1NDJaFw0zMjA3MjAyMjE1NDJaMHoxFDASBgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZpY2VzMREwDwYDVQQDDAhTRVYtVkNFSzB2MBAGByqGSM49AgEGBSuBBAAiA2IABEqwpvnwhedRKh5aFKoVIchssOMEnyyvkIst3gYQy4yFPKlO45jU8NEOb0ZOqohPEFqAwIksjd/E+hKvHJExp6mRpCuVgZvDva+7x+eqdpyi3PsLifYM1v8jeIbzkD5Fu6OCARMwggEPMBAGCSsGAQQBnHgBAQQDAgEAMBQGCSsGAQQBnHgBAgQHFgVUdXJpbjARBgorBgEEAZx4AQMBBAMCAQkwEQYKKwYBBAGceAEDAgQDAgEAMBEGCisGAQQBnHgBAwQEAwIBADARBgorBgEEAZx4AQMFBAMCAQAwEQYKKwYBBAGceAEDBgQDAgEAMBEGCisGAQQBnHgBAwcEAwIBADARBgorBgEEAZx4AQMDBAMCARcwEQYKKwYBBAGceAEDCAQDAgFIME0GCSsGAQQBnHgBBARAncmZYsBjAp5DC297c0B17FQvTz7GOeZX4UWF0/5VmzhTK8QtA31hgxdpStZjTSUHlk4nbI7t6sSXjHAGv4n44TBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAgUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATADggIBAFjFVeDT5plRhqsiF0HDe0xxQuZhBluhJDztxjT190niD4nHJJPYomfagjny8/X7vKjJbEbMU8tfISo6pUt0S731d9X6YUWDWSmvEtFlgv7A3ytMkSRtotoN2xc8WiLaW13ZTIF94WKsspVXqaQobsJgXZUOwha22f5a7tyvb+BHq5YLgmxJ/IBrbBiLfNIjRlE9Ne4HWmuuYObD550UgpR8bqVbfGA9C5SfMsPpnCM4wKL5gPcWqQK41EP8ogqpW0PImSFWZG3Ii243r5yJADtmEvlDpod5fGUU5oRcWsd38WGaxqm/NJyddr5mB6GsoE2K/QJ02DdOsXpfITttUWHve9VA5KicTEDx4LpauqPVKDcQlHzRye0cvOkn0mXbxoIsXjBVetyYhpfzvawIgc877Pn18nCU0iV9V2jKOHAyhNiN8K1iEzwK8ZFudREmP3h77GOIQOCVrM8Iwr+0oURczJZ157ghFkUe5Oup6PhPLxceBRE6MnBi3N9QWRXBC589fk1bUYruNI+bo+tQFryU4BkqNm8cYVn0+QBk3XmjcxLQRd7NoYCDQSmDqUFrPu4CcI20dOxHD9GkbYCV0i3Mvkc7MvqWs6F8+owq0Wnh3jJXPZEZ58Pywo7kDIjaHPhwAdLR56WUgZgIqjxGvmggKamRBXix4//l2p7wCKkz"
    )
    assert(vcekDerGenoaWithTurinProduct)
    local sevVcek = Vcek:new(vcekDerGenoaWithTurinProduct)
    assert.error_match(function()
      sevVcek:verify()
    end, "Expected issuer SEV-Genoa, got: SEV-Turin", nil, true)
  end)

  test("Rejects invalid SEV-VCEK signature", function()
    local pem = io.open("tests/data/vcek-chain-genoa.pem", "r"):read("a")
    local der = util.derFromPem(pem) --[[@as string]]
    local wrzl = "wrzl"
    local derInvalidSig = der:sub(1, -1 * #wrzl - 1) .. "wrzl"
    local sevVcek = Vcek:new(derInvalidSig)
    assert.error_match(function()
      sevVcek:verify()
    end, "Failed to verify certificate SEV-VCEK with issuer SEV-Genoa: invalid signature", nil, true)
  end)
end)
