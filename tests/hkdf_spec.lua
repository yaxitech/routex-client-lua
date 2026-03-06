-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

require("tests.init")

local hmac = require("routex-client.vendor.tls13.crypto.hmac")
local sha2 = require("routex-client.vendor.tls13.crypto.hash.sha2")
local hmacSha256 = hmac.hmac(sha2.sha256)
local HKDF = require("routex-client.crypto.hkdf").HKDF
local util = require("routex-client.vendor.tls13.util")

---@class HKDFTestCase
---@field label string
---@field ikm string
---@field salt string
---@field info string
---@field length integer
---@field mod table
---@field expected string

---@type HKDFTestCase[]
local test_cases = {
  {
    label = "RFC 5869 - Test Case 1 (SHA-256)",
    ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    salt = "000102030405060708090a0b0c",
    info = "f0f1f2f3f4f5f6f7f8f9",
    length = 42,
    mod = hmacSha256,
    expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
  },
  {
    label = "RFC 5869 - Test Case 2 (SHA-256, long inputs)",
    ikm = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
            202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
            404142434445464748494a4b4c4d4e4f]],
    salt = [[606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf]],
    info = [[b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff]],
    length = 82,
    mod = hmacSha256,
    expected = [[b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c
                 59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71
                 cc30c58179ec3e87c14c01d5c1f3434f1d87]],
  },
  {
    label = "RFC 5869 - Test Case 3 (SHA-256, zero salt/info)",
    ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    salt = "",
    info = "",
    length = 42,
    mod = hmacSha256,
    expected = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
  },
}

--- Clean hex strings (multiline-friendly)
local function normalize_hex(hex)
  return hex:gsub("[%s\n]", "")
end

for _, tc in ipairs(test_cases) do
  test(tc.label, function()
    local ikm = util.fromHex(normalize_hex(tc.ikm))
    local salt = util.fromHex(normalize_hex(tc.salt or ""))
    local info = util.fromHex(normalize_hex(tc.info or ""))
    local expected = normalize_hex(tc.expected)

    local okm = HKDF:new(tc.mod, tc.length, salt, info):derive(ikm)

    local result = util.toHex(okm)
    assert(result == expected, string.format("FAILED: %s\nExpected: %s\nActual:   %s", tc.label, expected, result))
  end)
end
