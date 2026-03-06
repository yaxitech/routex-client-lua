-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

local base64 = require("routex-client.util.base64")
local jwt = require("routex-client.jwt")

-- Deep comparison function to assert two tables are equal
local function assertTablesEqual(t1, t2, path)
  path = path or "" -- Use path to track keys in nested tables

  -- If both t1 and t2 are not tables, just compare them directly
  if type(t1) ~= "table" and type(t2) ~= "table" then
    assert(t1 == t2, "Tables are not equal at " .. path .. ": " .. tostring(t1) .. " ~= " .. tostring(t2))
    return
  end

  -- If one of them is a table but the other is not, they are not equal
  if type(t1) ~= "table" or type(t2) ~= "table" then
    assert(false, "Tables are not equal at " .. path .. ": " .. tostring(t1) .. " ~= " .. tostring(t2))
    return
  end

  -- Check if the tables have the same number of keys
  local keys1 = 0
  for _ in pairs(t1) do
    keys1 = keys1 + 1
  end

  local keys2 = 0
  for _ in pairs(t2) do
    keys2 = keys2 + 1
  end

  assert(keys1 == keys2, "Tables have different number of keys at " .. path .. ": " .. keys1 .. " ~= " .. keys2)

  -- Check if all keys and their corresponding values are equal
  for k, v1 in pairs(t1) do
    local v2 = t2[k]
    -- If a key is missing in t2, the tables are not equal
    assert(v2 ~= nil, "Key '" .. k .. "' is missing in second table at " .. path)

    -- Recursively compare nested tables
    assertTablesEqual(v1, v2, path .. "." .. tostring(k))
  end
end

local function jwtDecodeUnverified(token)
  return jwt.decode(token, nil, nil, { verifyExp = false, verifySignature = false })
end

local function getConfig()
  return {
    keyId = os.getenv("KEY_ID") or error("Expected key ID in $KEY_ID environment variable"),
    key = os.getenv("KEY") or error("Expected Base64-encoded key in $KEY environment variable"),
    url = (os.getenv("ROUTEX_URL") or error("Expected URL in $ROUTEX_URL environment variable")):gsub("([/]*)$", ""),
    testSigningKeys = os.getenv("TEST_SIGNING_KEYS")
      and {
        ["dYa685dhHap8RSUtB4DDy1l4UcycsGhklBnV5a/4HSg="] = base64.decode(
          "qzLgDnRegbiQzY416i9/MClrmMp24jcHzaWCWSWSutA="
        ),
      },
  }
end

return {
  assertTablesEqual = assertTablesEqual,
  jwtDecodeUnverified = jwtDecodeUnverified,
  getConfig = getConfig,
}
