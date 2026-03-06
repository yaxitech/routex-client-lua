-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

require("tests.init")
local jwt = require("routex-client.jwt")

test("JWT decoding/encoding", function()
  local token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    .. "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0."
    .. "KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"
  local key = "a-string-secret-at-least-256-bits-long"

  -- Expected payload
  local expected_claims = {
    sub = "1234567890",
    name = "John Doe",
    admin = true,
    iat = 1516239022,
  }

  assert.same(expected_claims, jwt.decode(token, key))

  local encoded_jwt = jwt.encode(expected_claims, key, "HS256")
  jwt.decode(encoded_jwt, key, "HS256", { verifyExp = true })
end)
