-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

require("tests.init")

local ticket = require("tests.ticket")

test("Get Ticket ID", function()
  local ticketId = ticket.getId(
    "eyJhbGciOiJIUzI1NiIsImtpZCI6IjY1Yjc5MDZkLTc4OGQtNDgxMy04M2U1LWFlZjliZDVjMjY5ZiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7InNlcnZpY2UiOiJDb2xsZWN0UGF5bWVudCIsImlkIjoiYzgzMjczNTAtMzhjMi00NGU1LWI5OWYtNTNmM2NmOWU3NjBiIiwiZGF0YSI6eyJhbW91bnQiOnsiY3VycmVuY3kiOiJFVVIiLCJhbW91bnQiOiIxMDAifSwiY3JlZGl0b3JBY2NvdW50Ijp7ImliYW4iOiJOTDU4WUFYSTEyMzQ1Njc4OTAifSwiY3JlZGl0b3JOYW1lIjoiWUFYSSBHbWJIIiwicmVtaXR0YW5jZSI6IlNpZ24tdXAgZmVlIHJvdXRleCAxMjM0NTY3ODkifX0sImV4cCI6MTczMjcxODg5M30.N0W7MP6dkyXGeeCkwnZISX-Uh79o0HDkgy4hH5_XMII"
  )
  assert.same(ticketId, "c8327350-38c2-44e5-b99f-53f3cf9e760b")
end)

test("Ticket issuing", function()
  local res = ticket.issue(
    "wurzelpfropf",
    "this-is-very-secret",
    "DC7C99C5-06E0-4E0F-85DA-6789D2C4CAAB",
    "Accounts",
    {},
    1755180558
  )
  assert.is_not.nil_(res)
end)
