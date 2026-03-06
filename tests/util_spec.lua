local util = require("routex-client.util")

test("propsToMsg", function()
  local props = {
    { wuff = "miau" },
    {
      wurzel = {
        pfropf = {
          { kaese = "kuchen" },
          { lecker = "123" },
        },
      },
    },
  }
  local actual = util.propsToMsg(props)
  assert.same("wuff: miau, wurzel: (pfropf: [kaese: kuchen, lecker: 123])", actual)

  assert.same(
    "This should work: miau",
    util.propsToMsg({
      ["This should work"] = "miau",
    })
  )

  assert.same(
    "1: wuff, 2: miau, 3: schlabber",
    util.propsToMsg({
      "wuff",
      "miau",
      "schlabber",
    })
  )

  assert.same(
    "wurzel: BAEDAwc=",
    util.propsToMsg({
      wurzel = "\x04\x01\x03\x03\x07",
    })
  )
end)

test("sortKeyValueTable", function()
  assert.same(
    {
      { a = "b" },
      { c = "d" },
      { e = "f" },
    },
    util.sortKeyValueTable({
      c = "d",
      e = "f",
      a = "b",
    })
  )
end)

context("util.date", function()
  local dateutil = require("routex-client.util.date")

  test("date without time", function()
    ---@type osdate
    local dt = {
      year = 2026,
      month = 02,
      day = 02,
      hour = nil,
      min = nil,
      sec = nil,
      wday = nil,
      yday = nil,
      isdst = nil,
    }
    local formatted = dateutil.formatDate(dt)
    assert.equal("2026-02-02", formatted)
  end)

  test("date with time", function()
    ---@type osdate
    local dt = {
      year = 2026,
      month = 02,
      day = 02,
      hour = 08,
      min = 26,
      sec = 04,
      wday = 2,
      yday = 33,
      isdst = false,
    }
    local formatted = dateutil.formatDate(dt)
    assert.equal("2026-02-02T08:26:04Z", formatted)
  end)
end)
