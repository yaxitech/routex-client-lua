-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

local base64 = require("routex-client.util.base64")

local function super(class)
  local mt = getmetatable(class)
  return mt and mt.__index or nil
end

---@class YAXI.ClassBase
---@field new fun(self: YAXI.ClassBase)
---@field isInstanceOf fun(self: YAXI.ClassBase, class: table): boolean
---@field toString fun(self: YAXI.ClassBase): string
---@field protected _super YAXI.ClassBase

---Define a new class with optional inheritance
---@param base table? Base class (optional)
---@return YAXI.ClassBase @The new class
local function class(base)
  local cls = {}
  cls.__index = cls
  cls._super = base

  ---Default constructor
  function cls:new() ---@diagnostic disable-line: unused
    local obj = setmetatable({}, cls)
    return obj
  end

  --- Check if this is an instance of the given class
  --- @param clazz table The class to check against
  --- @return boolean
  function cls:isInstanceOf(clazz)
    local mt = getmetatable(self)
    while mt do
      if mt == clazz then
        return true
      end
      mt = mt._super
    end
    return false
  end

  function cls:toString()
    return string.format("<object at %s>", tostring(rawget(self, "__address") or "??"))
  end

  function cls:__tostring()
    return self:toString()
  end

  setmetatable(cls, {
    __index = base,
    __call = function(c, ...)
      return c:new(...)
    end,
  })

  return cls --[[@as YAXI.ClassBase]]
end

---Splits a string by a delimiter
---http://lua-users.org/wiki/SplitJoin
---@param str string
---@param delimiter string
---@return string[]
local function split(str, delimiter)
  assert(type(str) == "string", "split: `str` must be a string, not " .. type(str))
  local t, ll
  t = {}
  ll = 0
  if #str == 1 then
    return { str }
  end
  while true do
    local l = string.find(str, delimiter, ll, true)
    if l ~= nil then
      table.insert(t, string.sub(str, ll, l - 1))
      ll = l + 1
    else
      table.insert(t, string.sub(str, ll))
      break
    end
  end
  return t
end

---Decode a PEM-encoded X.509 certificate to DER
---@param pem string
local function derFromPem(pem)
  local header = "-----BEGIN CERTIFICATE-----"
  local footer = "-----END CERTIFICATE-----"

  -- Remove leading whitespace (indentation)
  pem = pem:gsub("\r", "")
  pem = pem:gsub("^[%s]+", "\n")
  pem = pem:gsub("\n[%s]+", "\n")
  -- Remove comments
  pem = pem:gsub("^#[^\n]*", "")
  pem = pem:gsub("\n#[^\n]*", "")
  -- Join all lines
  pem = pem:gsub("\n", "")

  local start = pem:find(header) or error("Failed to find PEM certificate header")
  start = start + #header
  local ending = pem:find(footer) or error("Failed to find PEM certificate footer")
  ending = ending - 1

  local derBase64 = pem:sub(start, ending)
  local der, err = base64.decode(derBase64)
  if der == nil then
    error(string.format("Failed to Base64-decode PEM: %s", err))
  end

  return der
end

local function keys(tbl)
  local res = {}
  for k, _ in pairs(tbl) do
    table.insert(res, k)
  end
  return res
end

local function isAscii(str)
  return str:match("^[\x20-\x7E]*$") ~= nil
end

local function sortKeyValueTable(tbl)
  -- Step 1: Create a list of key-value pairs
  local sortedPairs = {}
  for key, value in pairs(tbl) do
    table.insert(sortedPairs, { key = key, value = value })
  end

  -- Step 2: Sort the key-value pairs by the key (lexically)
  table.sort(sortedPairs, function(a, b)
    return tostring(a.key) < tostring(b.key)
  end)

  -- Step 3: Create an indexed table with sorted pairs
  local indexedTable = {}
  for _, pair in ipairs(sortedPairs) do
    table.insert(indexedTable, { [pair.key] = pair.value })
  end

  return indexedTable
end

local function propsToMsg(tbl, level)
  level = level or 1
  local elems = {}
  local leaf = false

  local lastIndex = 0
  for k, v in pairs(tbl) do
    if k == lastIndex + 1 and type(v) == "table" then
      lastIndex = lastIndex + 1
    else
      lastIndex = -1
      break
    end
  end
  local isIndexed = lastIndex == #tbl

  if isIndexed then
    for _, v in ipairs(tbl) do
      table.insert(elems, propsToMsg(v, level))
    end
  else
    for k, v in pairs(tbl) do
      if type(v) == "table" then
        table.insert(elems, ("%s: %s"):format(k, propsToMsg(v, level + 1)))
      else
        local displayVal = v
        if type(v) == "string" and not isAscii(v) then
          displayVal = base64.encode(v)
        end
        table.insert(elems, ("%s: %s"):format(k, displayVal))
        leaf = true
      end
    end
  end

  local braces = {
    { "(", ")" },
    { "[", "]" },
    { "{", "}" },
  }

  if #elems == 1 and leaf then
    return elems[1]
  else
    local brace
    if level == 1 then
      brace = { "", "" }
    else
      brace = braces[(level - 1) % #braces] ---@diagnostic disable-line: undefined-field
    end
    return ("%s%s%s"):format(brace[1], table.concat(elems, ", "), brace[2])
  end
end

return {
  class = class,
  super = super,
  split = split,
  derFromPem = derFromPem,
  keys = keys,
  sortKeyValueTable = sortKeyValueTable,
  propsToMsg = propsToMsg,
}
