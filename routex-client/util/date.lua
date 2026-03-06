-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

---@alias osdate {year: integer, month: integer, day: integer, hour: integer?, min: integer?, sec: integer?}
---@alias RFC3339 string @Format: "YYYY-MM-DDTHH:MM:SSZ"
---@alias SimpleDate string @Format: "YYYY-MM-DD"

---Formats an os.date table into a string.
---Returns "YYYY-MM-DD" if time fields are nil, or RFC3339 if time is present.
---Assumes the input date is in UTC.
---Throws an error if the input is invalid.
---@param dt osdate
---@return SimpleDate | RFC3339
local function formatDate(dt)
  -- 1. Validate Input Type
  if type(dt) ~= "table" then
    error("Invalid argument: expected 'osdate' table, got " .. type(dt))
  end

  -- 2. Validate Required Fields (Date components)
  local required = { "year", "month", "day" }
  for _, field in ipairs(required) do
    if type(dt[field]) ~= "number" then
      error(string.format("Invalid date: missing or invalid field '%s'", field))
    end
  end

  -- 3. Validate Ranges (Basic sanity check)
  if dt.month < 1 or dt.month > 12 then
    error("Invalid month: " .. dt.month)
  end
  if dt.day < 1 or dt.day > 31 then
    error("Invalid day: " .. dt.day)
  end

  -- 4. Check for Time Components
  local hasTime = (type(dt.hour) == "number") and (type(dt.min) == "number") and (type(dt.sec) == "number")

  if not hasTime then
    -- Return simple date string
    return string.format("%04d-%02d-%02d", dt.year, dt.month, dt.day)
  else
    -- 5. Validate Time Ranges
    if dt.hour < 0 or dt.hour > 23 then
      error("Invalid hour: " .. dt.hour)
    end
    if dt.min < 0 or dt.min > 59 then
      error("Invalid min: " .. dt.min)
    end
    if dt.sec < 0 or dt.sec > 61 then
      error("Invalid sec: " .. dt.sec)
    end

    -- 6. Format RFC3339 (UTC)
    -- We append 'Z' to indicate UTC time defined in RFC3339.
    return string.format("%04d-%02d-%02dT%02d:%02d:%02dZ", dt.year, dt.month, dt.day, dt.hour, dt.min, dt.sec)
  end
end

local function toIso8601(utcTime)
  return os.date("!%Y-%m-%dT%H:%M:%SZ", utcTime)
end

return {
  formatDate = formatDate,
  toIso8601 = toIso8601,
}
