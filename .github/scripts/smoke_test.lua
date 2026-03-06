local RoutexClient = require("routex-client").RoutexClient

local client = RoutexClient:new(os.getenv("ROUTEX_URL"))

local bankName = "Deutsche Kreditbank Berlin"
local result = client:search({
  filters = { { name = bankName } },
})

assert(#result >= 1)

for _, info in ipairs(result) do
  assert(info.displayName == bankName)
end
