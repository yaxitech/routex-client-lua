# Changelog

### [0.1.3] - 2026-05-19

#### Changed

- Hardened attestation verification

### [0.1.2] - 2026-04-23

#### Added

- Result types: `YAXI.RoutexClient.Result.Balances.Payload.Entry`: add field `creditLimitIncluded`
- `YAXI.RoutexClient.ConnectionInfo`: add field `bics`
- `YAXI.RoutexClient.SearchOptions`: add optional field `details` to opt into additional data in search results
- `YAXI.RoutexClient.ConnectionDetails` enum with variant `Bics` to have search results contain BICs

#### Fixed

- Error code/reason values on raised errors now match the wire format

### [0.1.1] - 2026-03-20

#### Added

- Result types: `Capability` type alias and `capabilities` field on `Account`
- Result types: `BatchTransactionDetails` for batch transaction details

#### Fixed

- Vendored logger now writes to stderr (matching the default `logging` module behavior)
- Result types: `Balance.amount` is now `string` (matching `Decimal` serialization)
- Result types: Renamed `RequestBatch` to `BatchData` (deprecated alias preserved)

### [0.1.0] - 2026-03-06

Initial release.
