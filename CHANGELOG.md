# Changelog

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
