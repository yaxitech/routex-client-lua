# Changelog

## [0.4.0] - 2026-10-05

### Added

- `ConnectionInfo.labels`
- `connectionData` option for `accounts`, `balances` and `transactions`, so a service can be run with the `connectionData` of an earlier `Result` instead of `credentials`; such a request raises `InterruptError` if it cannot complete without user interaction.
- `standingOrders`, `respondStandingOrders` and `confirmStandingOrders`

### Security

- Reject attestation reports whose guest policy allows migration to another host.

## [0.3.0] - 2026-07-16

### Added

- `AccountReference` accepts a non-IBAN `number` (e.g. an ISO 20022 BBAN) in addition to `iban`, for the balances and transactions services
- Result types: `YAXI.RoutexClient.Result.Balances.Payload.Entry`: add field `dateTime`, the moment a balance is valid (ISO 8601 date-time)
- `RoutexRefreshClient:setUserInSession(...)` with `UserInSession.OnThisConnection` / `UserInSession.At(ipAddress)` to signal an in-session user.

## [0.2.0] - 2026-06-14

### Added

- `RoutexRefreshClient` (`routex-client.refresh`) for the non-interactive (refresh) variants of the accounts, balances and transactions services
- `InterruptError`, raised when a `RoutexRefreshClient` service call requires an interactive step (e.g., SCA); the interactive `RoutexClient` never raises it
- `ConnectionInfo.bankCodes` and `ConnectionDetails.BankCodes`: a connection's national bank codes (if any), included in `info` results and, when requested via `details = { ConnectionDetails.BankCodes }`, in search results

### Fixed

- The rockspec now installs the previously missing modules `routex-client.crypto.random`, `routex-client.util.date` and `routex-client.util.uuid`

### Changed

- Enforce intermediate CA, Key Usage, and path length constraints on the VCEK chain.

### Removed

- `ConsentExpiredError`: expired consents now raise `UnauthorizedError`

## [0.1.3] - 2026-05-19

### Changed

- Hardened attestation verification

## [0.1.2] - 2026-04-23

### Added

- Result types: `YAXI.RoutexClient.Result.Balances.Payload.Entry`: add field `creditLimitIncluded`
- `YAXI.RoutexClient.ConnectionInfo`: add field `bics`
- `YAXI.RoutexClient.SearchOptions`: add optional field `details` to opt into additional data in search results
- `YAXI.RoutexClient.ConnectionDetails` enum with variant `Bics` to have search results contain BICs

### Fixed

- Error code/reason values on raised errors now match the wire format

## [0.1.1] - 2026-03-20

### Added

- Result types: `Capability` type alias and `capabilities` field on `Account`
- Result types: `BatchTransactionDetails` for batch transaction details

### Fixed

- Vendored logger now writes to stderr (matching the default `logging` module behavior)
- Result types: `Balance.amount` is now `string` (matching `Decimal` serialization)
- Result types: Renamed `RequestBatch` to `BatchData` (deprecated alias preserved)

## [0.1.0] - 2026-03-06

Initial release.
