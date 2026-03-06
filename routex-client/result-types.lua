-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

-- This file is not loaded at runtime; it provides LuaLS type definitions only.

---@alias binary string A binary string

---@class YAXI.RoutexClient.Result.Amount
---@field amount string Numeric amount (e.g. "80.00").
---@field currency string ISO 4217 Alpha 3 currency code.

---@class YAXI.RoutexClient.Result.Account
---@field iban string? ISO 20022 IBAN2007Identifier
---@field number string? Account number that is not an IBAN, e.g. ISO 20022 BBANIdentifier or primary account number (PAN) of a card account
---@field bic string? ISO 20022 BICFIIdentifier
---@field bankCode string? National bank code
---@field currency string? ISO 4217 Alpha 3 currency code
---@field name string? Name of account, assigned by ASPSP
---@field displayName string? Display name of account, assigned by PSU
---@field ownerName string? Legal account owner
---@field productName string? Product name
---@field status YAXI.RoutexClient.AccountStatus? Account status
---@field type YAXI.RoutexClient.AccountType? Account type

-- YAXI TRANSACTION TYPES

---@class YAXI.RoutexClient.Result.Transaction
---Required
---@field amount YAXI.RoutexClient.Result.Amount Transaction amount as billed to the account.
---@field status YAXI.RoutexClient.Result.Transaction.Status Transaction status.
---Optional
---@field accountServicerReference string? Unique reference assigned by the account servicer.
---@field additionalInformation string? Additional information attached to the transaction. This might be a proprietary, localized, human-readable long text corresponding to some machine-readable bank transaction code that is not directly provided by the bank.
---@field bankTransactionCodes YAXI.RoutexClient.Result.Transaction.BankTransactionCodes[]? Bank transaction codes.
---@field batch YAXI.RoutexClient.Result.Transaction.RequestBatch? Grouped transaction info.
---@field bookingDate string? Booking date (ASPSP's books), format: date.
---@field creditor YAXI.RoutexClient.Result.Transaction.Party? Creditor data. In case of reversals this refers to the initial transaction.
---@field creditorId string? SEPA creditor identifier.
---@field debtor YAXI.RoutexClient.Result.Transaction.Party? Debtor data. In case of reversals this refers to the initial transaction.
---@field endToEndId string? Unique end-to-end identifier assigned by the initiating party.
---@field entryReference string? Identifier used for delta requests.
---@field exchanges YAXI.RoutexClient.Result.Transaction.ExchangeRate[]? Exchange rates if applicable.
---@field fees YAXI.RoutexClient.Result.Transaction.Fee[]? Transaction-related fees.
---@field mandateId string? Mandate identifier.
---@field originalAmount YAXI.RoutexClient.Result.Amount? Original amount of the transaction.
---@field paymentId string? Unique identifier assigned by the sending party.
---@field purposeCode string? ISO 20022 ExternalPurpose1Code.
---@field remittanceInformation string[]? Remittance (purpose).
---@field reversal boolean? Indicator for reversals.
---@field transactionDate string? Actual transaction date (e.g. card payment), format: date.
---@field transactionId string? Unique identifier assigned by the first instructing agent.
---@field valueDate string? Expected/requested value date (e.g. pending), format: date.

---@class YAXI.RoutexClient.Result.Transaction.ISOCode
---@field domain string ExternalBankTransactionDomain1Code.
---@field family string ExternalBankTransactionFamily1Code.
---@field subFamily string ExternalBankTransactionSubFamily1Code.

---@alias YAXI.RoutexClient.Result.Transaction.Status
---|"Pending"
---|"Booked"
---|"Invoiced"
---|"Paid"
---|"Canceled"

---@alias YAXI.RoutexClient.Result.Transaction.BankTransactionCodes
---|YAXI.RoutexClient.Result.Transaction.BankTransactionCodes.ISO
---|YAXI.RoutexClient.Result.Transaction.BankTransactionCodes.SWIFT
---|YAXI.RoutexClient.Result.Transaction.BankTransactionCodes.BAI
---|YAXI.RoutexClient.Result.Transaction.BankTransactionCodes.National
---|YAXI.RoutexClient.Result.Transaction.BankTransactionCodes.Other

---@class YAXI.RoutexClient.Result.Transaction.RequestBatch
---@field numberOfTransactions number? Count of transactions in batch.
---@field transactions YAXI.RoutexClient.Result.Transaction[] List of transactions.

---@class YAXI.RoutexClient.Result.Transaction.ExchangeRate
---@field sourceCurrency string ISO 4217 Alpha 3 currency code of the source currency that gets converted.
---@field targetCurrency string? ISO 4217 Alpha 3 currency code of the target currency that the source currency gets converted into.
---@field unitCurrency string? ISO 4217 Alpha 3 currency code of the unit currency for the exchange rate.
---@field exchangeRate string Numeric exchange rate.

---@class YAXI.RoutexClient.Result.Transaction.Fee
---@field amount YAXI.RoutexClient.Result.Amount Fee amount.
---@field kind string? Fee type (ExternalChargeType1Code).
---@field bic string? Agent's BIC (BICFIIdentifier).

---@class YAXI.RoutexClient.Result.Transaction.Party
---@field name string? Creditor / debtor name.
---@field iban string? ISO 20022 IBAN2007Identifier for the creditor / debtor account.
---@field bic string? ISO 20022 BICFIIdentifier for the creditor / debtor agent.
---@field ultimate string? Ultimate creditor / debtor (name).

---@class YAXI.RoutexClient.Result.Transaction.BankTransactionCodes.ISO
---@field iso YAXI.RoutexClient.Result.Transaction.ISOCode ISO 20022 transaction code.

---@class YAXI.RoutexClient.Result.Transaction.BankTransactionCodes.SWIFT
---@field swift string SWIFT transaction code.

---@class YAXI.RoutexClient.Result.Transaction.BankTransactionCodes.BAI
---@field bai string BAI2 transaction code.

---@class YAXI.RoutexClient.Result.Transaction.BankTransactionCodes.National
---@field national YAXI.RoutexClient.Result.Transaction.NationalCode National transaction code (e.g. German GVC).

---@class YAXI.RoutexClient.Result.Transaction.NationalCode
---@field code string Code.
---@field country string ISO 3166-1 alpha-2 country code.

---@class YAXI.RoutexClient.Result.Transaction.BankTransactionCodes.Other
---@field other YAXI.RoutexClient.Result.Transaction.OtherCode Unspecified transaction code with optional issuer.

---@class YAXI.RoutexClient.Result.Transaction.OtherCode
---@field code string Code.
---@field issuer string? Code issuer.

--- YAXI BALANCES TYPES

---@class YAXI.RoutexClient.Result.Balances
---@field balances YAXI.RoutexClient.Result.Balances.Payload[] List of balances for accounts.
---@field missingAccounts YAXI.RoutexClient.AccountReference[] Accounts that were requested but not found.

---@class YAXI.RoutexClient.Result.Balances.Payload
---@field account YAXI.RoutexClient.AccountReference
---@field balances YAXI.RoutexClient.Result.Balances.Payload.Entry[] List of balances (of different types) for the account.

---@class YAXI.RoutexClient.Result.Balances.Payload.Entry
---@field amount number Numeric amount.
---@field currency string ISO 4217 Alpha 3 currency code.
---@field balanceType YAXI.RoutexClient.Result.Balances.Payload.Entry.Type

---@alias YAXI.RoutexClient.Result.Balances.Payload.Entry.Type
---Balance from booked transactions.
---|"Booked"
---Balance from booked transactions and pending debits.
---|"Available"
---Expected balance from booked and pending transactions.
---|"Expected"
