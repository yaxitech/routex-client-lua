-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

local log = require("routex-client.logging").defaultLogger()

local util = require("routex-client.util")
local Vcek = require("routex-client.attestation.vcek").Vcek
local VcekGeneration = require("routex-client.attestation.vcek").VcekGeneration
local AttestationReport = require("routex-client.attestation.report").AttestationReport
local SigningKey = require("routex-client.attestation.report").SigningKey

---@class YAXI.Attestation.RemoteAttestation.Requirements
---@field minCommittedVersion YAXI.Attestation.Report.Version
---@field minCommittedTcbSnp integer
---@field minMicrocode fun(model: integer, stepping: integer): integer?

---@type table<YAXI.Attestation.Vcek.VcekGeneration, YAXI.Attestation.RemoteAttestation.Requirements>
local REQUIREMENTS = {
  [VcekGeneration.Milan] = {
    minCommittedVersion = { major = 0x1, minor = 0x37, build = 0x23 },
    minCommittedTcbSnp = 0x1B,
    minMicrocode = function(model, stepping)
      if model == 1 and stepping == 1 then -- Milan
        return 0xDE
      elseif model == 1 and stepping == 2 then -- Milan-X
        return 0x45
      end
      return nil
    end,
  },
  [VcekGeneration.Genoa] = {
    minCommittedVersion = { major = 0x1, minor = 0x37, build = 0x31 },
    minCommittedTcbSnp = 0x1B,
    minMicrocode = function(model, stepping)
      if model == 0x11 then
        ---@diagnostic disable-next-line: invert-if
        if stepping == 1 then -- Genoa
          return 0x56
        elseif stepping == 2 then -- Genoa-X
          return 0x51
        end
      elseif model == 0xA0 and stepping == 2 then -- Bergamo/Siena
        return 0x1B
      end
      return nil
    end,
  },
  [VcekGeneration.Turin] = {
    minCommittedVersion = { major = 0x1, minor = 0x37, build = 0x41 },
    minCommittedTcbSnp = 0x04,
    minMicrocode = function(model, stepping)
      if model == 2 and stepping == 1 then -- Turin Classic
        return 0x50
      elseif model == 0x11 and stepping == 0 then -- Turin Dense
        return 0x4D
      elseif model > 2 or (model == 2 and stepping > 1) or (model == 0x11 and stepping > 0) then -- Accept any newer models/steppings for Turin
        return 0
      end
      return nil
    end,
  },
}

---@class YAXI.Attestation.RemoteAttestation: YAXI.ClassBase
---@field vcek YAXI.Attestation.Vcek
---@field report YAXI.Attestation.Report
---@field requirements YAXI.Attestation.RemoteAttestation.Requirements
local RemoteAttestation = util.class()

---Create a new instance
---@param vcek string PEM-encoded SEV-VCEK certificate. If a certificate chain is passed, considers only the first certificate
---@param report binary SEV-SNP attestation report signed by `vcek`
---@return YAXI.Attestation.RemoteAttestation
function RemoteAttestation:new(vcek, report)
  local obj = setmetatable({}, self)
  obj.vcek = Vcek:new(vcek)
  ---@diagnostic disable-next-line undefined-field
  local attestationReport, err = AttestationReport:new(report, obj.vcek.vcekGeneration)
  if not attestationReport then
    error(("Failed to parse attestation report: %s"):format(err))
  end
  obj.report = attestationReport --[[@as YAXI.Attestation.Report]]
  obj.requirements = REQUIREMENTS[obj.vcek.vcekGeneration] ---@diagnostic disable-line: undefined-field
    or error(("Failed to find requirements for %s"):format(self.vcek.vcekGeneration))
  obj:verify()
  log:debug("SEV-VCEK: %s", obj.vcek)
  log:debug("Attestation report: %s", obj.report:summary())
  return obj
end

function RemoteAttestation:_verifySignature()
  local valid = self.vcek:getPublicKey():verify(self.report._signaturePayload, self.report.signature)
  if not valid then
    error("Failed to verify attestation report with SEV-VCEK public key")
  end
end

function RemoteAttestation:_verifyTcbVersion()
  local assertSame = function(expected, actual, field)
    if expected ~= actual then
      error(
        ("VCEK's TCB version does not match report's reported TCB version: invalid %s version. Expected %s, got %s"):format(
          field,
          expected,
          actual
        )
      )
    end
  end

  assertSame(self.vcek.tcbVersion.bootloader, self.report.reportedTcb.bootloader, "bootloader")
  assertSame(self.vcek.tcbVersion.tee, self.report.reportedTcb.tee, "TEE")
  assertSame(self.vcek.tcbVersion.snp, self.report.reportedTcb.snp, "SNP")
  assertSame(self.vcek.tcbVersion.microcode, self.report.reportedTcb.microcode, "microcode")
  assertSame(self.vcek.tcbVersion.fmc, self.report.reportedTcb.fmc, "FMC")
end

---@param v YAXI.Attestation.Report.Version
---@return integer
local function packVersion(v)
  return (v.major << 16) | (v.minor << 8) | v.build
end

function RemoteAttestation:_verifyCommittedVersion()
  local req = self.requirements.minCommittedVersion
  local rep = self.report.committed

  if packVersion(rep) < packVersion(req) then
    error(
      ("Report's committed version does not fulfill requirements. Expected at least %s.%s.%s, got %s.%s.%s"):format(
        req.major,
        req.minor,
        req.build,
        rep.major,
        rep.minor,
        rep.build
      )
    )
  end
end

function RemoteAttestation:_verifyCommittedTcbSnp()
  assert(
    self.requirements.minCommittedTcbSnp <= self.report.committedTcb.snp,
    ("Expected minimum committed SNP TCB of %s, got %s"):format(
      self.requirements.minCommittedTcbSnp,
      self.report.committedTcb.snp
    )
  )
end

function RemoteAttestation:_verifyAliasCheckComplete()
  assert(self.report.platInfo.aliasCheckComplete == true, "Expected alias check to have been completed")
end

function RemoteAttestation:_verifyDebugDisabled()
  assert(self.report.policy.debugAllowed == false, "Debug mode is enabled in guest policy")
end

function RemoteAttestation:_verifyVmpl()
  local maxVmpl = 3
  assert(self.report.vmpl <= maxVmpl, ("Expected VMPL <= %s, got %s"):format(maxVmpl, self.report.vmpl))
end

function RemoteAttestation:_verifySigningKey()
  assert(
    self.report.keyInfo.signingKey == SigningKey.Vcek,
    ("Expected signing key VCEK (%s), got %s"):format(SigningKey.Vcek, self.report.keyInfo.signingKey)
  )
end

function RemoteAttestation:_verifyMicrocodeVersion()
  assert(
    self.report.cpuidModId ~= nil and self.report.cpuidStep ~= nil,
    "Report is missing values for determining CPU type"
  )

  local minMicrocode = self.requirements.minMicrocode(self.report.cpuidModId, self.report.cpuidStep)

  assert(minMicrocode ~= nil, "Report doesn't match any valid CPU family")
  assert(
    minMicrocode <= self.report.reportedTcb.microcode,
    ("Expected minimum microcode version of %s, got %s"):format(minMicrocode, self.report.reportedTcb.microcode)
  )
end

function RemoteAttestation:verify()
  -- Verify SEV-VCEK + certificate chain
  self.vcek:verify()

  -- Verify signature
  self:_verifySignature()

  -- Verify TCB_VERSION in SEV-VCEK and report match
  self:_verifyTcbVersion()

  log:debug("Verified SEV-VCEK TCB matches reported TCB")

  -- Verify requirements
  -- Committed (=Anti-rollback limit)
  self:_verifyCommittedVersion()
  -- TCB SNP
  self:_verifyCommittedTcbSnp()
  -- Alias check complete
  self:_verifyAliasCheckComplete()
  -- Debug mode disabled
  self:_verifyDebugDisabled()
  -- VMPL
  self:_verifyVmpl()
  -- Signing key
  self:_verifySigningKey()

  self:_verifyMicrocodeVersion()

  log:debug("Verified committed TCB fulfills requirements")
end

return {
  RemoteAttestation = RemoteAttestation,
}
