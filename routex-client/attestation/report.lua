-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

local util = require("routex-client.util")

---@class YAXI.Attestation.Report.TcbVersion
---@field fmc integer? FMC firmware SVN (present in Turin layout; optional)
---@field bootloader integer SVN of PSP bootloader
---@field tee integer SVN of PSP operating system (TEE)
---@field snp integer SNP firmware SVN
---@field microcode integer Lowest microcode patch level for all cores

---@class YAXI.Attestation.Report.GuestPolicy
---@field abiMajor integer ABI major minimum required (bits 15:8)
---@field abiMinor integer ABI minor minimum required (bits 7:0)
---@field smtAllowed boolean SMT allowed (bit 16)
---@field migrateMaAllowed boolean Migration agent association allowed (bit 18)
---@field debugAllowed boolean Debug allowed (bit 19)
---@field singleSocketRequired boolean Single socket activation required (bit 20)
---@field cxlAllowed boolean CXL allowed (bit 21)
---@field memAes256Xts boolean Require AES-256 XTS memory encryption (bit 22)
---@field raplDis boolean RAPL disabled (bit 23)
---@field ciphertextHiding boolean Ciphertext hiding required (bit 24)
---@field pageSwapDisabled boolean Page-swap commands disabled (bit 25)

---@class YAXI.Attestation.Report.PlatformInfo
---@field smtEnabled boolean SMT enabled (bit 0)
---@field tsmeEnabled boolean TSME enabled (bit 1)
---@field eccEnabled boolean ECC memory in use (bit 2)
---@field raplDisabled boolean RAPL disabled (bit 3)
---@field ciphertextHidingEnabled boolean Ciphertext hiding enabled (bit 4)
---@field aliasCheckComplete boolean Alias check complete (bit 5)
---@field tioEnabled boolean SEV-TIO enabled (bit 7)

---@class YAXI.Attestation.Report.KeyInfo
---@field authorKeyEn boolean AUTHOR_KEY_EN (bit 0): author key digest present
---@field maskChipKey boolean MASK_CHIP_KEY (bit 1): mask chip key behavior
---@field signingKey YAXI.Attestation.Report.KeyInfo.SigningKey SIGNING_KEY (bits 4:2): which key signed the report

---@class YAXI.Attestation.Report.Version
---@field major integer Major version
---@field minor integer Minor version
---@field build integer Build number

---@enum YAXI.Attestation.Report.SigAlgo
local SignatureAlgorithm = {
  ecdsaP384WithSha384 = 1,
}

---@enum YAXI.Attestation.Report.KeyInfo.SigningKey
local SigningKey = {
  Vcek = 0,
  Vlek = 1,
  None = 7,
}

---@class YAXI.Attestation.Report
---@field version integer Report version (u32)
---@field guestSvn integer Guest SVN (u32)
---@field policy YAXI.Attestation.Report.GuestPolicy Guest policy (u64 bitfield)
---@field familyId binary FamilyID[16]
---@field imageId binary ImageID[16]
---@field vmpl integer VMPL (u32)
---@field sigAlgo YAXI.Attestation.Report.SigAlgo Signature algorithm (u32)
---@field currentTcb YAXI.Attestation.Report.TcbVersion Current TCB (8 bytes)
---@field platInfo YAXI.Attestation.Report.PlatformInfo Platform information (u64 bitfield)
---@field keyInfo YAXI.Attestation.Report.KeyInfo Key information (u32 bitfield)
---@field reportData binary Guest-provided ReportData[64]
---@field measurement binary Measurement[48] launch measurement
---@field hostData binary HostData[32]
---@field idKeyDigest binary IDKeyDigest[48] (SHA-384 digest)
---@field authorKeyDigest binary AuthorKeyDigest[48] (SHA-384 digest)
---@field reportId binary ReportID[32]
---@field reportIdMa binary ReportID_MA[32]
---@field reportedTcb YAXI.Attestation.Report.TcbVersion Reported TCB (8 bytes used to derive VCEK)
---@field cpuidFamId integer? CPUID Family ID (present in version >=3)
---@field cpuidModId integer? CPUID Model ID (present in version >=3)
---@field cpuidStep integer? CPUID Stepping (present in version >=3)
---@field chipId binary ChipID[64]
---@field committedTcb YAXI.Attestation.Report.TcbVersion Committed TCB (8 bytes)
---@field current YAXI.Attestation.Report.Version CurrentVersion (3 bytes)
---@field committed YAXI.Attestation.Report.Version CommittedVersion (3 bytes)
---@field launchTcb YAXI.Attestation.Report.TcbVersion LaunchTCB (8 bytes)
---@field launchMitVector integer? LaunchMitVector (u64, version >=5)
---@field currentMitVector integer? CurrentMitVector (u64, version >=5)
---@field signature binary Signature[512]
---@field _signaturePayload binary Internal: bytes 0x00..0x29f (used for signing)
local AttestationReport = {}
AttestationReport.__index = AttestationReport

local Offsets = {
  base = {
    version = 0x00,
    guestSvn = 0x04,
    policy = 0x08,
    familyId = 0x10,
    imageId = 0x20,
    vmpl = 0x30,
    sigAlgo = 0x34,
    currentTcb = 0x38,
    platInfo = 0x40,
    keyInfo = 0x48,
    reportData = 0x50,
    measurement = 0x90,
    hostData = 0xC0,
    idKeyDigest = 0xE0,
    authorKeyDigest = 0x110,
    reportId = 0x140,
    reportIdMa = 0x160,
    reportedTcb = 0x180,
    chipId = 0x1A0,
    committedTcb = 0x1E0,
    current_build = 0x1E8,
    current_minor = 0x1E9,
    current_major = 0x1EA,
    committed_build = 0x1EC,
    committed_minor = 0x1ED,
    committed_major = 0x1EE,
    launchTcb = 0x1F0,
    signature = 0x2A0,
  },
  v3 = { cpuidFamId = 0x188, cpuidModId = 0x189, cpuidStep = 0x18A },
  v5 = { launchMitVector = 0x1F8, currentMitVector = 0x200 },
}

local SignatureLen = 0x200
local ReportLen = Offsets.base.signature + SignatureLen

local function off(pos)
  return pos + 1
end

local function parseError(field, offset, fname, msg, level)
  local s = ("Failed to parse %s at %s with %s"):format(field or "<unknown>", offset - 1, fname)
  if msg then
    s = ("%s: %s"):format(s, msg)
  end
  error(s, level or 2)
end

---@return integer
local function readU32Le(b, o, field)
  local ok, v = pcall(string.unpack, "<I4", b, o)
  if not ok then
    parseError(field, o, "readU32Le", v, 3)
  end
  return v --[[@as integer]]
end

---@return integer
local function readU8(b, o, field)
  local v = b:byte(o)
  if v == nil then
    parseError(field, o, "readU8", nil, 3)
  end
  return v --[[@as integer]]
end

---@return binary
local function readBytes(b, o, n, field)
  n = n or #b - o
  if o + n - 1 > #b then
    parseError(field, o, "readBytes", "invalid offset", 3)
  end
  return b:sub(o, o + n - 1)
end

---@return integer
local function readU64Le(b, o, field)
  local ok, v = pcall(string.unpack, "<I8", b, o)
  if not ok then
    parseError(field, o, "readU64Le", v)
  end
  return v --[[@as integer]]
end

local function parseTcbVersion(bytes, offset, productName, field)
  local raw8 = readBytes(bytes, offset, 8, field)
  ---@diagnostic disable: undefined-field
  local b = { raw8:byte(1, 8) }
  local t = {}
  t.microcode = b[8]
  if productName == "Genoa" or productName == "Milan" then
    t.snp = b[7]
    t.tee = b[2]
    t.bootloader = b[1]
    t.fmc = nil
  elseif productName == "Turin" then
    t.snp = b[4]
    t.tee = b[3]
    t.bootloader = b[2]
    t.fmc = b[1]
  else
    if b[7] ~= 0 then
      t.snp = b[7]
      t.tee = b[2]
      t.bootloader = b[1]
      t.fmc = nil
    else
      t.snp = b[4]
      t.tee = b[3]
      t.bootloader = b[2]
      t.fmc = b[1]
    end
  end
  ---@diagnostic enable: undefined-field
  return t
end

local function parseGuestPolicy(bytes)
  local offset, field = off(Offsets.base.policy), "POLICY"
  local raw = readBytes(bytes, offset, 8, field)
  local ok, v = pcall(string.unpack, "<I8", raw)
  if not ok then
    parseError(field, offset, "parseGuestPolicy", v)
  end
  return {
    abiMinor = v & 0xFF,
    abiMajor = (v >> 8) & 0xFF,
    smtAllowed = ((v >> 16) & 1) ~= 0,
    migrateMaAllowed = ((v >> 18) & 1) ~= 0,
    debugAllowed = ((v >> 19) & 1) ~= 0,
    singleSocketRequired = ((v >> 20) & 1) ~= 0,
    cxlAllowed = ((v >> 21) & 1) ~= 0,
    memAes256Xts = ((v >> 22) & 1) ~= 0,
    raplDis = ((v >> 23) & 1) ~= 0,
    ciphertextHiding = ((v >> 24) & 1) ~= 0,
    pageSwapDisabled = ((v >> 25) & 1) ~= 0,
  }
end

local function parsePlatformInfo(bytes)
  local offset, field = off(Offsets.base.platInfo), "PLATFORM_INFO"
  local raw = readBytes(bytes, offset, 8, field)
  local ok, v = pcall(string.unpack, "<I8", raw)
  if not ok then
    parseError(field, offset, "parsePlatformInfo", v)
  end
  return {
    smtEnabled = ((v >> 0) & 1) ~= 0,
    tsmeEnabled = ((v >> 1) & 1) ~= 0,
    eccEnabled = ((v >> 2) & 1) ~= 0,
    raplDisabled = ((v >> 3) & 1) ~= 0,
    ciphertextHidingEnabled = ((v >> 4) & 1) ~= 0,
    aliasCheckComplete = ((v >> 5) & 1) ~= 0,
    tioEnabled = ((v >> 7) & 1) ~= 0,
  }
end

local function parseKeyInfo(bytes)
  local offset, field = off(Offsets.base.keyInfo), "SIGNING_KEY"
  local raw = readBytes(bytes, offset, 4, field)
  local ok, v = pcall(string.unpack, "<I4", raw)
  if not ok then
    parseError(field, offset, "parseKeyInfo", v)
  end
  return {
    authorKeyEn = ((v >> 0) & 1) ~= 0,
    maskChipKey = ((v >> 1) & 1) ~= 0,
    signingKey = (v >> 2) & 0x7,
  }
end

local function parseVersion(build, minor, major)
  return { major = major, minor = minor, build = build }
end

---Parse signature
---@param bytes binary
---@param sigAlgo YAXI.Attestation.Report.SigAlgo
---@return binary
local function parseSignature(bytes, sigAlgo)
  local offset, field = off(Offsets.base.signature), "SIGNATURE"
  local signatureBytes = readBytes(bytes, offset, SignatureLen, field)
  if sigAlgo == SignatureAlgorithm.ecdsaP384WithSha384 then
    -- Convert the signature bytes into a raw, uncompressed ECDSA signature (without the SEC1 prefix)
    if #signatureBytes ~= SignatureLen then
      parseError(
        field,
        offset,
        "parseSignature",
        ("Expected signature length of %s, got %s"):format(SignatureLen, #signatureBytes)
      )
    end
    -- Offset 0x00: R component of this signature. Value is zero-extended little-endian encoded.
    local r = signatureBytes:sub(0x00 + 1, 48)
    -- Offset 0x48: S component of this signature. Value is zero-extended little-endian encoded.
    local s = signatureBytes:sub(0x48 + 1, 0x48 + 48)
    -- Convert to big endian
    return r:reverse() .. s:reverse()
  else
    parseError(field, offset, "parseSignature", ("Unsupported signature algorithm %s"):format(sigAlgo))
  end

  return "" -- unreachable
end

---@param bytes binary
---@param productName "Milan"|"Genoa"|"Turin"
---@return YAXI.Attestation.Report?,string?
function AttestationReport:new(bytes, productName)
  if #bytes ~= ReportLen then
    error(("Expected exactly %s bytes, got: %s bytes"):format(ReportLen, #bytes))
  end
  local o = setmetatable({}, self)
  o._signaturePayload = readBytes(bytes, off(Offsets.base.version), Offsets.base.signature, "_signaturePayload")
  o.version = readU32Le(bytes, off(Offsets.base.version), "VERSION")
  o.guestSvn = readU32Le(bytes, off(Offsets.base.guestSvn), "GUEST_SVN")
  o.policy = parseGuestPolicy(bytes)
  o.familyId = readBytes(bytes, off(Offsets.base.familyId), 16, "FAMILY_ID")
  o.imageId = readBytes(bytes, off(Offsets.base.imageId), 16, "IMAGE_ID")
  o.vmpl = readU32Le(bytes, off(Offsets.base.vmpl), "VMPL")
  o.sigAlgo = readU32Le(bytes, off(Offsets.base.sigAlgo), "SIGNATURE_ALGORITHM")
  o.currentTcb = parseTcbVersion(bytes, off(Offsets.base.currentTcb), productName, "CURRENT_TCB")
  o.platInfo = parsePlatformInfo(bytes)
  o.keyInfo = parseKeyInfo(bytes)
  o.reportData = readBytes(bytes, off(Offsets.base.reportData), 64, "REPORT_DATA")
  o.measurement = readBytes(bytes, off(Offsets.base.measurement), 48, "MEASUREMENT")
  o.hostData = readBytes(bytes, off(Offsets.base.hostData), 32, "HOST_DATA")
  o.idKeyDigest = readBytes(bytes, off(Offsets.base.idKeyDigest), 48, "ID_KEY_DIGEST")
  o.authorKeyDigest = readBytes(bytes, off(Offsets.base.authorKeyDigest), 48, "AUTHOR_KEY_DIGEST")
  o.reportId = readBytes(bytes, off(Offsets.base.reportId), 32, "REPORT_ID")
  o.reportIdMa = readBytes(bytes, off(Offsets.base.reportIdMa), 32, "REPORT_ID_MA")
  o.reportedTcb = parseTcbVersion(bytes, off(Offsets.base.reportedTcb), productName, "REPORTED_TCB")
  if o.version >= 3 then
    o.cpuidFamId = readU8(bytes, off(Offsets.v3.cpuidFamId), "CPUID_FAM_ID")
    o.cpuidModId = readU8(bytes, off(Offsets.v3.cpuidModId), "CPUID_MOD_ID")
    o.cpuidStep = readU8(bytes, off(Offsets.v3.cpuidStep), "CPUID_STEP")
  end
  o.chipId = readBytes(bytes, off(Offsets.base.chipId), 64, "CHIP_ID")
  o.committedTcb = parseTcbVersion(bytes, off(Offsets.base.committedTcb), productName, "COMMITTED_TCB")
  o.current = parseVersion(
    readU8(bytes, off(Offsets.base.current_build), "CURRENT_BUILD"),
    readU8(bytes, off(Offsets.base.current_minor), "CURRENT_MINOR"),
    readU8(bytes, off(Offsets.base.current_major), "CURRENT_MAJOR")
  )
  o.committed = parseVersion(
    readU8(bytes, off(Offsets.base.committed_build), "COMMITTED_BUILD"),
    readU8(bytes, off(Offsets.base.committed_minor), "COMMITTED_MINOR"),
    readU8(bytes, off(Offsets.base.committed_major), "COMMITTED_MAJOR")
  )
  o.launchTcb = parseTcbVersion(bytes, off(Offsets.base.launchTcb), productName, "LAUNCH_TCB")
  if o.version >= 5 then
    o.launchMitVector = readU64Le(bytes, off(Offsets.v5.launchMitVector), "LAUNCH_MIT_VECTOR")
    o.currentMitVector = readU64Le(bytes, off(Offsets.v5.currentMitVector), "CURRENT_MIT_VECTOR")
  end
  o.signature = parseSignature(bytes, o.sigAlgo)
  return o
end

function AttestationReport:summary()
  local shallowCopy = {}
  for k, v in pairs(self) do
    if k:find("_") ~= 1 then
      shallowCopy[k] = v
    end
  end
  return util.propsToMsg(shallowCopy)
end

AttestationReport.__tostring = function(self)
  return self:summary()
end

return {
  AttestationReport = AttestationReport,
  SignatureAlgorithm = SignatureAlgorithm,
  SigningKey = SigningKey,
  Offsets = Offsets,
}
