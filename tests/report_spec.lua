-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

local base64 = require("routex-client.util.base64")
local AttestationReport = require("routex-client.attestation.report").AttestationReport
local SignatureAlgorithm = require("routex-client.attestation.report").SignatureAlgorithm

---@return string
local function base64Decode(s)
  return base64.decode(s) or error("Failed to Base64-decode data")
end

context("Attestation reports", function()
  test("Verify Genoa", function()
    local reportBytes = base64Decode(
      "AgAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAHAAAAAAAORAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA65STdUfx8UYT3YNXUsgcFgqYypVM4tJbMWy+5FVA6PgjOLcEOsRekm79MjVIvrjLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACMRJZhWehqBgwciXLLc59vjYp+5JOHfqQxFrOgumh8Hv//////////////////////////////////////////BwAAAAAADkQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADZMtAhJhowEMCKoRyLXvz7YvHgQ4r76mYOVc33wSBixrDpMFIFryR9CbzJ2WV3pOhMyZqyjyFTcsUgkPKS/vsVBwAAAAAADkQVNwEAFTcBAAcAAAAAAA5EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0VZKXPYgBdZlFm3Yowh2azE1mgwxUohtJzB5S3byhQnluOPuKut65gt8OW/5BkJtAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8DFaJ3Xw2kcKy7Xhn+3O6/I896ATXJ1FL3Il5abB6emoB1WWLKaXVW+TolLzXdKHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    local attestationReport = AttestationReport:new(reportBytes, "Genoa")
    assert.is_not_nil(attestationReport)

    ---@type YAXI.Attestation.Report
    local expected = {
      version = 2,
      guestSvn = 0,
      policy = {
        abiMinor = 0,
        abiMajor = 0,
        smtAllowed = true,
        migrateMaAllowed = false,
        debugAllowed = false,
        singleSocketRequired = false,
        cxlAllowed = false,
        memAes256Xts = false,
        raplDis = false,
        ciphertextHiding = false,
        pageSwapDisabled = false,
      },
      familyId = ("\x00"):rep(16),
      imageId = ("\x00"):rep(16),
      vmpl = 0,
      sigAlgo = SignatureAlgorithm.ecdsaP384WithSha384,
      currentTcb = {
        fmc = nil,
        bootloader = 7,
        tee = 0,
        snp = 14,
        microcode = 68,
      },
      platInfo = {
        smtEnabled = true,
        tsmeEnabled = false,
        eccEnabled = false,
        raplDisabled = false,
        ciphertextHidingEnabled = false,
        aliasCheckComplete = false,
        tioEnabled = false,
      },
      keyInfo = {
        authorKeyEn = false,
        maskChipKey = false,
        signingKey = 0,
      },
      reportData = ("\x00"):rep(64),
      measurement = base64Decode("65STdUfx8UYT3YNXUsgcFgqYypVM4tJbMWy+5FVA6PgjOLcEOsRekm79MjVIvrjL"),
      hostData = ("\x00"):rep(32),
      idKeyDigest = ("\x00"):rep(48),
      authorKeyDigest = ("\x00"):rep(48),
      reportId = base64Decode("jESWYVnoagYMHIlyy3Ofb42KfuSTh36kMRazoLpofB4="),
      reportIdMa = ("\xff"):rep(32),
      reportedTcb = {
        fmc = nil,
        bootloader = 7,
        tee = 0,
        snp = 14,
        microcode = 68,
      },
      cpuidFamId = nil,
      cpuidModId = nil,
      cpuidStep = nil,
      chipId = base64Decode("2TLQISYaMBDAiqEci178+2Lx4EOK++pmDlXN98EgYsaw6TBSBa8kfQm8ydlld6ToTMmaso8hU3LFIJDykv77FQ=="),
      committedTcb = {
        fmc = nil,
        bootloader = 7,
        tee = 0,
        snp = 14,
        microcode = 68,
      },
      current = {
        major = 1,
        minor = 55,
        build = 21,
      },
      committed = {
        major = 1,
        minor = 55,
        build = 21,
      },
      launchTcb = {
        fmc = nil,
        bootloader = 7,
        tee = 0,
        snp = 14,
        microcode = 68,
      },
      launchMitVector = nil,
      currentMitVector = nil,
      signature = base64Decode(
        "bUIG+W85fAvmeusq7uO45QmF8nZLeTAnbYhSMQyaNTFrdgij2G0WZdYFIPZcSlbRh9Jd81Kik29Vl6YsllUHqOnpwablJXIvRZ1cE6D3PPLrzu2f4bXLCkfa8HUnWjHw"
      ),
      _signaturePayload = reportBytes:sub(1, -512 - 1),
    }
    assert.same(expected, attestationReport)
  end)

  test("Verify Milan", function()
    local reportBytes = base64Decode(
      "AgAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAADAAAAAAAIcwEAAAAAAAAAAAAAAAAAAADUR7VdGXSRv+Fc8pj53pmGt6fEviRotPbi1Ttx18ZFgQsPLN/KAEBDO+Bj/BqCk/Dz+Nrnt5/ss9HNgr1qk+v9eh5cJmwBCNvJu5T6kmlRMglAkV0Kr7QkZL2ItXnqFY0+Gg3DmyxgvZW5xIDNgYQfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACSs7R9WfCioQp0xWeIaKgCOM9ZPAGoLzz/uHjpBMKNW///////////////////////////////////////////AwAAAAAACHMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADUlVTscX9OWw/msUO88EBb164wRyft9GYD8qdq72o6vBXXrzjbdXA5Ap8O+s/QjiRDJIhHOMcrCC4vh6RNVB62AwAAAAAACHMENAEABDQBAAMAAAAAAAhzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYatPEapmGZdiXyM99CpK1URA7repbqY94XDLwpw3wAXLVAVIgex9K+5WmwLQf4JyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIJ1+ub6Rmh0Lrx1X/m6/6rvFO3eMbpd+QLFcqTG7bUTFq54wz9xzRstBrAg7kL9JAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    local attestationReport = AttestationReport:new(reportBytes, "Milan")
    assert.is_not_nil(attestationReport)

    ---@type YAXI.Attestation.Report
    local expected = {
      version = 2,
      guestSvn = 0,
      policy = {
        abiMinor = 0,
        abiMajor = 0,
        smtAllowed = true,
        migrateMaAllowed = false,
        debugAllowed = false,
        singleSocketRequired = false,
        cxlAllowed = false,
        memAes256Xts = false,
        raplDis = false,
        ciphertextHiding = false,
        pageSwapDisabled = false,
      },
      familyId = ("\x00"):rep(16),
      imageId = ("\x00"):rep(16),
      vmpl = 0,
      sigAlgo = SignatureAlgorithm.ecdsaP384WithSha384,
      currentTcb = {
        fmc = nil,
        bootloader = 3,
        tee = 0,
        snp = 8,
        microcode = 115,
      },
      platInfo = {
        smtEnabled = true,
        tsmeEnabled = false,
        eccEnabled = false,
        raplDisabled = false,
        ciphertextHidingEnabled = false,
        aliasCheckComplete = false,
        tioEnabled = false,
      },
      keyInfo = {
        authorKeyEn = false,
        maskChipKey = false,
        signingKey = 0,
      },
      reportData = base64Decode(
        "1Ee1XRl0kb/hXPKY+d6ZhrenxL4kaLT24tU7cdfGRYELDyzfygBAQzvgY/wagpPw8/ja57ef7LPRzYK9apPr/Q=="
      ),
      measurement = base64Decode("eh5cJmwBCNvJu5T6kmlRMglAkV0Kr7QkZL2ItXnqFY0+Gg3DmyxgvZW5xIDNgYQf"),
      hostData = ("\x00"):rep(32),
      idKeyDigest = ("\x00"):rep(48),
      authorKeyDigest = ("\x00"):rep(48),
      reportId = base64Decode("krO0fVnwoqEKdMVniGioAjjPWTwBqC88/7h46QTCjVs="),
      reportIdMa = ("\xff"):rep(32),
      reportedTcb = {
        fmc = nil,
        bootloader = 3,
        tee = 0,
        snp = 8,
        microcode = 115,
      },
      cpuidFamId = nil,
      cpuidModId = nil,
      cpuidStep = nil,
      chipId = base64Decode("1JVU7HF/TlsP5rFDvPBAW9euMEcn7fRmA/Knau9qOrwV168423VwOQKfDvrP0I4kQySIRzjHKwguL4ekTVQetg=="),
      committedTcb = {
        fmc = nil,
        bootloader = 3,
        tee = 0,
        snp = 8,
        microcode = 115,
      },
      current = {
        major = 1,
        minor = 52,
        build = 4,
      },
      committed = {
        major = 1,
        minor = 52,
        build = 4,
      },
      launchTcb = {
        fmc = nil,
        bootloader = 3,
        tee = 0,
        snp = 8,
        microcode = 115,
      },
      launchMitVector = nil,
      currentMitVector = nil,
      signature = base64Decode(
        "coJ/0AKbVu4rfeyBSAVUywXAN5zCy3DhPaZuqbfuQETVSir0PSNfYpcZZqoRT6thSb+QOwisQctGc9zPMJ6rxURtuzGpXLFAfpdujHc7xbvqv27+Vx2vCx2akb65fp0g"
      ),
      _signaturePayload = reportBytes:sub(1, -512 - 1),
    }

    assert.same(expected, attestationReport)
  end)

  test("Verify Turin", function()
    -- Turin attestation report from here:
    -- https://github.com/project-oak/oak/blob/cbb5d5c/oak_attestation_verification/testdata/turin_oc_evidence.textproto#L10
    --
    -- Parsed by virtee/sev (rev: c7b6bbb4e9c0fe85199723ab082ccadf39a494f0):
    --
    -- AttestationReport {
    --     version: 5,
    --     guest_svn: 0,
    --     policy: GuestPolicy {
    --         .0: 196608,
    --         abi_minor: 0,
    --         abi_major: 0,
    --         smt_allowed: true,
    --         migrate_ma_allowed: false,
    --         debug_allowed: false,
    --         single_socket_required: false,
    --         cxl_allowed: false,
    --         mem_aes_256_xts: false,
    --         rapl_dis: false,
    --         ciphertext_hiding: false,
    --         page_swap_disabled: false,
    --     },
    --     family_id: [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ],
    --     image_id: [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ],
    --     vmpl: 0,
    --     sig_algo: 1,
    --     current_tcb: TcbVersion {
    --         fmc: Some(
    --             0,
    --         ),
    --         bootloader: 1,
    --         tee: 0,
    --         snp: 2,
    --         microcode: 71,
    --     },
    --     plat_info: PlatformInfo {
    --         .0: 103,
    --         smt_enabled: true,
    --         tsme_enabled: true,
    --         ecc_enabled: true,
    --         rapl_disabled: false,
    --         ciphertext_hiding_enabled: false,
    --         alias_check_complete: true,
    --         tio_enabled: false,
    --     },
    --     key_info: KeyInfo {
    --         .0: 0,
    --         author_key_en: false,
    --         mask_chip_key: false,
    --         signing_key: 0,
    --     },
    --     report_data: [ 224, 253, 11, 219, 106, 164, 3, 10, 109, 222, 169, 7, 62, 31, 206, 197, 190, 108, 120, 42, 44, 128, 117, 160, 130, 93, 251, 61, 154, 129, 185, 36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ],
    --     measurement: [ 249, 36, 221, 24, 241, 104, 223, 96, 251, 234, 147, 127, 11, 8, 98, 132, 213, 27, 27, 55, 109, 232, 114, 186, 196, 54, 148, 246, 17, 52, 213, 121, 103, 195, 24, 1, 141, 231, 51, 85, 3, 2, 61, 187, 80, 222, 230, 36, ],
    --     host_data: [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ],
    --     id_key_digest: [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ],
    --     author_key_digest: [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ],
    --     report_id: [ 165, 230, 251, 11, 58, 61, 161, 34, 223, 229, 47, 81, 92, 221, 186, 29, 100, 238, 18, 62, 52, 2, 84, 99, 132, 249, 46, 215, 114, 76, 23, 179, ],
    --     report_id_ma: [ 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, ],
    --     reported_tcb: TcbVersion {
    --         fmc: Some(
    --             0,
    --         ),
    --         bootloader: 1,
    --         tee: 0,
    --         snp: 2,
    --         microcode: 71,
    --     },
    --     cpuid_fam_id: Some(
    --         26,
    --     ),
    --     cpuid_mod_id: Some(
    --         2,
    --     ),
    --     cpuid_step: Some(
    --         1,
    --     ),
    --     chip_id: [ 59, 66, 9, 47, 105, 198, 86, 211, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ],
    --     committed_tcb: TcbVersion {
    --         fmc: Some(
    --             0,
    --         ),
    --         bootloader: 1,
    --         tee: 0,
    --         snp: 2,
    --         microcode: 71,
    --     },
    --     current: Version {
    --         major: 1,
    --         minor: 55,
    --         build: 61,
    --     },
    --     committed: Version {
    --         major: 1,
    --         minor: 55,
    --         build: 61,
    --     },
    --     launch_tcb: TcbVersion {
    --         fmc: Some(
    --             0,
    --         ),
    --         bootloader: 1,
    --         tee: 0,
    --         snp: 2,
    --         microcode: 71,
    --     },
    --     launch_mit_vector: Some(
    --         0,
    --     ),
    --     current_mit_vector: Some(
    --         0,
    --     ),
    --     signature: Signature { r:Iter([155, 247, 85, 148, 177, 181, 193, 245, 83, 57, 230, 23, 83, 5, 97, 33, 151, 27, 61, 111, 37, 12, 121, 149, 180, 124, 169, 218, 182, 9, 247, 175, 196, 76, 144, 133, 113, 166, 145, 229, 225, 19, 221, 249, 41, 62, 154, 251, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), s:Iter([20, 71, 88, 101, 81, 217, 170, 185, 152, 153, 11, 131, 131, 138, 105, 94, 81, 246, 42, 30, 124, 245, 125, 30, 238, 71, 14, 65, 122, 184, 4, 191, 121, 104, 250, 33, 215, 217, 115, 157, 76, 202, 194, 156, 119, 190, 137, 232, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) },
    -- }
    local reportBytes = base64Decode(
      "BQAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAQACAAAAR2cAAAAAAAAAAAAAAAAAAADg/QvbaqQDCm3eqQc+H87Fvmx4KiyAdaCCXfs9moG5JAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+STdGPFo32D76pN/CwhihNUbGzdt6HK6xDaU9hE01XlnwxgBjeczVQMCPbtQ3uYkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACl5vsLOj2hIt/lL1Fc3bodZO4SPjQCVGOE+S7XckwXs///////////////////////////////////////////AAEAAgAAAEcaAgEAAAAAAAAAAAAAAAAAAAAAAAAAAAA7QgkvacZW0wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAgAAAEc9NwEAPTcBAAABAAIAAABHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAm/dVlLG1wfVTOeYXUwVhIZcbPW8lDHmVtHyp2rYJ96/ETJCFcaaR5eET3fkpPpr7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFEdYZVHZqrmYmQuDg4ppXlH2Kh589X0e7kcOQXq4BL95aPoh19lznUzKwpx3vonoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    local attestationReport = AttestationReport:new(reportBytes, "Turin")
    assert.is_not_nil(attestationReport)

    ---@type YAXI.Attestation.Report
    local expected = {
      version = 5,
      guestSvn = 0,
      policy = {
        abiMinor = 0,
        abiMajor = 0,
        smtAllowed = true,
        migrateMaAllowed = false,
        debugAllowed = false,
        singleSocketRequired = false,
        cxlAllowed = false,
        memAes256Xts = false,
        raplDis = false,
        ciphertextHiding = false,
        pageSwapDisabled = false,
      },
      familyId = ("\x00"):rep(16),
      imageId = ("\x00"):rep(16),
      vmpl = 0,
      sigAlgo = SignatureAlgorithm.ecdsaP384WithSha384,
      currentTcb = {
        fmc = 0,
        bootloader = 1,
        tee = 0,
        snp = 2,
        microcode = 71,
      },
      platInfo = {
        smtEnabled = true,
        tsmeEnabled = true,
        eccEnabled = true,
        raplDisabled = false,
        ciphertextHidingEnabled = false,
        aliasCheckComplete = true,
        tioEnabled = false,
      },
      keyInfo = {
        authorKeyEn = false,
        maskChipKey = false,
        signingKey = 0,
      },
      reportData = base64Decode(
        "4P0L22qkAwpt3qkHPh/Oxb5seCosgHWggl37PZqBuSQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
      ),
      measurement = base64Decode("+STdGPFo32D76pN/CwhihNUbGzdt6HK6xDaU9hE01XlnwxgBjeczVQMCPbtQ3uYk"),
      hostData = ("\x00"):rep(32),
      idKeyDigest = ("\x00"):rep(48),
      authorKeyDigest = ("\x00"):rep(48),
      reportId = base64Decode("peb7Czo9oSLf5S9RXN26HWTuEj40AlRjhPku13JMF7M="),
      reportIdMa = ("\xff"):rep(32),
      reportedTcb = {
        fmc = 0,
        bootloader = 1,
        tee = 0,
        snp = 2,
        microcode = 71,
      },
      cpuidFamId = 26,
      cpuidModId = 2,
      cpuidStep = 1,
      chipId = base64Decode("O0IJL2nGVtMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="),
      committedTcb = {
        fmc = 0,
        bootloader = 1,
        tee = 0,
        snp = 2,
        microcode = 71,
      },
      current = {
        major = 1,
        minor = 55,
        build = 61,
      },
      committed = {
        major = 1,
        minor = 55,
        build = 61,
      },
      launchTcb = {
        fmc = 0,
        bootloader = 1,
        tee = 0,
        snp = 2,
        microcode = 71,
      },
      launchMitVector = 0,
      currentMitVector = 0,
      signature = base64Decode(
        "+5o+KfndE+HlkaZxhZBMxK/3CbbaqXy0lXkMJW89G5chYQVTF+Y5U/XBtbGUVfeb6Im+d5zCykydc9nXIfpoeb8EuHpBDkfuHn31fB4q9lFeaYqDgwuZmLmq2VFlWEcU"
      ),
      _signaturePayload = reportBytes:sub(1, -512 - 1),
    }

    assert.same(expected, attestationReport)
  end)

  test("Rejects truncated report", function()
    local truncated = ("\x00"):rep(100)
    assert.error_match(function()
      AttestationReport:new(truncated, "Genoa")
    end, "Expected exactly 1184 bytes, got: 100 bytes", nil, true)
  end)
end)
