-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

require("tests.init")

local Offsets = require("routex-client.attestation.report").Offsets
local SigningKey = require("routex-client.attestation.report").SigningKey
local base64 = require("routex-client.util.base64")

local function getRemoteAttestation()
  local RemoteAttestation = require("routex-client.attestation").RemoteAttestation
  local realVerify = RemoteAttestation.verify
  ---@diagnostic disable-next-line: assign-type-mismatch
  RemoteAttestation.verify = spy.new(function(_) end)
  return RemoteAttestation, realVerify
end

local RemoteAttestationStubbed, verify = getRemoteAttestation()

context("Remote attestation", function()
  test("Works with valid SEV-VCEK and attestation report (Genoa v5)", function()
    local vcekPem = io.open("tests/data/vcek-chain-genoa-v5.pem", "r"):read("a")
    local reportBytes = base64.decode(
      "BQAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAKAAAAAAAbWCUAAAAAAAAAAAAAAAAAAAC7hR4gN0fDaF15opkQ52xTlXiW2/bmiDW2TqLCsr59tgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAvs5zmaTaBUpjouP6Gkf/mMiOOR1DeRJvxOdcZ38lts1r/Y72CahjgEljOsfgDkrBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABi7rIj6+Czg/wjqW/1+ebErc8VNceg/WAmdAfxkwukIf//////////////////////////////////////////CgAAAAAAG1gZEQEAAAAAAAAAAAAAAAAAAAAAAAAAAADgI0vts5GEMfVO4nkHh9evE4pnvh5YGiI2UOgQyUU0K8mujR/qg7McSdyMw020VwvPJb1teTmFaTqfDCEz3zPYCgAAAAAAG1gxNwEAMTcBAAoAAAAAABtYCwAAAAAAAAALAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZYrjOIJQEkOAa96UY4bNzGBfb3rkU/nkYlrJPreawo+VxJapz1dauh50ZJaQlQAnAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALN/WkfrqKgMOMMcOriyKfs6OwtTjsN6iSWKTnl7uQEpVKdNW8vEm/MBFYVbq8iKyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    assert(reportBytes ~= nil)

    local attestation = RemoteAttestationStubbed:new(vcekPem, reportBytes)
    -- Make sure this implicitly calls `verify()` when creating a new instance
    assert.spy(RemoteAttestationStubbed.verify).was.called(1)
    assert.has.no.error(function()
      verify(attestation)
    end)
  end)

  test("Rejects valid SEV-VCEK with unmet requirements (Genoa v3)", function()
    local vcekPem = io.open("tests/data/vcek-chain-genoa.pem", "r"):read("a")
    local reportBytes = base64.decode(
      "AwAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAJAAAAAAAXSCUAAAAAAAAAAAAAAAAAAADtb2Mz/shgXl7AGT+hYxjQU4waK+PGU+Ig1lZYhc4jpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsPXQl7XHrd1O4GpvX9BKdFxUFddzY8p0hXtEImob19pQMpVJ3vCJfCNGleN7jCeTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADeGjc9T7YLxCR50RUdyMYT1RmfN3fI0OhYlThg7g5yUP//////////////////////////////////////////CQAAAAAAF0gZEQEAAAAAAAAAAAAAAAAAAAAAAAAAAACdyZliwGMCnkMLb3tzQHXsVC9PPsY55lfhRYXT/lWbOFMrxC0DfWGDF2lK1mNNJQeWTidsju3qxJeMcAa/ifjhCQAAAAAAF0gnNwEAJzcBAAkAAAAAABdIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8OXKBDA/vppb2qRn3e6NN/VWwraRslTEgRs1FQPyPr0eT7zpT7qcL3oRDzwFFqmlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp3DOM+SPxf/rIoGcr/A8bgdwP6ImCUuVjOnFo8d+BFupS5di4IyvCcnSWuWuESr2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    assert(reportBytes ~= nil)

    local attestation = RemoteAttestationStubbed:new(vcekPem, reportBytes)
    assert.error_match(function()
      verify(attestation)
    end, "Report's committed version does not fulfill requirements. Expected at least 1.55.49, got 1.55.39", nil, true)
  end)

  test("Rejects valid SEV-VCEK with unmet requirements (Milan)", function()
    local vcekPem = io.open("tests/data/vcek-chain-milan.pem", "r"):read("a")
    local reportBytes = base64.decode(
      "AwAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAEAAAAAAAY2yUAAAAAAAAAAAAAAAAAAACnypibA1nqTl78R728rYSy3z8m/Qnue9pbsnlTq/aJkgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGVsBt0l2ofq6E72F6veHlY8KRubd3UXFvb+Gc1Ind4QrgFeuXYZrdUFu+2IBLeqjAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACzclDrjtBmN2iXUhSjq9/CWbW87kZYduyL4wSeswYZpP//////////////////////////////////////////BAAAAAAAGNsZAQEAAAAAAAAAAAAAAAAAAAAAAAAAAACj/cLGTcKZq5DUI4lzhktYY3ji5e+cnU3GCPO9qompaaA/G1dSytVaDBVHregA29dATpyz+XONo7KA0d9pz4LkBAAAAAAAGNsdNwEAHTcBAAQAAAAAABjbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAnLn0Mfy49uodHsu4vhypVq/F1gwJBi+dx7CsqqAniT7WyrhUVSvM4hTbcYQhy8SIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhnIsL98bkJckteClvV+NxF7EJYcOznFmccw8tD2T8bj/+3swC97qWVJu60n6rwmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    assert(reportBytes ~= nil)

    local attestation = RemoteAttestationStubbed:new(vcekPem, reportBytes)
    assert.error_match(function()
      verify(attestation)
    end, "Report's committed version does not fulfill requirements. Expected at least 1.55.35, got 1.55.29", nil, true)
  end)

  test("Rejects valid SEV-VCEK with unmet requirements (Turin)", function()
    local vcekPem = io.open("tests/data/vcek-chain-turin.pem", "r"):read("a")
    local reportBytes = base64.decode(
      "BQAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAQACAAAAR2cAAAAAAAAAAAAAAAAAAADg/QvbaqQDCm3eqQc+H87Fvmx4KiyAdaCCXfs9moG5JAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+STdGPFo32D76pN/CwhihNUbGzdt6HK6xDaU9hE01XlnwxgBjeczVQMCPbtQ3uYkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACl5vsLOj2hIt/lL1Fc3bodZO4SPjQCVGOE+S7XckwXs///////////////////////////////////////////AAEAAgAAAEcaAgEAAAAAAAAAAAAAAAAAAAAAAAAAAAA7QgkvacZW0wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAgAAAEc9NwEAPTcBAAABAAIAAABHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAm/dVlLG1wfVTOeYXUwVhIZcbPW8lDHmVtHyp2rYJ96/ETJCFcaaR5eET3fkpPpr7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFEdYZVHZqrmYmQuDg4ppXlH2Kh589X0e7kcOQXq4BL95aPoh19lznUzKwpx3vonoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    assert(reportBytes ~= nil)

    local attestation = RemoteAttestationStubbed:new(vcekPem, reportBytes)
    assert.error_match(function()
      verify(attestation)
    end, "Report's committed version does not fulfill requirements. Expected at least 1.55.65, got 1.55.61", nil, true)
  end)

  test("Rejects invalid attestation report", function()
    local vcekPem = io.open("tests/data/vcek-chain-genoa-v5.pem", "r"):read("a")
    local reportBytes = base64.decode(
      "BQAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAKAAAAAAAbWCUAAAAAAAAAAAAAAAAAAAC7hR4gN0fDaF15opkQ52xTlXiW2/bmiDW2TqLCsr59tgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAvs5zmaTaBUpjouP6Gkf/mMiOOR1DeRJvxOdcZ38lts1r/Y72CahjgEljOsfgDkrBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABi7rIj6+Czg/wjqW/1+ebErc8VNceg/WAmdAfxkwukIf//////////////////////////////////////////CgAAAAAAG1gZEQEAAAAAAAAAAAAAAAAAAAAAAAAAAADgI0vts5GEMfVO4nkHh9evE4pnvh5YGiI2UOgQyUU0K8mujR/qg7McSdyMw020VwvPJb1teTmFaTqfDCEz3zPYCgAAAAAAG1gxNwEAMTcBAAoAAAAAABtYCwAAAAAAAAALAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZYrjOIJQEkOAa96UY4bNzGBfb3rkU/nkYlrJPreawo+VxJapz1dauh50ZJaQlQAnAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALN/WkfrqKgMOMMcOriyKfs6OwtTjsN6iSWKTnl7uQEpVKdNW8vEm/MBFYVbq8iKyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    assert(reportBytes ~= nil)
    reportBytes = reportBytes:sub(1, Offsets.base.signature)
      .. ("W"):rep(512)
      .. reportBytes:sub(Offsets.base.signature + 512 + 1)

    local attestation = RemoteAttestationStubbed:new(vcekPem, reportBytes)
    assert.error_match(function()
      verify(attestation)
    end, "Failed to verify attestation report with SEV-VCEK public key", nil, true)
  end)

  context("Requirements", function()
    local vcekPem = io.open("tests/data/vcek-chain-genoa-v5.pem", "r"):read("a")
    local reportBytes = base64.decode(
      "BQAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAKAAAAAAAbWCUAAAAAAAAAAAAAAAAAAAC7hR4gN0fDaF15opkQ52xTlXiW2/bmiDW2TqLCsr59tgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAvs5zmaTaBUpjouP6Gkf/mMiOOR1DeRJvxOdcZ38lts1r/Y72CahjgEljOsfgDkrBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABi7rIj6+Czg/wjqW/1+ebErc8VNceg/WAmdAfxkwukIf//////////////////////////////////////////CgAAAAAAG1gZEQEAAAAAAAAAAAAAAAAAAAAAAAAAAADgI0vts5GEMfVO4nkHh9evE4pnvh5YGiI2UOgQyUU0K8mujR/qg7McSdyMw020VwvPJb1teTmFaTqfDCEz3zPYCgAAAAAAG1gxNwEAMTcBAAoAAAAAABtYCwAAAAAAAAALAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZYrjOIJQEkOAa96UY4bNzGBfb3rkU/nkYlrJPreawo+VxJapz1dauh50ZJaQlQAnAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALN/WkfrqKgMOMMcOriyKfs6OwtTjsN6iSWKTnl7uQEpVKdNW8vEm/MBFYVbq8iKyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    assert(reportBytes ~= nil)

    test("Rejects invalid TCB version (VCEK VS. reported TCB)", function()
      local attestation = RemoteAttestationStubbed:new(vcekPem, reportBytes)
      attestation.report.reportedTcb.tee = attestation.vcek.tcbVersion.tee + 1

      assert.error_match(
        function()
          verify(attestation)
        end,
        "VCEK's TCB version does not match report's reported TCB version: invalid TEE version. Expected 0, got 1",
        nil,
        true
      )
    end)

    test("Accepts higher committed version", function()
      local attestation = RemoteAttestationStubbed:new(vcekPem, reportBytes)
      attestation.report.committed.major = attestation.requirements.minCommittedVersion.major + 1
      assert.no_error(function()
        verify(attestation)
      end)
    end)

    test("Accepts higher minor with lower build", function()
      local attestation = RemoteAttestationStubbed:new(vcekPem, reportBytes)
      attestation.report.committed.minor = attestation.requirements.minCommittedVersion.minor + 1
      attestation.report.committed.build = 0
      assert.no_error(function()
        verify(attestation)
      end)
    end)

    test("Accepts higher major with lower minor and build", function()
      local attestation = RemoteAttestationStubbed:new(vcekPem, reportBytes)
      attestation.report.committed.major = attestation.requirements.minCommittedVersion.major + 1
      attestation.report.committed.minor = 0
      attestation.report.committed.build = 0
      assert.no_error(function()
        verify(attestation)
      end)
    end)

    test("Rejects invalid committed version", function()
      local attestation = RemoteAttestationStubbed:new(vcekPem, reportBytes)
      attestation.report.committed.build = attestation.requirements.minCommittedVersion.build - 1
      assert.error_match(
        function()
          verify(attestation)
        end,
        "Report's committed version does not fulfill requirements. Expected at least 1.55.49, got 1.55.48",
        nil,
        true
      )
    end)

    test("Rejects invalid committed SNP TCB version", function()
      local attestation = RemoteAttestationStubbed:new(vcekPem, reportBytes)
      attestation.report.committedTcb.snp = attestation.requirements.minCommittedTcbSnp - 1
      assert.error_match(function()
        verify(attestation)
      end, "Expected minimum committed SNP TCB of 27, got 26", nil, true)
    end)

    test("Rejects incomplete alias check", function()
      local attestation = RemoteAttestationStubbed:new(vcekPem, reportBytes)
      attestation.report.platInfo.aliasCheckComplete = false
      assert.error_match(function()
        verify(attestation)
      end, "Expected alias check to have been completed", nil, true)
    end)

    test("Rejects debug-enabled guest policy", function()
      local attestation = RemoteAttestationStubbed:new(vcekPem, reportBytes)
      attestation.report.policy.debugAllowed = true
      assert.error_match(function()
        verify(attestation)
      end, "Debug mode is enabled in guest policy", nil, true)
    end)

    test("Rejects non-guest VMPL", function()
      local attestation = RemoteAttestationStubbed:new(vcekPem, reportBytes)
      attestation.report.vmpl = 4
      assert.error_match(function()
        verify(attestation)
      end, "Expected VMPL <= 3, got 4", nil, true)
    end)

    test("Rejects non-VCEK signing key", function()
      local attestation = RemoteAttestationStubbed:new(vcekPem, reportBytes)
      attestation.report.keyInfo.signingKey = SigningKey.None
      assert.error_match(function()
        verify(attestation)
      end, "Expected signing key VCEK", nil, true)
    end)

    test("Rejects report with missing cpuid fields", function()
      local attestation = RemoteAttestationStubbed:new(vcekPem, reportBytes)
      attestation.report.cpuidFamId = nil
      attestation.report.cpuidStep = nil

      assert.error_match(function()
        verify(attestation)
      end, "Report is missing values for determining CPU type", nil, true)
    end)

    test("Rejects invalid committed microcode version", function()
      local attestation = RemoteAttestationStubbed:new(vcekPem, reportBytes)
      attestation.requirements.minMicrocode = function(_, _)
        return attestation.report.reportedTcb.microcode + 1
      end

      assert.error_match(function()
        verify(attestation)
      end, "Expected minimum microcode version of 89, got 88", nil, true)
    end)
  end)
end)
