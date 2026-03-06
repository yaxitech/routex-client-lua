-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

local asn = require("routex-client.vendor.tls13.asn")
local base64 = require("routex-client.util.base64")
local bitstring = require("routex-client.vendor.tls13.asn.bitstring")
local oid = require("routex-client.vendor.tls13.asn.oid")
local util = require("routex-client.vendor.tls13.util")
local utilMap = require("routex-client.vendor.tls13.util.map")
local x509 = require("routex-client.vendor.tls13.x509")
require("routex-client.attestation.vcek") -- registers AMD SEV-SNP OID

-- https://github.com/OpenPrograms/Fingercomp-Programs/blob/a6f0561/libtls13/test/x509.lua#L10
-- ASL-2.0
local function loadPemFile(path)
  local certs = {}
  local certLines = nil
  local caName

  for line in io.lines(path) do
    line = line:gsub("\r", "")

    if certLines then
      if line:sub(1, 5) == "-----" then
        table.insert(certs, {
          caName,
          assert(base64.decode(table.concat(certLines))),
        })
        certLines = nil
      else
        table.insert(certLines, line)
      end
    elseif line:sub(1, 1) == "#" then
      caName = line:sub(3)
    elseif line:sub(1, 5) == "-----" then
      certLines = {}
    end
  end

  return certs
end

test("Registers AMD SEV-SNP OIDs", function()
  assert.is_not_nil(oid.amdSnp)
end)

context("VCEK Chain Milan", function()
  local chain = loadPemFile("tests/data/vcek-chain-milan.pem")

  for _, element in ipairs(chain) do
    local name, certDer = table.unpack(element)
    local certAsn = asn.decode(certDer)
    local cert = x509.parseCertificateFromAsn(certAsn)
    assert(cert ~= nil)

    assert:set_parameter("TableFormatLevel", -1)
    assert.is_not_nil(cert.tbsCertificate)

    if name == "SEV-VCEK" then
      test("AMD " .. name, function()
        assert.same({
          tbsCertificate = {
            version = 3,
            serialNumber = util.fromHex("0000000000000000"),
            issuer = {
              {
                { type = oid.at.organizationalUnitName, value = "Engineering" },
              },
              {
                { type = oid.at.countryName, value = "US" },
              },
              {
                { type = oid.at.localityName, value = "Santa Clara" },
              },
              {
                { type = oid.at.stateOrProvinceName, value = "CA" },
              },
              {
                { type = oid.at.organizationName, value = "Advanced Micro Devices" },
              },
              {
                { type = oid.at.commonName, value = "SEV-Milan" },
              },
            },
            signature = {
              algorithm = oid.pkcs1.rsassaPss,
              parameters = {
                hashAlgorithm = {
                  algorithm = oid.hashalgs.sha384,
                  parameters = false,
                },
                maskGenAlgorithm = {
                  algorithm = oid.pkcs1.mgf1,
                  parameters = {
                    algorithm = oid.hashalgs.sha384,
                    parameters = false,
                  },
                },
                saltLength = 48,
                trailerField = 1,
              },
            },
            validity = {
              -- 2025-01-15 21:21:54 UTC
              notBefore = {
                year = 2025,
                month = 1,
                day = 15,
                hour = 21,
                minute = 21,
                second = 54,
              },
              -- 2032-01-15 21:21:54 UTC
              notAfter = {
                year = 2032,
                month = 1,
                day = 15,
                hour = 21,
                minute = 21,
                second = 54,
              },
            },
            subject = {
              {
                { type = oid.at.organizationalUnitName, value = "Engineering" },
              },
              {
                { type = oid.at.countryName, value = "US" },
              },
              {
                { type = oid.at.localityName, value = "Santa Clara" },
              },
              {
                { type = oid.at.stateOrProvinceName, value = "CA" },
              },
              {
                { type = oid.at.organizationName, value = "Advanced Micro Devices" },
              },
              {
                { type = oid.at.commonName, value = "SEV-VCEK" },
              },
            },
            subjectPublicKeyInfo = {
              algorithm = {
                algorithm = oid.ansiX962.keyType.ecPublicKey,
                parameters = {
                  namedCurve = oid.iso.identifiedOrganization.certicom.curve.ansip384r1,
                },
              },
              subjectPublicKey = bitstring.fromHex(
                "042fcfe69e9999cb4444fcb1418893ac0db1d22f1ae7b0ef81cd159f84547c17569cdcfd041e84bbb6fa822f7fa37a50cf7d4a4c0acb4a6734fcd5df3a9019ec344f0c8ba8e5d02a0c095eee601777502702f32cc78a71972558d0edc45d4038ca"
              ),
            },
            extensions = utilMap.makeProjectionMap(tostring, {
              [oid.amdSnp.structVersion] = {
                extnID = oid.amdSnp.structVersion,
                critical = false,
                extnValue = 0,
              },
              [oid.amdSnp.productName] = {
                extnID = oid.amdSnp.productName,
                critical = false,
                extnValue = "Milan-B0",
              },
              [oid.amdSnp.tcbVersion.blSPL] = {
                extnID = oid.amdSnp.tcbVersion.blSPL,
                critical = false,
                extnValue = 4,
              },
              [oid.amdSnp.tcbVersion.teeSPL] = {
                extnID = oid.amdSnp.tcbVersion.teeSPL,
                critical = false,
                extnValue = 0,
              },
              [oid.amdSnp.tcbVersion.spl_4] = {
                extnID = oid.amdSnp.tcbVersion.spl_4,
                critical = false,
                extnValue = 0,
              },
              [oid.amdSnp.tcbVersion.spl_5] = {
                extnID = oid.amdSnp.tcbVersion.spl_5,
                critical = false,
                extnValue = 0,
              },
              [oid.amdSnp.tcbVersion.spl_6] = {
                extnID = oid.amdSnp.tcbVersion.spl_6,
                critical = false,
                extnValue = 0,
              },
              [oid.amdSnp.tcbVersion.spl_7] = {
                extnID = oid.amdSnp.tcbVersion.spl_7,
                critical = false,
                extnValue = 0,
              },
              [oid.amdSnp.tcbVersion.snpSPL] = {
                extnID = oid.amdSnp.tcbVersion.snpSPL,
                critical = false,
                extnValue = 24,
              },
              [oid.amdSnp.tcbVersion.ucodeSPL] = {
                extnID = oid.amdSnp.tcbVersion.ucodeSPL,
                critical = false,
                extnValue = 219,
              },
              [oid.amdSnp.hwID] = {
                extnID = oid.amdSnp.hwID,
                critical = false,
                extnValue = util.fromHex(
                  "a3fdc2c64dc299ab90d4238973864b586378e2e5ef9c9d4dc608f3bdaa89a969a03f1b5752cad55a0c1547ade800dbd7404e9cb3f9738da3b280d1df69cf82e4"
                ),
              },
            }),
          },
          signatureAlgorithm = {
            algorithm = oid.pkcs1.rsassaPss,
            parameters = {
              hashAlgorithm = {
                algorithm = oid.hashalgs.sha384,
                parameters = false,
              },
              maskGenAlgorithm = {
                algorithm = oid.pkcs1.mgf1,
                parameters = {
                  algorithm = oid.hashalgs.sha384,
                  parameters = false,
                },
              },
              saltLength = 48,
              trailerField = 1,
            },
          },
          signatureValue = bitstring.fromHex(
            "045f85a4787bcca2d4f6ffa736f079bf3db220df6982c6da2c15421437e1801e109defa36f7c9d3e2a4d2cfa86e078a217d4fda15a96bb5699454ce72013a1ea32fd971d135e3a1b4c452c6549e5cb9e8a5cf00eccc69310e53a49ae31bcffcedc60b56a8def3c92bedfe927bc052e6327b9937eb857e5b0b78847de7f0325b007dc4d5b60b7f088fff1f3d389a9da1182f5dd0d8a6de46adbd54c4aa9ae7456628562f0cbc94833788d7d912c54cbbcf607e7b3dcb38b4fd70ec1de54c2ec32728426eb1ef40091c369be2f09fd40475dab5413d62e2e0805151be73c4dd0337b14fa99d8bb89b9a44d6ddf69ceadfbc704b4bf458d9341aaa72b767e01f541f918d3eb2d6845d76815445bf38d22e056f36cc0529ed6bc28eba610f04c829fe3a1757b9f77b41c8df7d0734cca34f04eb5a086af3f7f30bf667cc8250e05570ab5b71f3a8aa88a7b44d3d8d4f62161a459d66e344b28190d2218d927e113488b450b175f0acd62d883913424c6335efe72a4944c4ecad82331c652416d76243c8199151a6c073fd8457685684fac5fe7047b97f0f1cba0918b0a042107edf94882db413f914aff1dafe5e5792f75e9c3752cfb904b44497c12e8b083954f15673290723986e01bb169bae1cce4d325fae005837cd6962543ab2c1c3543ba0a8f5b96378a830d9a4d21ee9e790a5920a584fe2851ca12c239053ce08550458b"
          ),
        }, cert)
      end)
    end
  end
end)

context("VCEK Chain Genoa", function()
  local chain = loadPemFile("tests/data/vcek-chain-genoa.pem")

  for _, element in ipairs(chain) do
    local name, certDer = table.unpack(element)
    local certAsn = asn.decode(certDer)
    local cert, err = x509.parseCertificateFromAsn(certAsn)

    assert:set_parameter("TableFormatLevel", -1)
    assert.is_not.nil_(cert.tbsCertificate)

    if name == "SEV-VCEK" then
      test("AMD " .. name, function()
        assert.same({
          tbsCertificate = {
            version = 3,
            serialNumber = util.fromHex("0000000000000000"),
            issuer = {
              {
                { type = oid.at.organizationalUnitName, value = "Engineering" },
              },
              {
                { type = oid.at.countryName, value = "US" },
              },
              {
                { type = oid.at.localityName, value = "Santa Clara" },
              },
              {
                { type = oid.at.stateOrProvinceName, value = "CA" },
              },
              {
                { type = oid.at.organizationName, value = "Advanced Micro Devices" },
              },
              {
                { type = oid.at.commonName, value = "SEV-Genoa" },
              },
            },
            signature = {
              algorithm = oid.pkcs1.rsassaPss,
              parameters = {
                hashAlgorithm = {
                  algorithm = oid.hashalgs.sha384,
                  parameters = false,
                },
                maskGenAlgorithm = {
                  algorithm = oid.pkcs1.mgf1,
                  parameters = {
                    algorithm = oid.hashalgs.sha384,
                    parameters = false,
                  },
                },
                saltLength = 48,
                trailerField = 1,
              },
            },
            validity = {
              notBefore = {
                year = 2025,
                month = 7,
                day = 20,
                hour = 22,
                minute = 15,
                second = 42,
              },
              notAfter = {
                year = 2032,
                month = 7,
                day = 20,
                hour = 22,
                minute = 15,
                second = 42,
              },
            },
            subject = {
              {
                { type = oid.at.organizationalUnitName, value = "Engineering" },
              },
              {
                { type = oid.at.countryName, value = "US" },
              },
              {
                { type = oid.at.localityName, value = "Santa Clara" },
              },
              {
                { type = oid.at.stateOrProvinceName, value = "CA" },
              },
              {
                { type = oid.at.organizationName, value = "Advanced Micro Devices" },
              },
              {
                { type = oid.at.commonName, value = "SEV-VCEK" },
              },
            },
            subjectPublicKeyInfo = {
              algorithm = {
                algorithm = oid.ansiX962.keyType.ecPublicKey,
                parameters = {
                  namedCurve = oid.iso.identifiedOrganization.certicom.curve.ansip384r1,
                },
              },
              subjectPublicKey = bitstring.fromHex(
                "044AB0A6F9F085E7512A1E5A14AA1521C86CB0E3049F2CAF908B2DDE0610CB8C8"
                  .. "53CA94EE398D4F0D10E6F464EAA884F105A80C0892C8DDFC4FA12AF1C9131A7A9"
                  .. "91A42B95819BC3BDAFBBC7E7AA769CA2DCFB0B89F60CD6FF237886F3903E45BB"
              ),
            },
            extensions = utilMap.makeProjectionMap(tostring, {
              [oid.amdSnp.structVersion] = {
                extnID = oid.amdSnp.structVersion,
                critical = false,
                extnValue = 0,
              },
              [oid.amdSnp.productName] = {
                extnID = oid.amdSnp.productName,
                critical = false,
                extnValue = "Genoa",
              },
              [oid.amdSnp.tcbVersion.blSPL] = {
                extnID = oid.amdSnp.tcbVersion.blSPL,
                critical = false,
                extnValue = 9,
              },
              [oid.amdSnp.tcbVersion.teeSPL] = {
                extnID = oid.amdSnp.tcbVersion.teeSPL,
                critical = false,
                extnValue = 0,
              },
              [oid.amdSnp.tcbVersion.spl_4] = {
                extnID = oid.amdSnp.tcbVersion.spl_4,
                critical = false,
                extnValue = 0,
              },
              [oid.amdSnp.tcbVersion.spl_5] = {
                extnID = oid.amdSnp.tcbVersion.spl_5,
                critical = false,
                extnValue = 0,
              },
              [oid.amdSnp.tcbVersion.spl_6] = {
                extnID = oid.amdSnp.tcbVersion.spl_6,
                critical = false,
                extnValue = 0,
              },
              [oid.amdSnp.tcbVersion.spl_7] = {
                extnID = oid.amdSnp.tcbVersion.spl_7,
                critical = false,
                extnValue = 0,
              },
              [oid.amdSnp.tcbVersion.snpSPL] = {
                extnID = oid.amdSnp.tcbVersion.snpSPL,
                critical = false,
                extnValue = 23,
              },
              [oid.amdSnp.tcbVersion.ucodeSPL] = {
                extnID = oid.amdSnp.tcbVersion.ucodeSPL,
                critical = false,
                extnValue = 72,
              },
              [oid.amdSnp.hwID] = {
                extnID = oid.amdSnp.hwID,
                critical = false,
                extnValue = util.fromHex(
                  "9dc99962c063029e430b6f7b734075ec542f4f3ec639e657e14585d3fe559b38"
                    .. "532bc42d037d618317694ad6634d2507964e276c8eedeac4978c7006bf89f8e1"
                ),
              },
            }),
          },
          signatureAlgorithm = {
            algorithm = oid.pkcs1.rsassaPss,
            parameters = {
              hashAlgorithm = {
                algorithm = oid.hashalgs.sha384,
                parameters = false,
              },
              maskGenAlgorithm = {
                algorithm = oid.pkcs1.mgf1,
                parameters = {
                  algorithm = oid.hashalgs.sha384,
                  parameters = false,
                },
              },
              saltLength = 48,
              trailerField = 1,
            },
          },
          signatureValue = bitstring.fromHex(
            "58c555e0d3e6995186ab221741c37b4c7142e661065ba1243cedc634f5f749e2"
              .. "0f89c72493d8a267da8239f2f3f5fbbca8c96c46cc53cb5f212a3aa54b744bbd"
              .. "f577d5fa6145835929af12d16582fec0df2b4c91246da2da0ddb173c5a22da5b"
              .. "5dd94c817de162acb29557a9a4286ec2605d950ec216b6d9fe5aeedcaf6fe047"
              .. "ab960b826c49fc806b6c188b7cd22346513d35ee075a6bae60e6c3e79d148294"
              .. "7c6ea55b7c603d0b949f32c3e99c2338c0a2f980f716a902b8d443fca20aa95b"
              .. "43c8992156646dc88b6e37af9c89003b6612f943a687797c6514e6845c5ac777"
              .. "f1619ac6a9bf349c9d76be6607a1aca04d8afd0274d8374eb17a5f213b6d5161"
              .. "ef7bd540e4a89c4c40f1e0ba5abaa3d5283710947cd1c9ed1cbce927d265dbc6"
              .. "822c5e30557adc988697f3bdac0881cf3becf9f5f27094d2257d5768ca387032"
              .. "84d88df0ad62133c0af1916e7511263f787bec638840e095accf08c2bfb4a144"
              .. "5ccc9675e7b82116451ee4eba9e8f84f2f171e05113a327062dcdf505915c10b"
              .. "9f3d7e4d5b518aee348f9ba3eb5016bc94e0192a366f1c6159f4f90064dd79a3"
              .. "7312d045decda18083412983a9416b3eee02708db474ec470fd1a46d8095d22d"
              .. "ccbe473b32fa96b3a17cfa8c2ad169e1de32573d9119e7c3f2c28ee40c88da1c"
              .. "f87001d2d1e7a594819808aa3c46be682029a9910578b1e3ffe5da9ef008a933"
          ),
        }, cert)
      end)
    end
  end
end)

context("VCEK Chain Turin", function()
  local chain = loadPemFile("tests/data/vcek-chain-turin.pem")

  for _, element in ipairs(chain) do
    local name, certDer = table.unpack(element)
    local certAsn = asn.decode(certDer)
    local cert, err = x509.parseCertificateFromAsn(certAsn)

    assert:set_parameter("TableFormatLevel", -1)
    assert.is_not.nil_(cert.tbsCertificate)

    if name == "SEV-VCEK" then
      test("AMD " .. name, function()
        assert.same({
          tbsCertificate = {
            version = 3,
            serialNumber = util.fromHex("0000000000000000"),
            issuer = {
              {
                { type = oid.at.organizationalUnitName, value = "Engineering" },
              },
              {
                { type = oid.at.countryName, value = "US" },
              },
              {
                { type = oid.at.localityName, value = "Santa Clara" },
              },
              {
                { type = oid.at.stateOrProvinceName, value = "CA" },
              },
              {
                { type = oid.at.organizationName, value = "Advanced Micro Devices" },
              },
              {
                { type = oid.at.commonName, value = "SEV-Turin" },
              },
            },
            signature = {
              algorithm = oid.pkcs1.rsassaPss,
              parameters = {
                hashAlgorithm = {
                  algorithm = oid.hashalgs.sha384,
                  parameters = false,
                },
                maskGenAlgorithm = {
                  algorithm = oid.pkcs1.mgf1,
                  parameters = {
                    algorithm = oid.hashalgs.sha384,
                    parameters = false,
                  },
                },
                saltLength = 48,
                trailerField = 1,
              },
            },
            validity = {
              -- 2025-07-17 17:04:46 UTC
              notBefore = {
                year = 2025,
                month = 7,
                day = 17,
                hour = 17,
                minute = 04,
                second = 46,
              },
              -- 2032-07-17 17:04:46 UTC
              notAfter = {
                year = 2032,
                month = 7,
                day = 17,
                hour = 17,
                minute = 04,
                second = 46,
              },
            },
            subject = {
              {
                { type = oid.at.organizationalUnitName, value = "Engineering" },
              },
              {
                { type = oid.at.countryName, value = "US" },
              },
              {
                { type = oid.at.localityName, value = "Santa Clara" },
              },
              {
                { type = oid.at.stateOrProvinceName, value = "CA" },
              },
              {
                { type = oid.at.organizationName, value = "Advanced Micro Devices" },
              },
              {
                { type = oid.at.commonName, value = "SEV-VCEK" },
              },
            },
            subjectPublicKeyInfo = {
              algorithm = {
                algorithm = oid.ansiX962.keyType.ecPublicKey,
                parameters = {
                  namedCurve = oid.iso.identifiedOrganization.certicom.curve.ansip384r1,
                },
              },
              subjectPublicKey = bitstring.fromHex(
                "04156d336880cd1031a732a3ad66c4e3927de675d6ec38d798d1ab3892fa0a3506e5f97fa5a9747ab6a6e87703ea20fbf1fa624acdbf03addd16bd1657fabe466956559499113c6468794a13eddd0a69e0a1214282c2fa5bba233f38172e511a26"
              ),
            },
            extensions = utilMap.makeProjectionMap(tostring, {
              [oid.amdSnp.structVersion] = {
                extnID = oid.amdSnp.structVersion,
                critical = false,
                extnValue = 1,
              },
              [oid.amdSnp.productName] = {
                extnID = oid.amdSnp.productName,
                critical = false,
                extnValue = "Turin",
              },
              [oid.amdSnp.tcbVersion.fmcSPL] = {
                extnID = oid.amdSnp.tcbVersion.fmcSPL,
                critical = false,
                extnValue = 0,
              },
              [oid.amdSnp.tcbVersion.blSPL] = {
                extnID = oid.amdSnp.tcbVersion.blSPL,
                critical = false,
                extnValue = 1,
              },
              [oid.amdSnp.tcbVersion.teeSPL] = {
                extnID = oid.amdSnp.tcbVersion.teeSPL,
                critical = false,
                extnValue = 0,
              },
              [oid.amdSnp.tcbVersion.spl_5] = {
                extnID = oid.amdSnp.tcbVersion.spl_5,
                critical = false,
                extnValue = 0,
              },
              [oid.amdSnp.tcbVersion.spl_6] = {
                extnID = oid.amdSnp.tcbVersion.spl_6,
                critical = false,
                extnValue = 0,
              },
              [oid.amdSnp.tcbVersion.spl_7] = {
                extnID = oid.amdSnp.tcbVersion.spl_7,
                critical = false,
                extnValue = 0,
              },
              [oid.amdSnp.tcbVersion.snpSPL] = {
                extnID = oid.amdSnp.tcbVersion.snpSPL,
                critical = false,
                extnValue = 2,
              },
              [oid.amdSnp.tcbVersion.ucodeSPL] = {
                extnID = oid.amdSnp.tcbVersion.ucodeSPL,
                critical = false,
                extnValue = 71,
              },
              [oid.amdSnp.hwID] = {
                extnID = oid.amdSnp.hwID,
                critical = false,
                extnValue = util.fromHex("3b42092f69c656d3"),
              },
            }),
          },
          signatureAlgorithm = {
            algorithm = oid.pkcs1.rsassaPss,
            parameters = {
              hashAlgorithm = {
                algorithm = oid.hashalgs.sha384,
                parameters = false,
              },
              maskGenAlgorithm = {
                algorithm = oid.pkcs1.mgf1,
                parameters = {
                  algorithm = oid.hashalgs.sha384,
                  parameters = false,
                },
              },
              saltLength = 48,
              trailerField = 1,
            },
          },
          signatureValue = bitstring.fromHex(
            "9233c3d997ed1634904f473dcea623e49ad3d572247f105bd5d868b506a3f4bc9b41137cf721da3a950ea96b9a0344086dbfb50d159eb89573cb1af3c9927ae32e53dfb519444b5a59b5689622759513647d5014b17af849063c6b5e3b20d3a4bdee02c248ef34359c88043e4cf1499d146228bf30e6b34a2bd6d99f9be4c82b34eb939584516b62a09cd2aaa36fd16b804af6deb5cc0ceeb2d0dd12f07a4b05f1deb80a87661cd9195f180bf251944bcdd108de40b40b41ad316c028597360f1afcb7539f68c0a2364c2bc4185c570eca2266a601092c9876c0f2cbe2448bbdc27ca89b10db601d7bfa1cb1116694681b1c4abb3df6ca712db6388165ec1637fd3db297cc065eff6bf7ac2b4181b86e109f95897d52a3210b781c9dbe475048c57e828bec31801c6540ba4d94d19fe149ff317af5d52f87b41a3a4e0a32d215419060e5aaf01d6431237e10fdd13d66ad57817e1a12d8d8cb97ddea04fefbcb7565b4a301ec3578280513805cef41b90b124fde72e2e197e557a52aab767047bd66dfdcbccd454a003e625973fb60cdf12667a8e9175c691ec751b7a53f6fd3b36faa9c74db31c6654473c1eafd0bbf289c782804869069b7f1f2bfa20e15e68466176e667ed89fae0fd35f60edac16b0a01a83103c40bca9431a2b976b564a9fb7d40798fbf5c874d45dd0aa8a89ad96dd8dbf12c17a821feb97ac24ee7943"
          ),
        }, cert)
      end)
    end
  end
end)
