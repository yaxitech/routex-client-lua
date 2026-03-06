-- SPDX-License-Identifier: MIT
-- Author: Vincent Haupert <vincent.haupert@yaxi.tech>

--- This far from an implementation supporting arbitrary X.509 certificates and algorithms.
--- In fact, it only supports verifying issuer signatures which use PKCS#1 RSASSA-PSS with SHA-384.
--- Retrieving the public key is also limited to PKCS#1 RSASSA-PSS with SHA-384 but additionally
--- supports EC P-384 with SHA-384.

local asn = require("routex-client.vendor.tls13.asn")
local dateutil = require("routex-client.util.date")
local log = require("routex-client.logging").defaultLogger()
local oid = require("routex-client.vendor.tls13.asn.oid")
local secp384r1 = require("routex-client.vendor.tls13.crypto.secp384r1")
local sha2 = require("routex-client.vendor.tls13.crypto.hash.sha2")
local sigalg = require("routex-client.vendor.tls13.sigalg")
local util = require("routex-client.util")
local x509 = require("routex-client.vendor.tls13.x509")

-- We only support certificates signed with PKCS#1 RSASSA-PSS SHA-384
local rsaPssRsaeSha384 = sigalg.makeRsaPssRsaeSigAlg(sha2.sha384)
-- SEV-VCEK public key is always P-384 with SHA-384
local ecdsaSecp384r1Sha384 = sigalg.makeEcdsaSecp384r1SigAlg()

-- Recursive function to compare two tables deeply
local function deepEqual(t1, t2)
  -- If one isn't a table, use a primitive compare
  if type(t1) ~= "table" or type(t2) ~= "table" then
    return t1 == t2
  end

  -- Compare the number of keys
  local count1, count2 = 0, 0
  for _ in pairs(t1) do
    count1 = count1 + 1
  end
  for _ in pairs(t2) do
    count2 = count2 + 1
  end

  if count1 ~= count2 then
    return false
  end

  -- Compare each key-value pair
  for key, value in pairs(t1) do
    if not deepEqual(value, t2[key]) then
      return false
    end
  end

  return true
end

---Parse the given DER-encoded X.509 certificate
---@param certDer binary
---@return table @Parsed X.509 certificate
---@return binary @Raw tbsCertificate bytes
local function parseCertificate(certDer)
  local certAsn, err
  certAsn, err = asn.decode(certDer)
  if certAsn == nil then
    error(string.format("Failed to parse certificate DER as ASN.1: %s", err))
  end

  if certAsn.TAG ~= asn.asnTags.universal.sequence or not certAsn[1] then
    error("Passed certificate is not an X.509 certificate")
  end
  local tbsCertificate = certDer:sub(certAsn[1].START, certAsn[1].END)

  ---@diagnostic disable-next-line redefined-local
  local cert, err = x509.parseCertificateFromAsn(certAsn)
  if cert == nil then
    error(string.format("Failed to parse certificate ASN.1 as X.509: %s", err))
  end

  return cert, tbsCertificate
end

---Get the common name
---@param field table
---@return string
local function getCommonName(field)
  for _, elements in ipairs(field) do
    for _, element in ipairs(elements) do
      if element.type == oid.at.commonName then
        return element.value
      end
    end
  end
  error(("Failed to get common name for %s"):format(field))
end

---@class YAXI.Attestation.X509.PublicKey
---@field bytes binary Public key bytes
---@field verify fun(self, message: binary, signature: binary): boolean

---@return YAXI.Attestation.X509.PublicKey
local function publicKeyFromSubjectPublicKeyInfo(spki)
  local algo
  if spki.algorithm.algorithm == oid.pkcs1.rsaEncryption then
    algo = rsaPssRsaeSha384
  elseif
    spki.algorithm.algorithm == oid.ansiX962.keyType.ecPublicKey
    and spki.algorithm.parameters.namedCurve == oid.iso.identifiedOrganization.certicom.curve.ansip384r1
  then
    algo = {
      decodePublicKey = ecdsaSecp384r1Sha384.decodePublicKey,
      verify = function(_self, publicKey, signedMessage, rawSignature)
        -- We don't use ecdsaSecp384r1Sha384:verify since it expects an ASN.1 encoded signature and it seems more work to do that
        local r, s = rawSignature:sub(1, 48), rawSignature:sub(48 + 1)
        return secp384r1.ecdsaVerifySha384(signedMessage, r, s, publicKey)
      end,
    }
  else
    error(("Unsupported subjectPublicKeyInfo algorithm: %s"):format(spki.algorithm.algorithm))
  end
  assert(algo)

  local pk, err = algo:decodePublicKey(spki)
  if pk == nil then
    error(("Failed to parse subjectPublicKeyInfo with %s: %s"):format(spki.algorithm.algorithm, err))
  end

  return {
    bytes = pk,
    verify = function(self, message, signature)
      return algo:verify(self.bytes, message, signature)
    end,
  }
end

---@class YAXI.Attestation.X509.Certificate: YAXI.ClassBase
---@field commonName string Subject common name
---@field notBefore integer Not before validity timestamp
---@field notAfter integer Not after validity timestamp
---@field isCa boolean Whether this is a certificate authority
---@field verifiedAt integer?
---@field protected _der binary DER-encoded input X.509 certificate
---@field protected _inner table tls13 X.509 certificate
---@field protected _tbsCertificateBytes binary Raw X.509 tbsCertificate bytes
local Certificate = util.class()

---Create a new instance
---@param pemOrDer string
---@return YAXI.Attestation.X509.Certificate
function Certificate:new(pemOrDer)
  local obj = setmetatable({}, self)
  if pemOrDer:find("-----BEGIN CERTIFICATE-----") then
    obj._der = util.derFromPem(pemOrDer)
  else
    obj._der = pemOrDer
  end
  obj._inner, obj._tbsCertificateBytes = parseCertificate(obj._der)
  obj.commonName = getCommonName(obj._inner.tbsCertificate.subject)
  obj.notBefore = os.time(obj._inner.tbsCertificate.validity.notBefore)
  obj.notAfter = os.time(obj._inner.tbsCertificate.validity.notAfter)
  local basicConstraints = obj:getExtensionValue(oid.ce.basicConstraints)
  obj.isCa = basicConstraints and basicConstraints.cA == true or false
  return obj
end

---Verify the certificate with the given issuer certificate
---@param issuer YAXI.Attestation.X509.Certificate DER-encoded X.509 certificate that issue this instance's certificate
function Certificate:verify(issuer)
  -- Verify issuer
  if not deepEqual(self._inner.tbsCertificate.issuer, issuer._inner.tbsCertificate.subject) then
    error(
      string.format(
        "Expected issuer %s, got: %s",
        getCommonName(self._inner.tbsCertificate.issuer),
        getCommonName(issuer._inner.tbsCertificate.subject)
      )
    )
  end

  -- Verify signing algorithm (We only support PKCS#1 RSASSA-PSS SHA-384)
  if self._inner.signatureAlgorithm.algorithm ~= oid.pkcs1.rsassaPss then
    error(
      string.format(
        "SEV-VCEK: Expected signature algorithm %s, got: %s",
        oid.pkcs1.rsassaPss,
        self._inner.signatureAlgorithm.algorithm
      )
    )
  end
  if self._inner.signatureAlgorithm.parameters.hashAlgorithm.algorithm ~= oid.hashalgs.sha384 then
    error(
      string.format(
        "SEV-VCEK: Expected signature hash algorithm %s, got: %s",
        oid.hashalgs.sha384,
        self._inner.signatureAlgorithm.parameters.hashAlgorithm.algorithm
      )
    )
  end

  -- Verify signature
  local issuerPublicKey = publicKeyFromSubjectPublicKeyInfo(issuer._inner.tbsCertificate.subjectPublicKeyInfo)
  local valid = issuerPublicKey:verify(self._tbsCertificateBytes, self._inner.signatureValue:toBytes())
  if valid then
    log:debug(
      "[%s] Verified issuer from %s%s",
      self.commonName,
      issuer.commonName,
      self._inner == issuer._inner and " (self-signed)" or ""
    )
  else
    error(
      string.format(
        "Failed to verify certificate %s with issuer %s: invalid signature",
        self.commonName,
        issuer.commonName
      )
    )
  end

  -- Verify validity
  local now = os.time()
  if now > self.notAfter then
    error(("Certificate %s has expired since %s"):format(self.commonName, dateutil.toIso8601(self.notAfter)))
  elseif now < self.notBefore then
    error(("Certificate %s is not valid before %s"):format(self.commonName, dateutil.toIso8601(self.notBefore)))
  end

  self.verifiedAt = now
end

---Get the certificate's public key to verify a message signature
---@return YAXI.Attestation.X509.PublicKey
function Certificate:getPublicKey()
  return publicKeyFromSubjectPublicKeyInfo(self._inner.tbsCertificate.subjectPublicKeyInfo)
end

---Get the value of the X.509 extension with the given OID
---Raises an error if the extension is not present.
---@param oid string
---@return any|nil
---@diagnostic disable-next-line redefine-local
function Certificate:getExtensionValue(oid)
  local extn = self._inner.tbsCertificate.extensions[oid]
  return extn and extn.extnValue or nil
end

---@diagnostic disable-next-line: undefined-field
function Certificate.toString(self)
  ---@diagnostic disable: undefined-field
  local msg = util.propsToMsg({
    { verified = self.verifiedAt and ("yes (%s)"):format(dateutil.toIso8601(self.verifiedAt)) or "no" },
    { issuer = getCommonName(self._inner.tbsCertificate.issuer) },
    { ca = (self.isCa and "yes" or "no") },
    { notBefore = dateutil.toIso8601(self.notBefore) },
    { notAfter = dateutil.toIso8601(self.notAfter) },
  })

  return ("[Certificate %s] %s"):format(self.commonName, msg)
end

return {
  Certificate = Certificate,
}
