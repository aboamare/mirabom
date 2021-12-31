const jose = require('jose')

async function JWS(obj, privateKey, public) {
  const protected = {
    alg: 'ES384'
  }
  if (typeof public === 'string') {
    protected.x5u = public
  } else {
    protected.jwk = public
  }

  console.log(JSON.stringify(protected, null, 2))

  const jws = await new jose.FlattenedSign(new TextEncoder().encode(JSON.stringify(obj)))
    .setProtectedHeader(protected)
    .sign(privateKey)

  console.log(JSON.stringify(jws, null, 2))
  return jws
}


async function getCert () {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES384')
  const public = await jose.exportJWK(publicKey)
  const private = await jose.exportJWK(privateKey)
  console.log(JSON.stringify({
    public,
    private
  }, null, 2))
  
  const req = {
    name: "AboaMare Spirit",
    callSign: "ABCDEF",
    MMSI: "230999999",
    homePort: "FI TKU"
  }

  const jws = await JWS(req, privateKey, public)


  const { payload, protectedHeader } = await jose.flattenedVerify(jws, (protectedHeader) => {
    return jose.importJWK(protectedHeader.jwk, protectedHeader.alg)
  })
  console.log(JSON.stringify(JSON.parse(new TextDecoder().decode(payload)), null, 2))
}

async function getPublicKeyFromCert (pem, alg='ES384') {
  return jose.importX509(pem, alg, {extractable: true})
}

async function authenticate () {

  const privateKey = await jose.importJWK({
    kty: "EC",
    x: "NR1g4V6Q2OOGT5nzgys6iVF8ijcmm7XW4r7zicwSfXaaA7PDekOOEVjeoq6SGJ5l",
    y: "redpwLEmJgOuAJ7drXQblBCBXzMiX-n3sHH7P_9QeP4u4-y87nGCl5EGcDhIqMoP",
    crv: "P-384",
    d: "QjCXRNIa5Xru3zSnKcXyzmGuLo34kEXBKcJRxSa2VssNy470FlM64JWiP0Hm-srk"
  }, 'ES384')

  const public = "https://mir.aboamare.net/test/certificates/1da3a11b1ab76ea926b51ff95c793b71ea175e33.x5u"
  const claims = {
    nonce: "bohQwng72K",
    sub: "urn:mrn:mcp:id:aboamare:test:aboamare-spirit"
  }

  const protected = {
    alg: 'ES384',
    x5u: public
  }
  
  console.log(JSON.stringify(protected, null, 2))

  const jwt = await new jose.SignJWT(claims)
    .setProtectedHeader(protected)
    .setIssuedAt()
    .setExpirationTime('2h')
    .sign(privateKey)
  console.log(jwt)

  const pem = `-----BEGIN CERTIFICATE-----
  MIIC9DCCAnmgAwIBAgIGAX4MVvjkMAoGCCqGSM49BAMDMC4xLDAqBgoJkiaJk/Is
  ZAEBDBx1cm46bXJuOm1jcDppZDphYm9hbWFyZTp0ZXN0MB4XDTIxMTIzMDE3MTUz
  M1oXDTIzMTIzMTE3MTUzM1owPjE8MDoGCgmSJomT8ixkAQEMLHVybjptcm46bWNw
  OmlkOmFib2FtYXJlOnRlc3Q6YWJvYW1hcmUtc3Bpcml0MHYwEAYHKoZIzj0CAQYF
  K4EEACIDYgAENR1g4V6Q2OOGT5nzgys6iVF8ijcmm7XW4r7zicwSfXaaA7PDekOO
  EVjeoq6SGJ5lredpwLEmJgOuAJ7drXQblBCBXzMiX+n3sHH7P/9QeP4u4+y87nGC
  l5EGcDhIqMoPo4IBVDCCAVAwcgYDVR0RBGswaaAgBhRpgrmI8MCbr/jHy6m9wICq
  rteKG6AIDAZBQkNERUagIwYUaYPuloSAm6/4x8uLqcCAqq7XihugCwwJMjMwOTk5
  OTk5oCAGFGmDreLv99u5krbJoo3fjpC7/+5LoAgMBkZJIFRLVTAdBgNVHQ4EFgQU
  p8VMbYqWwowvusyGGw1xswy55IQwHwYDVR0jBBgwFoAUoRxLRep7qHEbNfgCJzwZ
  oavKEMowCwYDVR0PBAQDAgCAMBkGA1UdJQQSMBAGBFUdJQAGCCsGAQUFBwMCMDIG
  A1UdHwQrMCkwJ6AloCOGIWh0dHBzOi8vbWlyLmFib2FtYXJlLm5ldC90ZXN0L2Ny
  bDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHBzOi8vbWlyLmFib2Ft
  YXJlLm5ldC90ZXN0L29jc3AwCgYIKoZIzj0EAwMDaQAwZgIxAK6F/LbToC4maeh6
  bTlATOSS3HD64ql6SwZ1MftTwAU15P5wzzPvH16FHXOcJ20w1gIxAMWhsarEdB5j
  Wy3wfoheQzJpEYiJiB5h+26NkkAZcCFWNhIL7RFM0GNiV6kkDq97Hw==
  -----END CERTIFICATE-----
  `
  
  const publicKey = await getPublicKeyFromCert(pem)
  const jwk = await jose.exportJWK(publicKey)
  console.log(JSON.stringify(jwk, null, 2))
  const { payload, protectedHeader } = await jose.jwtVerify(jwt, publicKey)
  console.log(JSON.stringify(protectedHeader, null, 2))
  console.log(JSON.stringify(payload, null, 2))

}

authenticate().then(() => process.exit(0))