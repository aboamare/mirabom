const jose = require('jose')

async function test () {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES384')
  const public = await jose.exportJWK(publicKey)
  console.log(public)

  const req = {
    name: "AboaMare Spirit",
    callSign: "ABCDEF",
    MMSI: "230999999",
    homePort: "FI TKU"
  }

  const jws = await new jose.FlattenedSign(new TextEncoder().encode(JSON.stringify(req)))
    .setProtectedHeader({
      alg: 'ES384',
      jwk: public
    })
    .sign(privateKey)

  console.log(JSON.stringify(jws))

  const { payload, protectedHeader } = await jose.flattenedVerify(jws, (protectedHeader, token) => {
    return jose.importJWK(protectedHeader.jwk, protectedHeader.alg)
  })

  console.log(new TextDecoder().decode(payload))
}

test().then(() => process.exit(0))