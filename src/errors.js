class MirError extends Error {
  constructor (code, msg) {
    if (!MirError[code]) {
      throw new Error(`Invalid Mir error code ${code}`)
    }
    super(msg)
    this.code = code
  }
}

const Codes = {
  IdUnavailable: 'Suggested ID is not available'
}

for (let code in Codes) {
  Object.assign(MirError, {
    [code]: function (msg) {
      return new MirError(code, msg || Codes[code])
    }
  })
}

module.exports = { MirError }