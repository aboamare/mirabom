const fs = require('fs/promises')
const chai = require('chai')

const { OCSPRequest } = require('../src/ca/ocsp.js')

chai.should()

describe('OCSP processing', function () {
  describe('Parse OCSP requests', function () {
    it('Parse request from binary file', async function () {
      const buf = await fs.readFile('test/data/ocsp.req')
      console.debug(buf.toString('hex'))
      const req = new OCSPRequest(buf.buffer, 'urn:mrn:mcp:id:aboamare:test')
      req.should.be.instanceof(OCSPRequest)

      const serials = req.serials
      serials.should.be.an('array')
      serials.length.should.be.greaterThan(0)
      serials[0].should.be.a('string')
      serials[0].toUpperCase().should.equal('017E0C56F8E4')

      req.nonce.should.be.a('string')
      req.nonce.toUpperCase().should.equal('0410B3AF5CC6B9F0AA3A6D96F3AC82C75C2B')
    })
  })
})