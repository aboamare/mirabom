if (require.main === module) {
  // generate a new UUID based OID
  const uuid = require('uuid')
  const bigInt = BigInt(`0x${uuid.v4().replaceAll('-', '')}`)
  console.log(`2.25.${bigInt.toString()}`)
}

module.exports = {
  /*
   * standard OIDs needed in MCP certificates
  */
  country:      '2.5.4.6',                  // C
  name:         '2.5.4.3',                  // CN
  email:        '1.2.840.113549.1.9.1',     // E
  organization: '2.5.4.10',                 // O
  unit:         '2.5.4.11',                 // OU
  UID:          '0.9.2342.19200300.100.1.1',

  /*
   * Extended Key Usage OIDs
   */
  anyKeyUsage:      '2.5.29.37.0',       // anyExtendedKeyUsage
  serverAuth:       '1.3.6.1.5.5.7.3.1', // id-kp-serverAuth
  clientAuth:       '1.3.6.1.5.5.7.3.2', // id-kp-clientAuth
  codeSigning:      '1.3.6.1.5.5.7.3.3', // id-kp-codeSigning
  emailProtection:  '1.3.6.1.5.5.7.3.4', // id-kp-emailProtection
  timeStamping:     '1.3.6.1.5.5.7.3.8', // id-kp-timeStamping
  OCSPSigning:      '1.3.6.1.5.5.7.3.9', // id-kp-OCSPSigning
  
  /*
   * Other standard extensions
   */
  authorityKeyIdentifier: '2.5.29.35',          // id-ce 35
  subjectKeyIdentifier:   '2.5.29.14',          // id-ce 14
  crlDistributionPoints:  '2.5.29.31',          // id-ce 31
  authorityInfoAccess:    '1.3.6.1.5.5.7.1.1',  // id-pe 1

  /*
   * Authority Information Access Methods
   */
  ocsp: '1.3.6.1.5.5.7.48.1', // id-ad-ocsp

  /*
   * MCP defined OIDs
   */
  flagState:    '2.25.323100633285601570573910217875371967771',
  callSign:     '2.25.208070283325144527098121348946972755227',
  IMONumber:    '2.25.291283622413876360871493815653100799259',
  MMSI:         '2.25.328433707816814908768060331477217690907',
  shipType:     '2.25.107857171638679641902842130101018412315',
  homePort:     '2.25.285632790821948647314354670918887798603',
  secondaryMRN: '2.25.268095117363717005222833833642941669792',
  URL:          '2.25.245076023612240385163414144226581328607',
  x5u:          '2.25.225758541249626787560521749862278982872'
}