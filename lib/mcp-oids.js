module.exports = {
  /*
   * standard OIDs needed in MCP certificates
  */
  C:    '2.5.4.6',
  CN:   '2.5.4.3',
  E:    '1.2.840.113549.1.9.1', //short field name for emailAddress
  emailAddress:    '1.2.840.113549.1.9.1', //long field name is commonly used with openssl, so we use it here too
  O:    '2.5.4.10',
  OU:   '2.5.4.11',
  UID:  '0.9.2342.19200300.100.1.1',

  /*
   * Extended Key Usage OIDs
   */
  any:              "2.5.29.37.0",       // anyExtendedKeyUsage
  serverAuth:       "1.3.6.1.5.5.7.3.1", // id-kp-serverAuth
  clientAuth:       "1.3.6.1.5.5.7.3.2", // id-kp-clientAuth
  codeSigning:      "1.3.6.1.5.5.7.3.3", // id-kp-codeSigning
  emailProtection:  "1.3.6.1.5.5.7.3.4", // id-kp-emailProtection
  timeStamping:     "1.3.6.1.5.5.7.3.8", // id-kp-timeStamping
  OCSPSigning:      "1.3.6.1.5.5.7.3.9", // id-kp-OCSPSigning
  
  /*
   * MCP defined OIDs
   */
  FS:   '2.25.323100633285601570573910217875371967771',
  CS:   '2.25.208070283325144527098121348946972755227',
  IMO:  '2.25.291283622413876360871493815653100799259',
  MMSI: '2.25.328433707816814908768060331477217690907',
  ST:   '2.25.107857171638679641902842130101018412315',
  PORT: '2.25.285632790821948647314354670918887798603',
  SMRN: '2.25.268095117363717005222833833642941669792',
  MRN:  '2.25.271477598449775373676560215839310464283', // not needed
  PMS:  '2.25.174437629172304915481663724171734402331', // should not be used!
  BMRN: '2.25.133833610339604538603087183843785923701', // not needed
  MMS:  '2.25.171344478791913547554566856023141401757', // not needed
  URL:  '2.25.245076023612240385163414144226581328607'
}