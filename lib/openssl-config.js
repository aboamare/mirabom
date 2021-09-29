const oid = require('./mcp-oids')

const mcp_oids = Object.entries(oid).reduce((oids, entry) => {
  return `${oids}\n${entry[0]}=${entry[1]}`
}, '[mcp_oids]')

const req = `
[req]
oid_section=mcp_oids
prompt=no
distinguished_name=dn_fields
x509_extensions=v3_exts

` 

function _SAN(fields=['MRN'], values = {}) {
  return fields.map(field => {
    if (! (oid[field] && values[field])) {
      return false
    }
    return `otherName:${oid[field]};UTF8:${values[field]}`
  }).filter(v => v)
  .join(',')
}

function forRootCert(config) {
  const fields = Object.assign({
    CN: config.ipid,
    O: config.ou || config.ipid,
    OU: 'mir',
    C: config.country,
    emailAddress: config.email || `mir@${config.domain}`,
    MRN: `urn:mrn:mcp:mir:${config.ipid}:self`},
    config)

  const san = _SAN(['MRN'], fields)
  return `
${req}
[dn_fields]
CN=${fields.CN}
O=${fields.O}
OU=${fields.OU}
emailAddress=${fields.emailAddress}
C=${fields.C}
UID=${fields.MRN}

[ v3_exts ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints=critical, CA:true
keyUsage=critical, digitalSignature, cRLSign, keyCertSign
${san ? `subjectAltName=${san}` : ''}

${mcp_oids}`
}

module.exports = {
  forRootCert
}