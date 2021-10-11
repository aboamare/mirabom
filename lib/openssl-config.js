const oid = require('./mcp-oids')

const mcp_oids = Object.entries(oid).reduce((oids, entry) => {
  return `${oids}\n${entry[0]}=${entry[1]}`
}, '[mcp_oids]')


function forCAcert(ca) {
  return `
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
crlDistributionPoints = @crl_info
authorityInfoAccess = @ocsp_info
${ca.san ? `subjectAltName=${ca.san}` : ''}
    
[crl_info]
URI.0 = ${ca.crlUrl || `https://${ca.domain}/revoked.crl`}

[ocsp_info]
caIssuers;URI.0 = ${ca.crtUrl || `https://${ca.domain}/revoked.crt`}
OCSP;URI.0 = ${ca.ocspUrl || `https://${ca.domain}/ocsp`}
`
}

function _dnFieldsSection(entity) {
  return entity.dnFields.map(field => `${field}=${entity[field]}`)
    .join('\n')
}

function forCSR(entity) {
  return `
[req]
oid_section=mcp_oids
prompt=no
distinguished_name=dn_fields

[dn_fields]
${_dnFieldsSection(entity)}

${mcp_oids}`
}

function forRootCert(entity) {
  return `
[req]
oid_section=mcp_oids
prompt=no
distinguished_name=dn_fields
x509_extensions=v3_exts

[dn_fields]
${_dnFieldsSection(entity)}

[ v3_exts ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints=critical, CA:true
keyUsage=critical, digitalSignature, cRLSign, keyCertSign
${entity.san ? `subjectAltName=${entity.san}` : ''}

${mcp_oids}`
}

module.exports = {
  forCAcert,
  forCSR,
  forRootCert,
}