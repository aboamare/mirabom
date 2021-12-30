const pem = `MIIGzzCCBbegAwIBAgIJALzfRZa2vcUjMA0GCSqGSIb3DQEBCwUAMIHGMQswCQYD
VQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEl
MCMGA1UEChMcU3RhcmZpZWxkIFRlY2hub2xvZ2llcywgSW5jLjEzMDEGA1UECxMq
aHR0cDovL2NlcnRzLnN0YXJmaWVsZHRlY2guY29tL3JlcG9zaXRvcnkvMTQwMgYD
VQQDEytTdGFyZmllbGQgU2VjdXJlIENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcy
MB4XDTIxMDYxMjEzMTYyM1oXDTIyMDcxNDEzMTYyM1owODEhMB8GA1UECxMYRG9t
YWluIENvbnRyb2wgVmFsaWRhdGVkMRMwEQYDVQQDDAoqLmlldGYub3JnMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtnjLm1ts1hC4fNNt3UnQD9y73bDX
gioTyWYSI3ca/KNfuTydjFTEYAmqnuGrBOUfgbmH3PRQ0AmpqljgWTb3d3K8H4UF
vDWQTPSS21IMjm8oqd19nE5GxWirGu0oDRzhWLHe1RZ7ZrohCPg/1Ocsy47QZuK2
laFB0rEmrRWBmEYbDl3/wxf5XfqIqpOynJB02thXrTCcTM7Rz1FqCFt/ZVZB5hKY
2S+CTdE9OIVKlr4WHMfuvUYeOj06GkwLFJHNv2tU+tovI3mYRxUuY4UupkS3MC+O
tey7XKm1P+INjWWoegm6iCAt3VuspVz+6pU2xgl3nrAVMQHB4fReQPH0pQIDAQAB
o4IDSzCCA0cwDAYDVR0TAQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB
BQUHAwIwDgYDVR0PAQH/BAQDAgWgMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9j
cmwuc3RhcmZpZWxkdGVjaC5jb20vc2ZpZzJzMS0zMTUuY3JsMGMGA1UdIARcMFow
TgYLYIZIAYb9bgEHFwEwPzA9BggrBgEFBQcCARYxaHR0cDovL2NlcnRpZmljYXRl
cy5zdGFyZmllbGR0ZWNoLmNvbS9yZXBvc2l0b3J5LzAIBgZngQwBAgEwgYIGCCsG
AQUFBwEBBHYwdDAqBggrBgEFBQcwAYYeaHR0cDovL29jc3Auc3RhcmZpZWxkdGVj
aC5jb20vMEYGCCsGAQUFBzAChjpodHRwOi8vY2VydGlmaWNhdGVzLnN0YXJmaWVs
ZHRlY2guY29tL3JlcG9zaXRvcnkvc2ZpZzIuY3J0MB8GA1UdIwQYMBaAFCVFgWhQ
Jjg9Oy0svs1q2bY9s2ZjMB8GA1UdEQQYMBaCCiouaWV0Zi5vcmeCCGlldGYub3Jn
MB0GA1UdDgQWBBQG/gur2OZ0bvzEcwKF96lIftE0TzCCAXwGCisGAQQB1nkCBAIE
ggFsBIIBaAFmAHUAKXm+8J45OSHwVnOfY6V35b5XfZxgCvj5TV0mXCVdx4QAAAF6
AF3JBwAABAMARjBEAiBmf9nUYh0j/VN96fAws/TdlwxvJOz2Gq8QjaAvn42RNgIg
MkTSbUj80FqddNna/Vg7UFyuni24Wi9149xgCK356eIAdQAiRUUHWVUkVpY/oS/x
922G4CMmY63AS39dxoNcbuIPAgAAAXoAXcpHAAAEAwBGMEQCIFVkM/Ol0gp2BXs+
C1Snr5F6ni02T9T1wc7xUJEqvAOpAiABMpXr3VNfETEjni+0coXxkQM/9IVe1f9c
+bmBgMt+CAB2AN+lXqtogk8fbK3uuF9OPlrqzaISpGpejjsSwCBEXCpzAAABegBd
y5oAAAQDAEcwRQIhAPHAsEhok5T7xhUK1veOvzFLEccVktDxoqKabwg+bBeEAiBe
AGQfzw2gH3k0zdoYDWWvSeT4brph1P19C5SqW7jKTjANBgkqhkiG9w0BAQsFAAOC
AQEA1DesRELyprrU402wvXwl4XU2Wr2g8yFnvNCx6LA2EGFjh4eiSJ5OxgFgtNGJ
jh5FeccM/+i0AeGtGnecxoik6todHNEOu8LwZn0J6Fjmb7aB2Gf+xjOvmAXThHr3
TkDIadNLmcvhGddE4FXaz2q1ctsuIjOuhK5cDNsh9CrlpWY9Vz8vFPY2S2L36c+v
Basmw2BfHtuC6MJvdAg7ww1JKrsAYhYQYA8e97Wsa1lo0xiYB2IEP03RahhD4ikg
UBqJO0/witC9P5hke0Xg47Ss7fR8EvzzNWGzbKjorDs5kA95aLjbMeR3/YwdB9wn
Yy+VWtTJevn0yBifEvT6mwOMTg==`

const ansnjs = require('asn1js')
const pki = require('pkijs')
const buffer = (Buffer.from(pem, 'base64')).buffer
const asn1 = ansnjs.fromBER(buffer)
const cert = new pki.Certificate({ schema: asn1.result })
console.log(cert.toJSON())