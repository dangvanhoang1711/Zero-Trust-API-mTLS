# TLS Assets

This directory documents the TLS files Envoy expects at runtime.

Required mounted files:

1. `tls.crt`: Envoy server leaf certificate.
2. `tls.key`: Envoy server private key.
3. `intermediate-ca.crt`: trusted client CA bundle.
4. `ca.crl`: latest CRL exported from Vault.
5. `chain.pem`: Intermediate CA followed by Root CA.

Do not store live private keys in this repository.
