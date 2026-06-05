storage "file" {
  path = "/vault/data"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_cert_file = "/certs/vault-tls/cert.pem"
  tls_key_file  = "/certs/vault-tls/privkey.pem"
}
api_addr = "https://vault:8200"
disable_mlock = true
