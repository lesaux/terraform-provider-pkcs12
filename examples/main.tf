terraform {
  required_providers {
    pkcs12 = {
      source = "chilicat/pkcs12"
      version = "0.1.0"
    }
  }
}

provider "pkcs12" {
  # Configuration options
}


resource "tls_private_key" "my_private_key" {
  algorithm = "RSA"
}

resource "tls_self_signed_cert" "my_cert" {
  # key_algorithm   = tls_private_key.my_private_key.algorithm
  private_key_pem = tls_private_key.my_private_key.private_key_pem
  validity_period_hours = 58440
  early_renewal_hours = 5844
  allowed_uses = [
      "key_encipherment",
      "digital_signature",
      "server_auth",
  ]
  dns_names = [ "myserver1.lcoal", "myserver2.lcoal"]
  is_ca_certificate = true 
  set_subject_key_id  = true

  subject {
      common_name  = "myserver.local"
  }
}

resource "pkcs12_from_pem" "my_pkcs12" {
  password = "mypassword"
  cert_pem = tls_self_signed_cert.my_cert.cert_pem
  private_key_pem  = tls_private_key.my_private_key.private_key_pem
  # private_key_pass = "key-pass"
}

ephemeral "pkcs12_nopass_from_pem" "my_pkcs12_ephemeral" {
  cert_pem        = tls_self_signed_cert.my_cert.cert_pem
  private_key_pem = tls_private_key.my_private_key.private_key_pem
}

resource "local_file" "result" {
  filename = "${path.module}/certificates.p12"
  content_base64     = pkcs12_from_pem.my_pkcs12.result
}

resource "local_file" "result_ephemeral" {
  filename = "${path.module}/certificates_ephemeral.p12"
  content_base64     = ephemeral.pkcs12_nopass_from_pem.my_pkcs12_ephemeral.result
}


output "my_pkcs12" {
  value = pkcs12_from_pem.my_pkcs12
  sensitive = true
}
