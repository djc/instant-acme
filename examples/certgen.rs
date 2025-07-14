//! This "example" is used for generating integration test certificates.
//!
//! It is not intended to be an example of using `instant-acme`.

use std::fs;

use rcgen::{BasicConstraints, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair};

fn main() -> anyhow::Result<()> {
    let ca_key = KeyPair::generate()?;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "Pebble CA".to_owned());
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.distinguished_name = distinguished_name;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    let issuer = CertifiedIssuer::self_signed(ca_params, ca_key)?;
    fs::write("tests/testdata/ca.pem", issuer.as_ref().pem())?;

    let ee_key = KeyPair::generate()?;
    fs::write("tests/testdata/server.key", ee_key.serialize_pem())?;

    let mut ee_params = rcgen::CertificateParams::new([
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ])?;
    ee_params.distinguished_name = DistinguishedName::new();
    let ee_cert = ee_params.signed_by(&ee_key, &issuer)?;
    fs::write("tests/testdata/server.pem", ee_cert.pem())?;

    Ok(())
}
