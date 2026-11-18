//! Print a pre-provisioned `dns-persist-01` validation record.
//!
//! Run against Let's Encrypt staging once support is deployed, or point the
//! account creation at another ACME directory.

#![cfg(any(feature = "ring", feature = "aws-lc-rs"))]

use std::sync::Arc;

use clap::Parser;
use instant_acme::{Account, CryptoProvider, DefaultClient, Identifier, LetsEncrypt, NewAccount};

#[derive(Parser)]
struct Options {
    /// Domain or IP address to create a persistent validation record for
    identifier: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let opts = Options::parse();

    #[cfg(feature = "aws-lc-rs")]
    let (provider, rustls_crypto_provider) = (
        CryptoProvider::aws_lc_rs(),
        rustls::crypto::aws_lc_rs::default_provider(),
    );

    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    let (provider, rustls_crypto_provider) = (
        CryptoProvider::ring(),
        rustls::crypto::ring::default_provider(),
    );

    let (account, _credentials) = Account::builder(
        Box::new(DefaultClient::new(Arc::new(rustls_crypto_provider))?),
        provider,
    )?
    .create(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        LetsEncrypt::Staging.url().to_owned(),
        None,
    )
    .await?;

    let identifier = match opts.identifier.parse() {
        Ok(ip) => Identifier::Ip(ip),
        Err(_) => Identifier::Dns(opts.identifier),
    };

    let response = account.dns_persist_response(&identifier)?;
    println!("{} IN TXT", response.host());
    for chunk in response.rdata_chunks() {
        println!("  \"{chunk}\"");
    }

    Ok(())
}
