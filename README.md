# instant-acme: async, pure-Rust ACME client

[![Documentation](https://docs.rs/instant-acme/badge.svg)](https://docs.rs/instant-acme/)
[![Crates.io](https://img.shields.io/crates/v/instant-acme.svg)](https://crates.io/crates/instant-acme)
[![Build status](https://github.com/InstantDomain/instant-acme/workflows/CI/badge.svg)](https://github.com/InstantDomain/instant-acme/actions?query=workflow%3ACI)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

instant-acme is an async, pure-Rust ACME (RFC 8555) client.

If you think this is interesting, Instant Domains is
[hiring](https://bookface.ycombinator.com/company/25451/jobs/52868) experienced Rust engineers.

instant-acme is used in production at [InstantDomain](https://instantdomain.com/) to help
us provision TLS certificates within seconds for our customers. instant-acme relies
on Tokio and rustls to implement the [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html)
specification.

## Features

* Store/recover your account credentials by serializing/deserializing
* Fully async implementation with tracing support
* Support for processing multiple orders concurrently
* Uses hyper with rustls and Tokio for HTTP requests
* Uses *ring* for ECDSA signing
* Minimum supported Rust version: 1.51

## Limitations

* Only tested with DNS challenges against Let's Encrypt so far (staging and production)
* Only supports ECDSA keys for now

## Getting started

```rust
use std::time::Duration;

use rcgen::{Certificate, CertificateParams, DistinguishedName};
use tokio::time::sleep;
use tracing::{error, info};

use acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};

async fn provision(names: Vec<String>) -> anyhow::Result<()> {
    // Create a new account. This will generate a fresh ECDSA key for you.
    // Alternatively, restore an account from serialized credentials by
    // using `Account::from_credentials()`.

    let account = Account::create(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        LetsEncrypt::Staging.url(),
    )
    .await?;

    // Create the ACME order based on the given domain names.
    // Note that this only needs an `&Account`, so the library will let you
    // process multiple orders in parallel for a single account.

    let identifiers = names
        .iter()
        .map(|name| Identifier::Dns(name.into()))
        .collect::<Vec<_>>();
    let (mut order, state) = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await
        .unwrap();

    info!("order state: {:#?}", state);
    assert!(matches!(state.status, OrderStatus::Pending));

    // Pick the desired challenge type and prepare the response.

    let authorizations = order.authorizations(&state.authorizations).await.unwrap();
    let mut challenges = Vec::with_capacity(authorizations.len());
    for authz in &authorizations {
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            _ => todo!(),
        }

        // We'll use the DNS challenges for this example, but you could
        // pick something else to use here.

        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .ok_or_else(|| anyhow::anyhow!("no dns01 challenge found"))?;

        let Identifier::Dns(identifier) = &authz.identifier;
        // TODO: set up the challenge response here.
        challenges.push((identifier, &challenge.url));
    }

    // Let the server know we're ready to accept the challenges.

    for (_, url) in &challenges {
        order.set_challenge_ready(url).await.unwrap();
    }

    // Exponentially back off until the order becomes ready or invalid.

    let mut tries = 1u8;
    let mut delay = Duration::from_millis(250);
    let state = loop {
        sleep(delay).await;
        let state = order.state().await.unwrap();
        if let OrderStatus::Ready | OrderStatus::Invalid = state.status {
            info!("order state: {:#?}", state);
            break state;
        }

        delay *= 2;
        tries += 1;
        match tries < 5 {
            true => info!(?state, tries, "order is not ready, waiting {delay:?}"),
            false => {
                error!(?state, tries, "order is not ready");
                return Err(anyhow::anyhow!("order is not ready"));
            }
        }
    };

    if state.status == OrderStatus::Invalid {
        return Err(anyhow::anyhow!("order is invalid"));
    }

    let mut names = Vec::with_capacity(challenges.len());
    for (identifier, _) in challenges {
        names.push(identifier.to_owned());
    }

    // If the order is ready, we can provision the certificate.
    // Use the rcgen library to create a Certificate Signing Request.

    let mut params = CertificateParams::new(names.clone());
    params.distinguished_name = DistinguishedName::new();
    let cert = Certificate::from_params(params).unwrap();
    let csr = cert.serialize_request_der()?;

    // Finalize the order and print certificate chain, private key and account credentials.

    let cert_chain_pem = order.finalize(&csr, &state.finalize).await.unwrap();
    info!("certficate chain:\n\n{}", cert_chain_pem,);
    info!("private key:\n\n{}", cert.serialize_private_key_pem());
    info!(
        "account credentials:\n\n{}",
        serde_json::to_string_pretty(&account.credentials()).unwrap()
    );

    Ok(())
}
```
