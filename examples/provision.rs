use std::io;
use std::time::Duration;

use clap::Parser;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use tokio::time::sleep;
use tracing::info;

use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let opts = Options::parse();

    // Create a new account. This will generate a fresh ECDSA key for you.
    // Alternatively, restore an account from serialized credentials by
    // using `Account::from_credentials()`.

    let (account, credentials) = Account::create(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        LetsEncrypt::Staging.url(),
        None,
    )
    .await?;
    info!(
        "account credentials:\n\n{}",
        serde_json::to_string_pretty(&credentials)?
    );

    // Create the ACME order based on the given domain names.
    // Note that this only needs an `&Account`, so the library will let you
    // process multiple orders in parallel for a single account.
    let identifiers = opts
        .names
        .iter()
        .map(|ident| Identifier::Dns(ident.clone()))
        .collect::<Vec<_>>();
    let mut order = account
        .new_order(&NewOrder::new(identifiers.as_slice()))
        .await?;

    let state = order.state();
    info!("order state: {:#?}", state);
    assert!(matches!(state.status, OrderStatus::Pending));

    // Pick the desired challenge type and prepare the response.

    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            _ => todo!(),
        }

        // We'll use the DNS challenges for this example, but you could
        // pick something else to use here.

        let mut challenge = authz
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| anyhow::anyhow!("no dns01 challenge found"))?;

        let Identifier::Dns(identifier) = challenge.identifier() else {
            panic!("unsupported identifier type");
        };

        println!("Please set the following DNS record then press the Return key:");
        println!(
            "_acme-challenge.{} IN TXT {}",
            identifier,
            challenge.key_authorization().dns_value()
        );
        io::stdin().read_line(&mut String::new())?;

        challenge.set_ready().await?;
    }

    // Exponentially back off until the order becomes ready or invalid.

    let status = order.poll(5, Duration::from_millis(250)).await?;
    if status != OrderStatus::Ready {
        return Err(anyhow::anyhow!("unexpected order status: {status:?}"));
    }

    // If the order is ready, we can provision the certificate.
    // Use the rcgen library to create a Certificate Signing Request.
    let mut params = CertificateParams::new(opts.names)?;
    params.distinguished_name = DistinguishedName::new();
    let private_key = KeyPair::generate()?;
    let csr = params.serialize_request(&private_key)?;

    // Finalize the order and print certificate chain, private key and account credentials.

    order.finalize(csr.der()).await?;
    let cert_chain_pem = loop {
        match order.certificate().await? {
            Some(cert_chain_pem) => break cert_chain_pem,
            None => sleep(Duration::from_secs(1)).await,
        }
    };

    info!("certificate chain:\n\n{cert_chain_pem}");
    info!("private key:\n\n{}", private_key.serialize_pem());
    Ok(())
}

#[derive(Parser)]
struct Options {
    #[clap(long)]
    names: Vec<String>,
}
