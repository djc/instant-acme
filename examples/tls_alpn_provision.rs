//! Demonstrate using instant-acme, tokio-rustls and rcgen to provision a certificate with
//! TLS-ALPN-01
//!
//! You can run this example on a server with :443 open to the internet by running:
//!  cargo run \
//!   --package instant-acme \
//!   --example tls_alpn_provision -- \
//!     --directory-url=https://acme-staging-v02.api.letsencrypt.org/directory \
//!     --name foo.example.com
//!
//! Make sure your DNS has been set up to resolve 'foo.example.com' to the server's IP address.
//! This will issue a certificate for 'foo.example.com' from the Let's Encrypt staging server.
//!
//! You can run this example with Pebble by running:
//!   cargo run \
//!     --package instant-acme \
//!     --example tls_alpn_provision -- \
//!       --directory-url=https://localhost:14000/dir \
//!       --server-root-cert-path=<path to pebble CA cert> \
//!       --port 5001 \
//!       --name foo.example.com
//!
//! Make sure Pebble is running using its default ports and your DNS has been set up to resolve
//! 'foo.example.com' to localhost (or use Pebble with a mock DNS server like pebble-challtestsrv).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use rcgen::{CertificateParams, CustomExtension, DistinguishedName, KeyPair};
use rustls::crypto::CryptoProvider;
use rustls::server::{Acceptor, ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio::{select, task};
use tokio_rustls::LazyConfigAcceptor;
use tracing::{info, warn};

use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, HttpClient, Identifier, LetsEncrypt, NewAccount,
    NewOrder, OrderStatus,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let opts = Options::parse();

    // Build a Rustls config that can validate the ACME server's certificate.
    let rustls_config = if let Some(roots_pem) = &opts.server_root_cert_path {
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(
            CertificateDer::pem_file_iter(roots_pem)?.map(|result| result.unwrap()),
        );
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        ClientConfig::with_platform_verifier()
    };

    // Build a Hyper client that can connect to the ACME server.
    let client = HyperClient::builder(TokioExecutor::new()).build(
        hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(rustls_config)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build(),
    );

    // Spawn a challenge response server that listens for incoming TLS connections to solve
    // TLS-ALPN-01 challenges.
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
    let challenge_state = Arc::new(Mutex::new(HashMap::new()));
    let challenge_response_server = ChallengeResponseServer {
        challenges: challenge_state.clone(),
        shutdown_rx,
    };
    let port = opts.port.unwrap_or(443);
    let server_handle = task::spawn(challenge_response_server.run(port));

    // Issue a certificate for the requested identifiers
    let result = issue_certificate(&opts, Box::new(client), challenge_state).await;

    // Always shut down the challenge server and join its handle before returning the result.
    shutdown_tx.send(()).await?;
    server_handle.await?;
    result
}

async fn issue_certificate(
    opts: &Options,
    client: Box<dyn HttpClient>,
    challenge_state: Arc<Mutex<HashMap<String, Arc<CertifiedKey>>>>,
) -> anyhow::Result<()> {
    // Create a new account. This will generate a fresh ECDSA key for you.
    // Alternatively, restore an account from serialized credentials by
    // using `Account::from_credentials()`.
    let (account, credentials) = Account::create_with_http(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        opts.directory_url
            .as_ref()
            .unwrap_or(&LetsEncrypt::Staging.url().to_owned()),
        None,
        client,
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
        .name
        .iter()
        .map(|ident| Identifier::Dns(ident.clone()))
        .collect::<Vec<_>>();
    let new_order = NewOrder::new(&identifiers);

    let mut order = account.new_order(&new_order).await?;
    let state = order.state();
    info!("order state: {:#?}", state);
    assert!(matches!(state.status, OrderStatus::Pending));

    // Pick the desired challenge type and prepare the response.
    let authorizations = order.authorizations().await?;
    let mut challenges = Vec::with_capacity(authorizations.len());
    for authz in &authorizations {
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            _ => todo!(),
        }

        // We'll use the TLS-ALPN-01 challenges for this example, but you could
        // pick something else to use here.
        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::TlsAlpn01)
            .ok_or_else(|| anyhow::anyhow!("no tls-alpn-01 challenge found"))?;

        let Identifier::Dns(identifier) = &authz.identifier else {
            panic!("unsupported identifier type");
        };

        // Add the challenge response to the TLS server's state
        let key_digest = order
            .key_authorization(challenge)
            .digest()
            .as_ref()
            .to_vec();
        challenge_state.lock().unwrap().insert(
            identifier.clone(),
            Arc::new(challenge_response_cert(identifier.to_owned(), key_digest)),
        );

        challenges.push(&challenge.url);
    }

    // Let the server know we're ready to accept the challenges.
    for url in &challenges {
        info!("posting challenge ready for {url}");
        order.set_challenge_ready(url).await?;
    }

    // Exponentially back off until the order becomes ready or invalid.
    let status = order.poll(5, Duration::from_millis(250)).await?;
    info!("got back status: {status:?} after polling...");
    if status != OrderStatus::Ready {
        return Err(anyhow::anyhow!("unexpected order status: {status:?}"));
    }

    // If the order is ready, we can provision the certificate.
    // Use the rcgen library to create a Certificate Signing Request.
    let mut params = CertificateParams::new(opts.name.clone())?;
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
    directory_url: Option<String>,
    #[clap(long)]
    server_root_cert_path: Option<String>,
    #[clap(long)]
    port: Option<u16>,
    #[clap(long)]
    name: Vec<String>,
}

fn challenge_response_cert(sni: String, key_auth: Vec<u8>) -> CertifiedKey {
    // Generate a throw-away keypair for the challenge response certificate.
    let key_pair = KeyPair::generate().unwrap();

    // Generate a self-signed response certificate that has only the to-be-validated SNI as a SAN,
    // and the special ACME identifier extension with the digest of the key auth.
    // In a full implementation you would likely want to cache this to use for multiple
    // validation responses.
    let mut params = CertificateParams::new(vec![sni]).unwrap();
    params
        .custom_extensions
        .push(CustomExtension::new_acme_identifier(&key_auth));
    let challenge_cert = params.self_signed(&key_pair).unwrap();
    let challenge_cert_der = challenge_cert.der();

    let provider = CryptoProvider::get_default().unwrap();
    let key = provider
        .key_provider
        .load_private_key(PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into())
        .unwrap();

    CertifiedKey::new(vec![challenge_cert_der.clone()], key)
}

/// A tokio-rustls server that responds to TLS-ALPN-01 challenges
///
/// When a client hello with the correct ALPN is received, with a server name indicator (SNI)
/// extension matching a challenge identifier, the server will respond with a certificate that
/// contains the SNI as a SAN and the TLS-ALPN-01 challenge response key auth digest extension.
///
/// Other types of TLS connection are ignored. In a more complete implementation, the server would
/// likely want to use a default server configuration for these connections, and process the
/// transmitted application data in some way.
struct ChallengeResponseServer {
    challenges: Arc<Mutex<HashMap<String, Arc<CertifiedKey>>>>,
    shutdown_rx: mpsc::Receiver<()>,
}

impl ChallengeResponseServer {
    async fn run(mut self, port: u16) {
        info!("starting challenge response server on port: {port}");
        let listener = TcpListener::bind(format!("[::]:{port}")).await.unwrap();

        loop {
            select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, addr)) => {
                            self.handle_connection(stream, addr).await;
                        },
                        Err(e) => {
                            warn!("error accepting conn: {e}");
                            continue;
                        },
                    }
                },
                _ = self.shutdown_rx.recv() => {
                    break;
                },
            }
        }

        info!("shutting down challenge response server");
    }

    async fn handle_connection(&self, stream: TcpStream, addr: SocketAddr) {
        info!("handling conn from {}", addr);

        // Start the TLS handshake by accepting the stream.
        let acceptor = LazyConfigAcceptor::new(Acceptor::default(), stream);
        tokio::pin!(acceptor);
        let handshake = match acceptor.as_mut().await {
            Ok(handshake) => handshake,
            Err(err) => {
                warn!("error accepting TLS connection: {err}");
                return;
            }
        };

        // We'll process the hello according to TLS-ALPN-01 challenge rules. A normal
        // application would probably want to handle other connections by dispatching to
        // existing application logic and a default ServerConfig instance.
        let hello = handshake.client_hello();

        // Per RFC 8737 section 3:
        //   The ACME server MUST provide an ALPN extension with the single protocol
        //   name "acme-tls/1" and an SNI extension containing only the domain name
        // being validated during the TLS handshake.
        let Some(alpn_iter) = hello.alpn() else {
            warn!("no ALPN offered by TLS client");
            return;
        };
        if alpn_iter.collect::<Vec<_>>() != [b"acme-tls/1"] {
            warn!("client did not offer acme-tls/1 ALPN protocol");
            return;
        }
        let Some(to_be_validated) = hello.server_name() else {
            warn!("no SNI offered by TLS client");
            return;
        };

        // Look up the to-be-validated SNI in the challenge state to find a certified key to
        // use to respond to the challenge.
        let certified_key = {
            let server_state = self.challenges.lock().unwrap();
            let Some(certified_key) = server_state.get(to_be_validated).cloned() else {
                warn!("no challenge response for SNI: {to_be_validated}");
                return;
            };
            certified_key
        };

        // Make a new ServerConfig w/ the certified key.
        // IMPORTANT: We must set the correct ALPN protocols for the challenge.
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(AlwaysResolvesChain(certified_key)));
        config.alpn_protocols = vec![b"acme-tls/1".to_vec()];

        // Complete the handshake using the server config.
        // There's no application data to care about reading.
        let _ = handshake.into_stream(config.into()).await;
    }
}

/// Simple [`ResolvesServerCert`] implementation that always uses the wrapped CertifiedKey
///
/// We can't use `ServerConfig::with_single_cert()` directly because it parses the certificate
/// to try and verify the private key matches the certificate's public key. This has the
/// side effect of erroring from the ACME challenge certificate's unsupported critical extension.
#[derive(Debug)]
struct AlwaysResolvesChain(Arc<CertifiedKey>);

impl ResolvesServerCert for AlwaysResolvesChain {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}
