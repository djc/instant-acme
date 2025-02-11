use std::collections::HashMap;
use std::error::Error as StdError;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use std::{env, fs};

use bytes::{Buf, Bytes};
use http::header::CONTENT_TYPE;
use http::{Method, Request};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, Order,
    OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use rustls::client::{verify_server_cert_signed_by_trust_anchor, verify_server_name};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::ParsedCertificate;
use rustls::RootCertStore;
use rustls_pki_types::UnixTime;
use serde::{Serialize, Serializer};
use tempfile::NamedTempFile;
use tokio::net::TcpStream;
use tokio::time::sleep;
use tracing::{debug, error, info, trace};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

/// Ignored by default because it requires `pebble` and `pebble-challtestsrv` binaries.
///
/// See documentation for [`Environment`].
#[tokio::test]
#[ignore]
async fn http_01() -> Result<(), Box<dyn StdError>> {
    let _ = tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init();

    // Spawn a Pebble CA and a challenge response server.
    debug!("starting Pebble CA environment");
    let pebble = EnvironmentConfig::default().run().await?;

    // Create a test account with the Pebble CA.
    debug!("creating test account");
    let (mut account, _) = Account::create_with_http(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        &pebble.directory_url(),
        None,
        Box::new(pebble.client.clone()),
    )
    .await?;
    info!(account_id = account.id(), "created ACME account");

    // Issue a certificate w/ HTTP-01 challenge.
    let (identifiers, cert_chain) = pebble.test_http1(&mut account).await?;

    // Split off and parse the EE cert, save the intermediates that follow.
    let (ee_cert, intermediates) = cert_chain.split_first().unwrap();
    let ee_cert = ParsedCertificate::try_from(ee_cert).unwrap();

    // Use the default crypto provider to verify the certificate chain to the Pebble CA root.
    let crypto_provider = CryptoProvider::get_default().unwrap();
    verify_server_cert_signed_by_trust_anchor(
        &ee_cert,
        &pebble.issuer_roots().await?,
        intermediates,
        UnixTime::now(),
        crypto_provider.signature_verification_algorithms.all,
    )
    .unwrap();

    // Verify the EE cert is valid for each of the identifiers.
    for ident in identifiers {
        verify_server_name(&ee_cert, &ServerName::try_from(ident.as_str())?)?;
    }

    Ok(())
}

/// A test environment running Pebble and a challenge test server.
///
/// Subprocesses are torn down cleanly on drop to avoid leaving
/// stray child processes.
struct Environment {
    config: EnvironmentConfig,
    #[allow(dead_code)] // Held for the lifetime of the environment.
    config_file: NamedTempFile,
    #[allow(dead_code)] // Held for the lifetime of the environment.
    pebble: Subprocess,
    #[allow(dead_code)] // Held for the lifetime of the environment.
    challtestsrv: Subprocess,
    client: HyperClient<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
}

impl Environment {
    async fn test_http1(
        &self,
        account: &mut Account,
    ) -> Result<(Vec<String>, Vec<CertificateDer<'static>>), Box<dyn StdError>> {
        info!("testing HTTP-01 challenge");

        // Create an order.
        let identifier = Identifier::Dns("example.com".to_owned());
        debug!(?identifier, "creating order");
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &[identifier],
            })
            .await?;
        info!(order_url = order.url(), "created order");

        let authorizations = order.authorizations().await?;
        let mut challenges = Vec::with_capacity(authorizations.len());
        let mut names = Vec::with_capacity(authorizations.len());

        // Collect up the relevant challenges, provisioning the expected responses as we go.
        for authz in &authorizations {
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                _ => unreachable!("unexpected authz state: {:?}", authz.status),
            }

            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Http01)
                .ok_or("no http01 challenge found")?;

            let Identifier::Dns(identifier) = &authz.identifier;

            // Provision the HTTP-01 challenge response with the Pebble challenge test server.
            let key_auth = order.key_authorization(challenge);
            debug!(
                token = challenge.token,
                key_auth = key_auth.as_str(),
                "provisioning HTTP-01 response",
            );
            self.add_http01_response(&challenge.token, key_auth.as_str())
                .await?;

            challenges.push((identifier, &challenge.url));
            names.push(identifier.clone());
        }

        // Tell the CA we have provisioned the response for each challenge.
        for (_, url) in &challenges {
            debug!(challenge_url = url, "marking challenge ready");
            order.set_challenge_ready(url).await?;
        }

        // Poll until the order is ready.
        poll_until_ready(&mut order).await?;

        // Issue a certificate for the names and test the chain validates to the issuer root.
        let cert_chain = self.certificate(&mut order, &names).await?;

        Ok((names, cert_chain))
    }

    /// Provision an HTTP-01 challenge response for the given token and key authorization.
    ///
    /// The Pebble challenge test server will be configured to respond to HTTP-01 challenge
    /// requests for the provided token by returning the expected key auth.
    async fn add_http01_response(
        &self,
        token: &str,
        key_auth: &str,
    ) -> Result<(), Box<dyn StdError>> {
        #[derive(Serialize)]
        struct AddHttp01Request<'a> {
            token: &'a str,
            content: &'a str,
        }

        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("{}/add-http01", self.challenge_management_url()))
            .header(CONTENT_TYPE, "application/json")
            .body(Full::from(serde_json::to_vec(&AddHttp01Request {
                token,
                content: key_auth,
            })?))?;

        self.client.request(req).await?;

        Ok(())
    }

    /// Issue a certificate for the given order, and identifiers.
    ///
    /// The issued certificate chain is verified with the provider roots.
    async fn certificate(
        &self,
        order: &mut Order,
        identifiers: &[String],
    ) -> Result<Vec<CertificateDer<'static>>, Box<dyn StdError>> {
        info!(?identifiers, order_url = order.url(), "issuing certificate");

        // Create a CSR for the identifiers corresponding to the order.
        let mut params = CertificateParams::new(identifiers.to_owned())?;
        params.distinguished_name = DistinguishedName::new();
        let private_key = KeyPair::generate()?;
        let csr = params.serialize_request(&private_key)?;

        // Finalize the order and fetch the issued certificate chain.
        debug!(order_url = order.url(), "finalizing order");
        order.finalize(csr.der()).await.unwrap();
        debug!(order_url = order.url(), "fetching order certificate chain");
        let cert_chain_pem = loop {
            match order.certificate().await.unwrap() {
                Some(cert_chain_pem) => break cert_chain_pem,
                None => sleep(Duration::from_secs(1)).await,
            }
        };

        // Parse the PEM chain into a vec of DER certificates ordered ee -> intermediates.
        info!("successfully issued certificate");
        Ok(CertificateDer::pem_slice_iter(cert_chain_pem.as_bytes())
            .map(|result| result.unwrap())
            .collect())
    }

    /// Return a RootCertStore containing the issuer root for the Pebble CA.
    ///
    /// This is distinct from the management root CA, and is randomly generated each
    /// time that Pebble starts up. This is the issuer that signs the randomly generated
    /// intermediate certificate returned as part of ACME issued certificate chains.
    async fn issuer_roots(&self) -> Result<RootCertStore, Box<dyn StdError>> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!(
                "https://{}/roots/0",
                &self.config.pebble.management_listen_address
            ))
            .header(CONTENT_TYPE, "application/json")
            .body(Full::default())?;

        let resp = self.client.request(req).await?;
        if resp.status() != 200 {
            return Err(format!("unexpected /roots/0 response status: {}", resp.status()).into());
        }

        let body = resp.collect().await?.aggregate();
        let mut pem = String::new();
        body.reader().read_to_string(&mut pem)?;
        let root = CertificateDer::from_pem_slice(pem.as_bytes())?;

        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(vec![root]);
        assert_eq!(roots.len(), 1);
        Ok(roots)
    }

    fn challenge_management_url(&self) -> String {
        format!("http://[::1]:{}", self.config.challtestsrv_port)
    }

    fn directory_url(&self) -> String {
        format!("https://{}/dir", &self.config.pebble.listen_address)
    }
}

/// Poll the given order until it is ready, waiting longer between each attempt up to
/// a maximum.
///
/// Returns an error when the maximum number of tries has been reached.
async fn poll_until_ready(order: &mut Order) -> Result<(), Box<dyn StdError>> {
    let url = order.url().to_owned();
    info!(order_url = url, "waiting for order to be ready");
    let mut tries = 1u8;
    let mut delay = Duration::from_millis(250);
    loop {
        sleep(delay).await;
        let state = order.refresh().await.unwrap();
        if let OrderStatus::Ready | OrderStatus::Invalid = state.status {
            break;
        }

        delay *= 2;
        tries += 1;
        match tries < 10 {
            true => info!(
                tries,
                ?delay,
                order_url = url,
                order_status = ?state.status,
                "order not ready yet, trying again after delay",
            ),
            false => {
                error!(
                    tries,
                    order_url = url,
                    order_state = ?state,
                    "giving up on polling order"
                );
                return Err("order is not ready".into());
            }
        }
    }

    let state = order.state();
    match state.status {
        OrderStatus::Ready => Ok(()),
        _ => Err(format!("unexpected order status: {:?}", state.status).into()),
    }
}

/// Wait for the server at the given address to be ready.
/// Sleeps a longer duration after each attempt and panics after 10 failed attempts.
async fn wait_for_server(addr: &str) {
    for i in 0..10 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        sleep(Duration::from_millis(i * 100)).await
    }
    panic!("failed to connect to {addr:?} after 10 tries");
}

/// Configuration for running a test [`Environment`] with unique per-environment ports.
struct EnvironmentConfig {
    pebble: PebbleConfig,
    dns_port: u16,
    challtestsrv_port: u16,
}

impl EnvironmentConfig {
    /// Consume the [`EnvironmentConfig`] and start a Pebble and challenge test servers.
    ///
    /// Returns the running [`Environment`] when successful.
    async fn run(self) -> io::Result<Environment> {
        #[derive(Clone, Serialize)]
        struct ConfigWrapper<'a> {
            pebble: &'a PebbleConfig,
        }

        let config_file = NamedTempFile::new()?;
        let config_json = serde_json::to_string_pretty(&ConfigWrapper {
            pebble: &self.pebble,
        })?;
        trace!(config = config_json, "using static config");
        fs::write(&config_file, config_json)?;

        let pebble_path = env::var("PEBBLE").unwrap_or_else(|_| "./pebble".to_owned());
        let challtestsrv_path =
            env::var("CHALLTESTSRV").unwrap_or_else(|_| "./pebble-challtestsrv".to_owned());

        let pebble = Subprocess::new(
            Command::new(&pebble_path)
                .arg("-config")
                .arg(config_file.path())
                .arg("-dnsserver")
                .arg(format!("[::1]:{}", self.dns_port))
                .arg("-strict"),
        )?;

        // Note: we bind `[::1]` for the challenge test server because by default it will
        //  return both A and AAAA records.
        let challtestsrv = Subprocess::new(
            Command::new(&challtestsrv_path)
                .arg("-management")
                .arg(format!("[::1]:{}", self.challtestsrv_port))
                .arg("-dns01")
                .arg(format!("[::1]:{}", self.dns_port))
                .arg("-http01")
                .arg(format!("[::1]:{}", self.pebble.http_port))
                .arg("-tlsalpn01")
                .arg(format!("[::1]:{}", self.pebble.tls_port))
                .arg("-https01")
                .arg("") // Disable HTTP-01 over https:// redirect challenges.
                .arg("-doh")
                .arg(""), // Disable DoH interface.
        )?;

        wait_for_server(&self.pebble.listen_address).await;

        // Trust the Pebble management interface root CA.
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(
            CertificateDer::pem_file_iter("tests/testdata/ca.pem")
                .unwrap()
                .map(|result| result.unwrap()),
        );

        let client = HyperClient::builder(TokioExecutor::new()).build(
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(
                    rustls::ClientConfig::builder()
                        .with_root_certificates(roots)
                        .with_no_client_auth(),
                )
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .build(),
        );

        Ok(Environment {
            config: self,
            config_file,
            pebble,
            challtestsrv,
            client,
        })
    }
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            pebble: PebbleConfig::default(),
            dns_port: NEXT_PORT.fetch_add(1, Ordering::SeqCst),
            challtestsrv_port: NEXT_PORT.fetch_add(1, Ordering::SeqCst),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PebbleConfig {
    listen_address: String,
    management_listen_address: String,
    certificate: &'static Path,
    private_key: &'static Path,
    http_port: u16,
    tls_port: u16,
    ocsp_responder_url: &'static str,
    external_account_binding_required: bool,
    domain_blocklist: Vec<&'static str>,
    retry_after: RetryConfig,
    profiles: HashMap<&'static str, Profile>,
}

impl Default for PebbleConfig {
    fn default() -> Self {
        Self {
            listen_address: format!("[::1]:{}", NEXT_PORT.fetch_add(1, Ordering::SeqCst)),
            management_listen_address: format!(
                "[::1]:{}",
                NEXT_PORT.fetch_add(1, Ordering::SeqCst)
            ),
            certificate: Path::new("tests/testdata/server.pem"),
            private_key: Path::new("tests/testdata/server.key"),
            http_port: NEXT_PORT.fetch_add(1, Ordering::SeqCst),
            tls_port: NEXT_PORT.fetch_add(1, Ordering::SeqCst),
            ocsp_responder_url: "",
            external_account_binding_required: false,
            domain_blocklist: vec!["blocked-domain.example"],
            retry_after: RetryConfig {
                authz: Duration::from_secs(3),
                order: Duration::from_secs(5),
            },
            profiles: [
                (
                    "default",
                    Profile {
                        description: "The profile you know and love",
                        validity_period: Duration::from_secs(7776000),
                    },
                ),
                (
                    "shortlived",
                    Profile {
                        description: "A short-lived cert profile, without actual enforcement",
                        validity_period: Duration::from_secs(518400),
                    },
                ),
            ]
            .into(),
        }
    }
}

#[derive(Clone, Serialize)]
struct RetryConfig {
    /// Duration to add to pending authorization retry-after headers.
    #[serde(serialize_with = "duration_as_secs")]
    authz: Duration,
    /// Duration to add to pending order authorization retry-after headers.
    #[serde(serialize_with = "duration_as_secs")]
    order: Duration,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Profile {
    description: &'static str,
    /// lifetime of issued end entity certificates, expressed in seconds.
    #[serde(serialize_with = "duration_as_secs")]
    validity_period: Duration,
}

fn duration_as_secs<S: Serializer>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_u64(duration.as_secs())
}

/// A wrapper type for a subprocess that ensures it is killed and waited on drop.
struct Subprocess(Option<Child>);

impl Subprocess {
    fn new(cmd: &mut Command) -> io::Result<Self> {
        Ok(Self(Some(cmd.spawn()?)))
    }
}

impl Drop for Subprocess {
    fn drop(&mut self) {
        // When the subprocess drops, kill the child process and wait for it to exit.
        // This avoids leaving zombie instances of Pebble and the challenge test server
        // behind when we're done with the test environment.
        if let Some(mut child) = self.0.take() {
            child.kill().expect("failed to kill subprocess");
            child.wait().expect("failed to wait for killed subprocess");
        }
    }
}

static NEXT_PORT: AtomicU16 = AtomicU16::new(5555);
