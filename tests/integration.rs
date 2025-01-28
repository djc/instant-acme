use std::error::Error as StdError;
use std::io::{self, Read};
use std::process::{Child, Command};
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
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use tempfile::NamedTempFile;
use tokio::net::TcpStream;
use tokio::time::sleep;
use tracing::{debug, error, info, trace};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError>> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    // Spawn a Pebble CA and a challenge response server.
    debug!("starting Pebble CA environment");
    let pebble = PebbleEnvironment::new(DEFAULT_CONFIG.clone()).await?;

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
        Box::new(pebble.http_client()),
    )
    .await?;
    info!(account_id = account.id(), "created ACME account");

    // Issue a certificate w/ HTTP-01 challenge and verify it.
    pebble.test_http1(&mut account).await?;

    Ok(())
}

/// A test environment running Pebble and a challenge test server.
///
/// Subprocesses are torn down cleanly on drop to avoid leaving
/// stray child processes.
struct PebbleEnvironment {
    config: Config,
    #[allow(dead_code)] // Held for the lifetime of the environment.
    config_file: NamedTempFile,
    #[allow(dead_code)] // Held for the lifetime of the environment.
    pebble: Subprocess,
    #[allow(dead_code)] // Held for the lifetime of the environment.
    challtestsrv: Subprocess,
}

impl PebbleEnvironment {
    /// Create a test environment for the given configuration.
    ///
    /// Set the PEBBLE and CHALLTESTSRV to pebble and pebble-challtestsrv binaries
    /// respectively. If unset "./pebble" and "./pebble-challtestsrv" are used.
    ///
    /// Returns only once the Pebble CA server interface is responding.
    async fn new(config: Config) -> io::Result<Self> {
        let config_file = NamedTempFile::new()?;
        let config_json = serde_json::to_string_pretty(&config)?;
        trace!(config = config_json, "using static config");
        fs::write(&config_file, config_json)?;

        let pebble_path = env::var("PEBBLE").unwrap_or("./pebble".to_owned());
        let challtestsrv_path =
            env::var("CHALLTESTSRV").unwrap_or("./pebble-challtestsrv".to_owned());

        let pebble = Subprocess::new(
            Command::new(&pebble_path)
                .arg("-config")
                .arg(config_file.path())
                .arg("-dnsserver")
                .arg("127.0.0.1:8053") // Matched to default -dns01 addr for pebble-challtestsrv.
                .arg("-strict"),
        )?;

        let challtestsrv = Subprocess::new(
            Command::new(&challtestsrv_path)
                .arg("-doh-cert")
                .arg("tests/testdata/server.pem")
                .arg("-doh-cert-key")
                .arg("tests/testdata/server.key"),
        )?;

        wait_for_server(config.pebble.listen_address).await;

        Ok(Self {
            config,
            config_file,
            pebble,
            challtestsrv,
        })
    }

    async fn test_http1(&self, account: &mut Account) -> Result<(), Box<dyn StdError>> {
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
        Self::poll_until_ready(&mut order).await?;

        // Issue a certificate for the names and test the chain validates to the issuer root.
        self.issue_certificate(&mut order, names).await
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

        self.http_client().request(req).await?;

        Ok(())
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

    /// Issue a certificate for the given order, and identifiers.
    ///
    /// The issued certificate chain is verified with the provider roots.
    async fn issue_certificate(
        &self,
        order: &mut Order,
        identifiers: Vec<String>,
    ) -> Result<(), Box<dyn StdError>> {
        info!(?identifiers, order_url = order.url(), "issuing certificate");

        // Create a CSR for the identifiers corresponding to the order.
        let mut params = CertificateParams::new(identifiers.clone())?;
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
        let pem_certs = CertificateDer::pem_slice_iter(cert_chain_pem.as_bytes())
            .map(|result| result.unwrap())
            .collect::<Vec<_>>();

        // Split off and parse the EE cert, save the intermediates that follow.
        let (ee_cert, intermediates) = pem_certs.split_first().unwrap();
        let ee_cert = ParsedCertificate::try_from(ee_cert).unwrap();

        // Use the default crypto provider to verify the certificate chain to the Pebble CA root.
        let crypto_provider = CryptoProvider::get_default().unwrap();
        verify_server_cert_signed_by_trust_anchor(
            &ee_cert,
            &self.issuer_roots().await?,
            intermediates,
            UnixTime::now(),
            crypto_provider.signature_verification_algorithms.all,
        )
        .unwrap();

        // Verify the EE cert is valid for each of the identifiers.
        for ident in identifiers {
            verify_server_name(&ee_cert, &ServerName::try_from(ident.as_str())?)?;
        }

        info!("successfully issued and validated certificate");
        Ok(())
    }

    /// Return a RootCertStore containing the issuer root for the Pebble CA.
    ///
    /// This is distinct from the management root CA, and is randomly generated each
    /// time that Pebble starts up. This is the issuer that signs the randomly generated
    /// intermediate certificate returned as part of ACME issued certificate chains.
    async fn issuer_roots(&self) -> Result<RootCertStore, Box<dyn StdError>> {
        let client = self.http_client();

        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("{}/roots/0", self.pebble_management_url()))
            .header(CONTENT_TYPE, "application/json")
            .body(Full::default())?;

        let resp = client.request(req).await?;
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

    /// Return an HTTP client configured to trust the Pebble management interface root CA.
    ///
    /// Note: this is distinct from the CA issuer.
    fn http_client(&self) -> HyperClient<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>> {
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(
            CertificateDer::pem_file_iter("tests/testdata/ca.pem")
                .unwrap()
                .map(|result| result.unwrap()),
        );

        HyperClient::builder(TokioExecutor::new()).build(
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
        )
    }

    fn challenge_management_url(&self) -> &str {
        "http://127.0.0.1:8055" // Default.
    }

    fn pebble_management_url(&self) -> String {
        format!("https://{}", &self.config.pebble.management_listen_address)
    }

    fn directory_url(&self) -> String {
        format!("https://{}/dir", &self.config.pebble.listen_address)
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

#[derive(Clone, Serialize)]
struct Config {
    pebble: PebbleConfig,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PebbleConfig {
    listen_address: &'static str,
    management_listen_address: &'static str,
    certificate: &'static str,
    private_key: &'static str,
    http_port: u16,
    tls_port: u16,
    ocsp_responder_url: &'static str,
    external_account_binding_required: bool,
    domain_blocklist: &'static [&'static str],
    retry_after: RetryConfig,
    #[serde(serialize_with = "serialize_profiles")]
    profiles: &'static [(&'static str, Profile)],
}

fn serialize_profiles<S>(
    profiles: &&'static [(&'static str, Profile)],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map = serializer.serialize_map(Some(profiles.len()))?;
    for (k, v) in *profiles {
        map.serialize_entry(k, v)?;
    }
    map.end()
}

#[derive(Clone, Serialize)]
struct RetryConfig {
    /// number of seconds to add to pending authorization retry-after headers.
    authz: u32,
    /// number of seconds to add to pending order authorization retry-after headers.
    order: u32,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Profile {
    description: &'static str,
    /// lifetime of issued end entity certificates, expressed in seconds.
    #[serde(rename = "validityPeriod")]
    validity_period_seconds: u32,
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

const DEFAULT_CONFIG: Config = Config {
    pebble: PebbleConfig {
        listen_address: "127.0.0.1:14000",
        management_listen_address: "127.0.0.1:15000",
        certificate: "tests/testdata/server.pem",
        private_key: "tests/testdata/server.key",
        http_port: 5002,
        tls_port: 5001,
        ocsp_responder_url: "",
        external_account_binding_required: false,
        domain_blocklist: &["blocked-domain.example"],
        retry_after: RetryConfig { authz: 3, order: 5 },
        profiles: &[
            (
                "default",
                Profile {
                    description: "The profile you know and love",
                    validity_period_seconds: 7776000,
                },
            ),
            (
                "shortlived",
                Profile {
                    description: "A short-lived cert profile, without actual enforcement",
                    validity_period_seconds: 518400,
                },
            ),
        ],
    },
};
