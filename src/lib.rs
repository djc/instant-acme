#![warn(unreachable_pub)]

use std::sync::Arc;

use base64::URL_SAFE_NO_PAD;
use hyper::client::HttpConnector;
use hyper::header::{CONTENT_TYPE, LOCATION};
use hyper::{Body, Method, Request, Response};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::de::{DeserializeOwned, Error as _, Unexpected};
use serde::{Deserialize, Serialize};

mod types;
use types::{
    AccountCredentials, Challenge, DirectoryUrls, Empty, FinalizeRequest, Header, JoseJson, Jwk,
    KeyAuthorization, KeyOrKeyId, Problem, SigningAlgorithm,
};
pub use types::{
    Authorization, AuthorizationStatus, ChallengeType, Error, Identifier, LetsEncrypt, NewAccount,
    NewOrder, OrderState, OrderStatus,
};

pub struct Order {
    account: Arc<AccountInner>,
    nonce: Option<String>,
    order_url: String,
}

impl Order {
    pub async fn authorizations(
        &mut self,
        authz_urls: &[String],
    ) -> Result<Vec<Authorization>, Error> {
        let mut authorizations = Vec::with_capacity(authz_urls.len());
        for url in authz_urls {
            authorizations.push(self.account.get(&mut self.nonce, url).await?);
        }
        Ok(authorizations)
    }

    pub fn key_authorization(&self, challenge: &Challenge) -> KeyAuthorization {
        KeyAuthorization(format!("{}.{}", challenge.token, &self.account.key.thumb))
    }

    pub async fn finalize(&mut self, csr_der: &[u8], finalize_url: &str) -> Result<String, Error> {
        let rsp = self
            .account
            .post(
                Some(&FinalizeRequest::new(csr_der)),
                self.nonce.take(),
                finalize_url,
            )
            .await?;

        self.nonce = nonce_from_response(&rsp);
        let state = Problem::check::<OrderState>(rsp).await?;

        let cert_url = match state.certificate {
            Some(url) => url,
            None => return Err(Error::Str("no certificate URL")),
        };

        let rsp = self
            .account
            .post(None::<&Empty>, self.nonce.take(), &cert_url)
            .await?;

        self.nonce = nonce_from_response(&rsp);
        let body = hyper::body::to_bytes(Problem::from_response(rsp).await?).await?;
        Ok(
            String::from_utf8(body.to_vec())
                .map_err(|_| "unable to decode certificate as UTF-8")?,
        )
    }

    pub async fn set_challenge_ready(&mut self, challenge_url: &str) -> Result<(), Error> {
        let rsp = self
            .account
            .post(Some(&Empty {}), self.nonce.take(), challenge_url)
            .await?;

        self.nonce = nonce_from_response(&rsp);
        let _ = Problem::check::<Challenge>(rsp).await?;
        Ok(())
    }

    pub async fn challenge(&mut self, challenge_url: &str) -> Result<Challenge, Error> {
        self.account.get(&mut self.nonce, challenge_url).await
    }

    pub async fn state(&mut self) -> Result<OrderState, Error> {
        self.account.get(&mut self.nonce, &self.order_url).await
    }
}

#[derive(Clone)]
pub struct Account {
    inner: Arc<AccountInner>,
}

impl Account {
    pub async fn create(account: &NewAccount<'_>, server_url: &str) -> Result<Account, Error> {
        let client = Client::new(server_url).await?;
        let key = Key::generate()?;
        let rsp = client
            .post(Some(account), None, &key, &client.urls.new_account)
            .await?;

        let account_url = rsp
            .headers()
            .get(LOCATION)
            .and_then(|hv| hv.to_str().ok())
            .map(|s| s.to_owned());

        // The response redirects, we don't need the body
        let _ = Problem::from_response(rsp).await?;
        Ok(Self {
            inner: Arc::new(AccountInner {
                client,
                key,
                id: account_url.ok_or("failed to get account URL")?,
            }),
        })
    }

    pub async fn new_order<'a>(
        &'a self,
        order: &NewOrder<'_>,
    ) -> Result<(Order, OrderState), Error> {
        let rsp = self
            .inner
            .post(Some(order), None, &self.inner.client.urls.new_order)
            .await?;

        let nonce = nonce_from_response(&rsp);
        let order_url = rsp
            .headers()
            .get(LOCATION)
            .and_then(|hv| hv.to_str().ok())
            .map(|s| s.to_owned());

        let status = Problem::check(rsp).await?;
        Ok((
            Order {
                account: self.inner.clone(),
                nonce,
                order_url: order_url.ok_or("no order URL found")?,
            },
            status,
        ))
    }
}

impl<'de> Deserialize<'de> for Account {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let creds = AccountCredentials::deserialize(deserializer)?;
        let pkcs8_der = base64::decode_config(&creds.key_pkcs8, URL_SAFE_NO_PAD).map_err(|_| {
            D::Error::invalid_value(
                Unexpected::Str(&creds.key_pkcs8),
                &"unable to base64-decode key",
            )
        })?;

        Ok(Self {
            inner: Arc::new(AccountInner {
                key: Key::from_pkcs8_der(pkcs8_der).map_err(|_| {
                    D::Error::invalid_value(
                        Unexpected::Str(&creds.key_pkcs8),
                        &"unable to parse key",
                    )
                })?,
                client: Client {
                    client: client(),
                    urls: creds.urls,
                },
                id: creds.id,
            }),
        })
    }
}

impl Serialize for Account {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        AccountCredentials {
            id: self.inner.id.clone(),
            key_pkcs8: base64::encode_config(&self.inner.key.pkcs8_der, URL_SAFE_NO_PAD),
            urls: self.inner.client.urls.clone(),
        }
        .serialize(serializer)
    }
}

struct AccountInner {
    client: Client,
    key: Key,
    id: String,
}

impl AccountInner {
    async fn get<T: DeserializeOwned>(
        &self,
        nonce: &mut Option<String>,
        url: &str,
    ) -> Result<T, Error> {
        let rsp = self.post(None::<&Empty>, nonce.take(), url).await?;
        *nonce = nonce_from_response(&rsp);
        Problem::check(rsp).await
    }

    async fn post(
        &self,
        payload: Option<&impl Serialize>,
        nonce: Option<String>,
        url: &str,
    ) -> Result<Response<Body>, Error> {
        self.client.post(payload, nonce, self, url).await
    }
}

impl Signer for AccountInner {
    fn header<'n, 'u: 'n, 's: 'u>(&'s self, nonce: &'n str, url: &'u str) -> Header<'n> {
        Header {
            alg: self.key.signing_algorithm,
            key: KeyOrKeyId::KeyId(&self.id),
            nonce,
            url,
        }
    }

    fn key(&self) -> &Key {
        &self.key
    }
}

#[derive(Debug)]
struct Client {
    client: hyper::Client<hyper_rustls::HttpsConnector<HttpConnector>>,
    urls: DirectoryUrls,
}

impl Client {
    async fn new(server_url: &str) -> Result<Self, Error> {
        let client = client();
        let rsp = client.get(server_url.parse()?).await?;
        let body = hyper::body::to_bytes(rsp.into_body()).await?;
        Ok(Client {
            client,
            urls: serde_json::from_slice(&body)?,
        })
    }

    async fn post(
        &self,
        payload: Option<&impl Serialize>,
        mut nonce: Option<String>,
        signer: &impl Signer,
        url: &str,
    ) -> Result<Response<Body>, Error> {
        if nonce.is_none() {
            let request = Request::builder()
                .method(Method::HEAD)
                .uri(&self.urls.new_nonce)
                .body(Body::empty())
                .unwrap();

            let rsp = self.client.request(request).await?;
            nonce = nonce_from_response(&rsp);
        };

        let nonce = nonce.ok_or("no nonce found")?;
        let request = Request::builder()
            .method(Method::POST)
            .uri(url)
            .header(CONTENT_TYPE, JOSE_JSON)
            .body(signer.signed_json(payload, &nonce, url)?)
            .unwrap();

        Ok(self.client.request(request).await?)
    }
}

struct Key {
    rng: SystemRandom,
    signing_algorithm: SigningAlgorithm,
    inner: EcdsaKeyPair,
    pkcs8_der: Vec<u8>,
    thumb: String,
}

impl Key {
    fn generate() -> Result<Self, Error> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)?;
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())?;
        let thumb = base64::encode_config(Jwk::thumb_sha256(&key)?, URL_SAFE_NO_PAD);

        Ok(Self {
            rng,
            signing_algorithm: SigningAlgorithm::Es256,
            inner: key,
            pkcs8_der: pkcs8.as_ref().to_vec(),
            thumb,
        })
    }

    fn from_pkcs8_der(pkcs8_der: Vec<u8>) -> Result<Self, Error> {
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8_der)?;
        let thumb = base64::encode_config(Jwk::thumb_sha256(&key)?, URL_SAFE_NO_PAD);

        Ok(Self {
            rng: SystemRandom::new(),
            signing_algorithm: SigningAlgorithm::Es256,
            inner: key,
            pkcs8_der,
            thumb,
        })
    }

    fn signed_json(
        &self,
        payload: Option<&impl Serialize>,
        protected: Header<'_>,
    ) -> Result<Body, Error> {
        let protected = base64(&protected)?;
        let payload = match payload {
            Some(data) => base64(&data)?,
            None => String::new(),
        };

        let combined = format!("{}.{}", protected, payload);
        let signature = self.inner.sign(&self.rng, combined.as_bytes())?;
        Ok(Body::from(serde_json::to_vec(&JoseJson {
            protected,
            payload,
            signature: base64::encode_config(signature.as_ref(), URL_SAFE_NO_PAD),
        })?))
    }
}

impl Signer for Key {
    fn header<'n, 'u: 'n, 's: 'u>(&'s self, nonce: &'n str, url: &'u str) -> Header<'n> {
        Header {
            alg: self.signing_algorithm,
            key: KeyOrKeyId::from_key(&self.inner),
            nonce,
            url,
        }
    }

    fn key(&self) -> &Key {
        self
    }
}

trait Signer {
    fn signed_json(
        &self,
        payload: Option<&impl Serialize>,
        nonce: &str,
        url: &str,
    ) -> Result<Body, Error> {
        self.key().signed_json(payload, self.header(nonce, url))
    }

    fn header<'n, 'u: 'n, 's: 'u>(&'s self, nonce: &'n str, url: &'u str) -> Header<'n>;

    fn key(&self) -> &Key;
}

fn nonce_from_response(rsp: &Response<Body>) -> Option<String> {
    rsp.headers()
        .get(REPLAY_NONCE)
        .and_then(|hv| String::from_utf8(hv.as_ref().to_vec()).ok())
}

fn base64(data: &impl Serialize) -> Result<String, serde_json::Error> {
    Ok(base64::encode_config(
        serde_json::to_vec(data)?,
        URL_SAFE_NO_PAD,
    ))
}

fn client() -> hyper::Client<hyper_rustls::HttpsConnector<HttpConnector>> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();

    hyper::Client::builder().build(https)
}

const JOSE_JSON: &str = "application/jose+json";
const REPLAY_NONCE: &str = "Replay-Nonce";
