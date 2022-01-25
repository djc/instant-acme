#![warn(unreachable_pub)]

use std::sync::Arc;

use base64::URL_SAFE_NO_PAD;
use reqwest::header::{CONTENT_TYPE, LOCATION};
use reqwest::redirect::Policy;
use reqwest::{Body, Response};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::de::{DeserializeOwned, Error as _, Unexpected};
use serde::{Deserialize, Serialize};

mod types;
use types::{
    AccountCredentials, Challenge, DirectoryUrls, Empty, FinalizeRequest, Header, JoseJson, Jwk,
    KeyAuthorization, KeyOrKeyId, OrderState, Problem, SigningAlgorithm,
};
pub use types::{
    Authorization, ChallengeType, Error, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus,
};

pub struct Order {
    account: Arc<AccountInner>,
    nonce: Option<String>,
    #[allow(dead_code)]
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

    pub async fn finalize(
        &mut self,
        csr_der: &[u8],
        finalize_url: &str,
    ) -> Result<OrderState, Error> {
        let rsp = self
            .account
            .post(
                Some(&FinalizeRequest::new(csr_der)),
                self.nonce.take(),
                finalize_url,
            )
            .await?;

        self.nonce = nonce_from_response(&rsp);
        Problem::check(rsp).await
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

    pub async fn certificate_chain(&mut self, cert_url: &str) -> Result<String, Error> {
        let rsp = self
            .account
            .post(None::<&Empty>, self.nonce.take(), cert_url)
            .await?;

        self.nonce = nonce_from_response(&rsp);
        let status = rsp.status();
        match status.is_client_error() || status.is_server_error() {
            false => Ok(rsp.text().await?),
            true => Err(rsp.json::<Problem>().await?.into()),
        }
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
        let client = client()?;
        let urls = client.get(server_url).send().await?;
        let client = Client {
            client,
            urls: urls.json().await?,
        };

        let key = Key::generate()?;
        let nonce = client.nonce().await?;
        let header = key.key_header(&nonce, &client.urls.new_account);
        let body = key.signed_json(Some(account), header)?;

        let rsp = client
            .client
            .post(&client.urls.new_account)
            .header(CONTENT_TYPE, JOSE_JSON)
            .body(body)
            .send()
            .await?;

        let account_url = rsp
            .headers()
            .get(LOCATION)
            .and_then(|hv| hv.to_str().ok())
            .map(|s| s.to_owned());

        let status = rsp.status();
        if status.is_client_error() || status.is_server_error() {
            return Err(rsp.json::<Problem>().await?.into());
        }

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
                    client: client().map_err(D::Error::custom)?,
                    urls: creds.urls.clone(),
                },
                id: creds.id.clone(),
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
        Ok(Problem::check(rsp).await?)
    }

    async fn post(
        &self,
        payload: Option<&impl Serialize>,
        nonce: Option<String>,
        url: &str,
    ) -> Result<Response, Error> {
        let nonce = match nonce {
            Some(nonce) => nonce,
            None => self.client.nonce().await?,
        };

        let header = self.key_id_header(&nonce, url);
        let body = self.key.signed_json(payload, header)?;
        Ok(self
            .client
            .client
            .post(url)
            .header(CONTENT_TYPE, JOSE_JSON)
            .body(body)
            .send()
            .await?)
    }

    fn key_id_header<'n, 'u: 'n, 'a: 'u>(&'a self, nonce: &'n str, url: &'u str) -> Header<'n> {
        Header {
            alg: self.key.signing_algorithm,
            key: KeyOrKeyId::KeyId(&self.id),
            nonce,
            url,
        }
    }
}

#[derive(Debug)]
struct Client {
    client: reqwest::Client,
    urls: DirectoryUrls,
}

impl Client {
    async fn nonce(&self) -> Result<String, Error> {
        let future = self.client.head(&self.urls.new_nonce).send();
        match nonce_from_response(&future.await?) {
            Some(nonce) => Ok(nonce),
            None => Err("no nonce found".into()),
        }
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

    fn key_header<'n, 'u: 'n, 'k: 'u>(&'k self, nonce: &'n str, url: &'u str) -> Header<'n> {
        Header {
            alg: self.signing_algorithm,
            key: KeyOrKeyId::from_key(&self.inner),
            nonce,
            url,
        }
    }
}

fn nonce_from_response(rsp: &Response) -> Option<String> {
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

fn client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder().redirect(Policy::none()).build()
}

const JOSE_JSON: &str = "application/jose+json";
const REPLAY_NONCE: &str = "Replay-Nonce";
