use std::fmt;

use base64::URL_SAFE_NO_PAD;
use reqwest::Response;
use ring::digest::{digest, Digest, SHA256};
use ring::signature::{EcdsaKeyPair, KeyPair};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("API error: {0}")]
    Api(#[from] Problem),
    #[error("base64 decoding failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("cryptographic operation failed: {0}")]
    Crypto(#[from] ring::error::Unspecified),
    #[error("invalid key bytes: {0}")]
    CryptoKey(#[from] ring::error::KeyRejected),
    #[error("HTTP request failure: {0}")]
    Http(#[from] reqwest::Error),
    #[error("failed to (de)serialize JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing data: {0}")]
    Str(&'static str),
}

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Self {
        Error::Str(s)
    }
}

#[derive(Deserialize, Serialize)]
pub(crate) struct AccountCredentials {
    pub(crate) id: String,
    pub(crate) key_pkcs8: String,
    pub(crate) urls: DirectoryUrls,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    pub r#type: String,
    pub detail: String,
    pub status: u16,
}

impl Problem {
    pub(crate) async fn check<T: DeserializeOwned>(rsp: Response) -> Result<T, Error> {
        let status = rsp.status();
        match status.is_client_error() || status.is_server_error() {
            false => Ok(rsp.json().await?),
            true => Err(rsp.json::<Self>().await?.into()),
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "API error: {} ({})", self.detail, self.r#type)
    }
}

impl std::error::Error for Problem {}

pub struct KeyAuthorization(pub(crate) String);

impl KeyAuthorization {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn dns_value(&self) -> String {
        base64::encode_config(digest(&SHA256, self.0.as_bytes()), URL_SAFE_NO_PAD)
    }
}

impl fmt::Debug for KeyAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KeyAuthorization").finish()
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct FinalizeRequest {
    csr: String,
}

impl FinalizeRequest {
    pub(crate) fn new(csr_der: &[u8]) -> Self {
        Self {
            csr: base64::encode_config(csr_der, URL_SAFE_NO_PAD),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct Header<'a> {
    pub(crate) alg: SigningAlgorithm,
    #[serde(flatten)]
    pub(crate) key: KeyOrKeyId<'a>,
    pub(crate) nonce: &'a str,
    pub(crate) url: &'a str,
}

#[derive(Debug, Serialize)]
pub(crate) enum KeyOrKeyId<'a> {
    #[serde(rename = "jwk")]
    Key(Jwk),
    #[serde(rename = "kid")]
    KeyId(&'a str),
}

impl<'a> KeyOrKeyId<'a> {
    pub(crate) fn from_key(key: &EcdsaKeyPair) -> KeyOrKeyId<'static> {
        KeyOrKeyId::Key(Jwk::new(key))
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct Jwk {
    alg: SigningAlgorithm,
    crv: &'static str,
    kty: &'static str,
    r#use: &'static str,
    x: String,
    y: String,
}

impl Jwk {
    pub(crate) fn new(key: &EcdsaKeyPair) -> Self {
        let (x, y) = key.public_key().as_ref()[1..].split_at(32);
        Self {
            alg: SigningAlgorithm::Es256,
            crv: "P-256",
            kty: "EC",
            r#use: "sig",
            x: base64::encode_config(x, URL_SAFE_NO_PAD),
            y: base64::encode_config(y, URL_SAFE_NO_PAD),
        }
    }

    pub(crate) fn thumb_sha256(key: &EcdsaKeyPair) -> Result<Digest, serde_json::Error> {
        let jwk = Self::new(key);
        Ok(digest(
            &SHA256,
            &serde_json::to_vec(&JwkThumb {
                crv: jwk.crv,
                kty: jwk.kty,
                x: &jwk.x,
                y: &jwk.y,
            })?,
        ))
    }
}

#[derive(Debug, Serialize)]
struct JwkThumb<'a> {
    crv: &'a str,
    kty: &'a str,
    x: &'a str,
    y: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct Challenge {
    pub r#type: ChallengeType,
    pub url: String,
    pub token: String,
    pub status: ChallengeStatus,
    pub error: Option<Problem>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderState {
    pub status: OrderStatus,
    pub authorizations: Vec<String>,
    pub error: Option<Problem>,
    pub finalize: String,
    pub certificate: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewOrder<'a> {
    pub identifiers: &'a [Identifier],
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccount<'a> {
    pub contact: &'a [&'a str],
    pub terms_of_service_agreed: bool,
    pub only_return_existing: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DirectoryUrls {
    pub(crate) new_nonce: String,
    pub(crate) new_account: String,
    pub(crate) new_order: String,
}

#[derive(Serialize)]
pub(crate) struct JoseJson {
    pub(crate) protected: String,
    pub(crate) payload: String,
    pub(crate) signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum Authorization {
    Pending {
        identifier: Identifier,
        challenges: Vec<Challenge>,
    },
    Valid,
    Invalid,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum Identifier {
    Dns(String),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

#[derive(Clone, Copy, Debug)]
pub enum LetsEncrypt {
    Production,
    Staging,
}

impl LetsEncrypt {
    pub fn url(&self) -> &'static str {
        match self {
            LetsEncrypt::Production => "https://acme-v02.api.letsencrypt.org/directory",
            LetsEncrypt::Staging => "https://acme-staging-v02.api.letsencrypt.org/directory",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum SigningAlgorithm {
    /// ECDSA using P-256 and SHA-256
    Es256,
}

#[derive(Debug, Serialize)]
pub(crate) struct Empty {}
