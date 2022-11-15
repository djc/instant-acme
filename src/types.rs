use std::borrow::Cow;
use std::fmt;

use base64::URL_SAFE_NO_PAD;
use hyper::{Body, Response};
use ring::digest::{digest, Digest, SHA256};
use ring::signature::{EcdsaKeyPair, KeyPair};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error type for instant-acme
#[derive(Debug, Error)]
pub enum Error {
    /// An JSON problem as returned by the ACME server
    ///
    /// RFC 8555 uses problem documents as described in RFC 7807.
    #[error("API error: {0}")]
    Api(#[from] Problem),
    /// Failed to base64-decode data
    #[error("base64 decoding failed: {0}")]
    Base64(#[from] base64::DecodeError),
    /// Failed from cryptographic operations
    #[error("cryptographic operation failed: {0}")]
    Crypto(#[from] ring::error::Unspecified),
    /// Failed to instantiate a private key
    #[error("invalid key bytes: {0}")]
    CryptoKey(#[from] ring::error::KeyRejected),
    /// HTTP request failure
    #[error("HTTP request failure: {0}")]
    Http(#[from] hyper::Error),
    /// Invalid ACME server URL
    #[error("invalid URI: {0}")]
    InvalidUri(#[from] hyper::http::uri::InvalidUri),
    /// Failed to (de)serialize a JSON object
    #[error("failed to (de)serialize JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Miscellaneous errors
    #[error("missing data: {0}")]
    Str(&'static str),
}

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Self {
        Error::Str(s)
    }
}

/// ACME account credentials
///
/// This opaque type contains the account ID, the private key data and the
/// server URLs from the relevant ACME server. This can be used to serialize
/// the account credentials to a file or secret manager and restore the
/// account from persistent storage.
#[derive(Deserialize, Serialize)]
pub struct AccountCredentials<'a> {
    pub(crate) id: Cow<'a, str>,
    pub(crate) key_pkcs8: String,
    pub(crate) urls: Cow<'a, DirectoryUrls>,
}

/// An RFC 7807 problem document as returned by the ACME server
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    /// One of an enumerated list of problem types
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc8555#section-6.7>
    pub r#type: String,
    /// A human-readable explanation of the problem
    pub detail: String,
    /// The HTTP status code returned for this response
    pub status: u16,
}

impl Problem {
    pub(crate) async fn check<T: DeserializeOwned>(rsp: Response<Body>) -> Result<T, Error> {
        Ok(serde_json::from_slice(
            &hyper::body::to_bytes(Self::from_response(rsp).await?).await?,
        )?)
    }

    pub(crate) async fn from_response(rsp: Response<Body>) -> Result<Body, Error> {
        let status = rsp.status();
        let body = rsp.into_body();
        if status.is_informational() || status.is_success() || status.is_redirection() {
            return Ok(body);
        }

        let body = hyper::body::to_bytes(body).await?;
        Err(serde_json::from_slice::<Problem>(&body)?.into())
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "API error: {} ({})", self.detail, self.r#type)
    }
}

impl std::error::Error for Problem {}

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

/// An ACME challenge as described in RFC 8555 (section 7.1.5)
///
/// <https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.5>
#[derive(Debug, Deserialize)]
pub struct Challenge {
    /// Type of challenge
    pub r#type: ChallengeType,
    /// Challenge identifier
    pub url: String,
    /// Token for this challenge
    pub token: String,
    /// Current status
    pub status: ChallengeStatus,
    /// Potential error state
    pub error: Option<Problem>,
}

/// Contents of an ACME order as described in RFC 8555 (section 7.1.3)
///
/// The order identity will usually be represented by an [Order](crate::Order).
///
/// <https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3>
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderState {
    /// Current status
    pub status: OrderStatus,
    /// Authorization URLs for this order
    ///
    /// There should be one authorization per identifier in the order.
    pub authorizations: Vec<String>,
    /// Potential error state
    pub error: Option<Problem>,
    /// A finalization URL, to be used once status becomes `Ready`
    pub finalize: String,
    /// The certificate URL, which becomes available after finalization
    pub certificate: Option<String>,
}

/// Input data for [Order](crate::Order) creation
///
/// To be passed into [Account::new_order()](crate::Account::new_order()).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewOrder<'a> {
    /// Identifiers to be included in the order
    pub identifiers: &'a [Identifier],
}

/// Input data for [Account](crate::Account) creation
///
/// To be passed into [Account::create()](crate::Account::create()).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccount<'a> {
    /// A list of contact URIs (like `mailto:info@example.com`)
    pub contact: &'a [&'a str],
    /// Whether you agree to the terms of service
    pub terms_of_service_agreed: bool,
    /// Set to `true` in order to retrieve an existing account
    ///
    /// Setting this to `false` has not been tested.
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

/// An ACME authorization as described in RFC 8555 (section 7.1.4)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    /// The identifier that the account is authorized to represent
    pub identifier: Identifier,
    /// Current state of the authorization
    pub status: AuthorizationStatus,
    /// Possible challenges for the authorization
    pub challenges: Vec<Challenge>,
}

/// Status for an [`Authorization`]
#[allow(missing_docs)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthorizationStatus {
    Pending,
    Valid,
    Invalid,
    Revoked,
    Expired,
}

/// Represent an identifier in an ACME [Order](crate::Order)
#[allow(missing_docs)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum Identifier {
    Dns(String),
}

/// The challenge type
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[allow(missing_docs)]
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

/// Status of an [Order](crate::Order)
#[allow(missing_docs)]
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

/// Helper type to reference Let's Encrypt server URLs
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug)]
pub enum LetsEncrypt {
    Production,
    Staging,
}

impl LetsEncrypt {
    /// Get the directory URL for the given Let's Encrypt server
    pub const fn url(&self) -> &'static str {
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
