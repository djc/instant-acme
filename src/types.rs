use std::fmt;

use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::Response;
use rustls_pki_types::CertificateDer;
use serde::de::DeserializeOwned;
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{self, KeyPair};

/// Error type for instant-acme
#[derive(Debug, Error)]
pub enum Error {
    /// An JSON problem as returned by the ACME server
    ///
    /// RFC 8555 uses problem documents as described in RFC 7807.
    #[error(transparent)]
    Api(#[from] Problem),
    /// Failed to base64-decode data
    #[error("base64 decoding failed: {0}")]
    Base64(#[from] base64::DecodeError),
    /// Failed from cryptographic operations
    #[error("cryptographic operation failed: {0}")]
    Crypto(#[from] crypto::Unspecified),
    /// Failed to instantiate a private key
    #[error("invalid key bytes: {0}")]
    CryptoKey(#[from] crypto::KeyRejected),
    /// HTTP failure
    #[error("HTTP request failure: {0}")]
    Http(#[from] hyper::http::Error),
    /// Hyper request failure
    #[error("HTTP request failure: {0}")]
    Hyper(#[from] hyper::Error),
    /// Invalid ACME server URL
    #[error("invalid URI: {0}")]
    InvalidUri(#[from] hyper::http::uri::InvalidUri),
    /// Failed to (de)serialize a JSON object
    #[error("failed to (de)serialize JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Other kind of error
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// Miscellaneous errors
    #[error("missing data: {0}")]
    Str(&'static str),
}

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Self {
        Error::Str(s)
    }
}

impl From<hyper_util::client::legacy::Error> for Error {
    fn from(value: hyper_util::client::legacy::Error) -> Self {
        Self::Other(Box::new(value))
    }
}

/// ACME account credentials
///
/// This opaque type contains the account ID, the private key data and the
/// server URLs from the relevant ACME server. This can be used to serialize
/// the account credentials to a file or secret manager and restore the
/// account from persistent storage.
#[derive(Deserialize, Serialize)]
pub struct AccountCredentials {
    pub(crate) id: String,
    /// Stored in DER, serialized as base64
    #[serde(with = "pkcs8_serde")]
    pub(crate) key_pkcs8: Vec<u8>,
    pub(crate) directory: Option<String>,
    /// We never serialize `urls` by default, but we support deserializing them
    /// in order to support serialized data from older versions of the library.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) urls: Option<DirectoryUrls>,
}

mod pkcs8_serde {
    use std::fmt;

    use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
    use serde::{de, Deserializer, Serializer};

    pub(crate) fn serialize<S>(key_pkcs8: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(key_pkcs8.as_ref());
        serializer.serialize_str(&encoded)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a base64-encoded PKCS#8 private key")
            }

            fn visit_str<E>(self, v: &str) -> Result<Vec<u8>, E>
            where
                E: de::Error,
            {
                BASE64_URL_SAFE_NO_PAD.decode(v).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

/// An RFC 7807 problem document as returned by the ACME server
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    /// One of an enumerated list of problem types
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc8555#section-6.7>
    pub r#type: Option<String>,
    /// A human-readable explanation of the problem
    pub detail: Option<String>,
    /// The HTTP status code returned for this response
    pub status: Option<u16>,
}

impl Problem {
    pub(crate) async fn check<T: DeserializeOwned>(rsp: Response<Incoming>) -> Result<T, Error> {
        Ok(serde_json::from_slice(
            &Self::from_response(rsp).await?.collect().await?.to_bytes(),
        )?)
    }

    pub(crate) async fn from_response(rsp: Response<Incoming>) -> Result<Incoming, Error> {
        let status = rsp.status();
        let body = rsp.into_body();
        if status.is_informational() || status.is_success() || status.is_redirection() {
            return Ok(body);
        }

        let body = body.collect().await?.to_bytes();
        Err(serde_json::from_slice::<Problem>(&body)?.into())
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("API error")?;
        if let Some(detail) = &self.detail {
            write!(f, ": {detail}")?;
        }

        if let Some(r#type) = &self.r#type {
            write!(f, " ({})", r#type)?;
        }

        Ok(())
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
            csr: BASE64_URL_SAFE_NO_PAD.encode(csr_der),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct Header<'a> {
    pub(crate) alg: SigningAlgorithm,
    #[serde(flatten)]
    pub(crate) key: KeyOrKeyId<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) nonce: Option<&'a str>,
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
    pub(crate) fn from_key(key: &crypto::EcdsaKeyPair) -> KeyOrKeyId<'static> {
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
    pub(crate) fn new(key: &crypto::EcdsaKeyPair) -> Self {
        let (x, y) = key.public_key().as_ref()[1..].split_at(32);
        Self {
            alg: SigningAlgorithm::Es256,
            crv: "P-256",
            kty: "EC",
            r#use: "sig",
            x: BASE64_URL_SAFE_NO_PAD.encode(x),
            y: BASE64_URL_SAFE_NO_PAD.encode(y),
        }
    }

    pub(crate) fn thumb_sha256(
        key: &crypto::EcdsaKeyPair,
    ) -> Result<crypto::Digest, serde_json::Error> {
        let jwk = Self::new(key);
        Ok(crypto::digest(
            &crypto::SHA256,
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

/// Payload for a certificate revocation request
/// Defined in <https://datatracker.ietf.org/doc/html/rfc8555#section-7.6>
#[derive(Debug)]
pub struct RevocationRequest<'a> {
    /// The certificate to revoke
    pub certificate: &'a CertificateDer<'a>,
    /// Reason for revocation
    pub reason: Option<RevocationReason>,
}

impl<'a> Serialize for RevocationRequest<'a> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let base64 = BASE64_URL_SAFE_NO_PAD.encode(self.certificate);
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("certificate", &base64)?;
        if let Some(reason) = &self.reason {
            map.serialize_entry("reason", reason)?;
        }
        map.end()
    }
}

/// The reason for a certificate revocation
/// Defined in <https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1>
#[allow(missing_docs)]
#[derive(Debug, Clone)]
#[repr(u8)]
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

impl Serialize for RevocationReason {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.clone() as u8)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NewAccountPayload<'a> {
    #[serde(flatten)]
    pub(crate) new_account: &'a NewAccount<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) external_account_binding: Option<JoseJson>,
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
    // The fields below were added later and old `AccountCredentials` may not have it.
    // Newer deserialized account credentials grab a fresh set of `DirectoryUrls` on
    // deserialization, so they should be fine. Newer fields should be optional, too.
    pub(crate) new_authz: Option<String>,
    pub(crate) revoke_cert: Option<String>,
    pub(crate) key_change: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct JoseJson {
    pub(crate) protected: String,
    pub(crate) payload: String,
    pub(crate) signature: String,
}

impl JoseJson {
    pub(crate) fn new(
        payload: Option<&impl Serialize>,
        protected: Header<'_>,
        signer: &impl Signer,
    ) -> Result<Self, Error> {
        let protected = base64(&protected)?;
        let payload = match payload {
            Some(data) => base64(&data)?,
            None => String::new(),
        };

        let combined = format!("{protected}.{payload}");
        let signature = signer.sign(combined.as_bytes())?;
        Ok(Self {
            protected,
            payload,
            signature: BASE64_URL_SAFE_NO_PAD.encode(signature.as_ref()),
        })
    }
}

pub(crate) trait Signer {
    type Signature: AsRef<[u8]>;

    fn header<'n, 'u: 'n, 's: 'u>(&'s self, nonce: Option<&'n str>, url: &'u str) -> Header<'n>;

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, Error>;
}

fn base64(data: &impl Serialize) -> Result<String, serde_json::Error> {
    Ok(BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(data)?))
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
#[derive(Clone, Copy, Debug, Deserialize)]
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

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

/// Status of an [Order](crate::Order)
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
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
            Self::Production => "https://acme-v02.api.letsencrypt.org/directory",
            Self::Staging => "https://acme-staging-v02.api.letsencrypt.org/directory",
        }
    }
}

/// ZeroSSL ACME only supports production at the moment
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug)]
pub enum ZeroSsl {
    Production,
}

impl ZeroSsl {
    /// Get the directory URL for the given ZeroSSL server
    pub const fn url(&self) -> &'static str {
        match self {
            Self::Production => "https://acme.zerossl.com/v2/DV90",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum SigningAlgorithm {
    /// ECDSA using P-256 and SHA-256
    Es256,
    /// HMAC with SHA-256,
    Hs256,
}

#[derive(Debug, Serialize)]
pub(crate) struct Empty {}
