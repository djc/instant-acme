use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::{self, Write};
use std::net::IpAddr;
use std::time::Instant;

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use rustls_pki_types::{CertificateDer, Der, PrivatePkcs8KeyDer};
use serde::de::{self, DeserializeOwned};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "time")]
use time::OffsetDateTime;
#[cfg(feature = "x509-parser")]
use x509_parser::extensions::ParsedExtension;
#[cfg(feature = "x509-parser")]
use x509_parser::parse_x509_certificate;

use crate::BytesResponse;
use crate::crypto::{self, KeyPair};

/// Error type for instant-acme
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// An JSON problem as returned by the ACME server
    ///
    /// RFC 8555 uses problem documents as described in RFC 7807.
    #[error(transparent)]
    Api(#[from] Problem),
    /// Failed from cryptographic operations
    #[error("cryptographic operation failed")]
    Crypto,
    /// Failed to instantiate a private key
    #[error("invalid key bytes")]
    KeyRejected,
    /// HTTP failure
    #[error("HTTP request failure: {0}")]
    Http(#[from] http::Error),
    /// Hyper request failure
    #[cfg(feature = "hyper-rustls")]
    #[error("HTTP request failure: {0}")]
    Hyper(#[from] hyper::Error),
    /// Invalid ACME server URL
    #[error("invalid URI: {0}")]
    InvalidUri(#[from] http::uri::InvalidUri),
    /// Failed to (de)serialize a JSON object
    #[error("failed to (de)serialize JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Timed out while waiting for the server to update [`OrderStatus`]
    ///
    /// If `Some`, the nested `Instant` indicates when the server suggests to poll next.
    #[error("timed out waiting for an order update")]
    Timeout(Option<Instant>),
    /// ACME server does not support a requested feature
    #[error("ACME server does not support: {0}")]
    Unsupported(&'static str),
    /// Other kind of error
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// Miscellaneous errors
    #[error("missing data: {0}")]
    Str(&'static str),
}

impl Error {
    #[cfg(feature = "rcgen")]
    pub(crate) fn from_rcgen(err: rcgen::Error) -> Self {
        Self::Other(Box::new(err))
    }
}

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Self {
        Self::Str(s)
    }
}

/// ACME account credentials
///
/// This opaque type contains the account ID, the private key data and the
/// server URLs from the relevant ACME server. This can be used to serialize
/// the account credentials to a file or secret manager and restore the
/// account from persistent storage.
#[must_use]
#[derive(Deserialize, Serialize)]
pub struct AccountCredentials {
    pub(crate) id: String,
    /// Stored in DER, serialized as base64
    #[serde(with = "pkcs8_serde")]
    pub(crate) key_pkcs8: PrivatePkcs8KeyDer<'static>,
    pub(crate) directory: Option<String>,
    /// We never serialize `urls` by default, but we support deserializing them
    /// in order to support serialized data from older versions of the library.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) urls: Option<Directory>,
}

impl AccountCredentials {
    /// The account's private key
    pub fn private_key(&self) -> &PrivatePkcs8KeyDer<'_> {
        &self.key_pkcs8
    }
}

mod pkcs8_serde {
    use std::fmt;

    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
    use rustls_pki_types::PrivatePkcs8KeyDer;
    use serde::{Deserializer, Serializer, de};

    pub(crate) fn serialize<S: Serializer>(
        key_pkcs8: &PrivatePkcs8KeyDer<'_>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(key_pkcs8.secret_pkcs8_der());
        serializer.serialize_str(&encoded)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<PrivatePkcs8KeyDer<'static>, D::Error> {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = PrivatePkcs8KeyDer<'static>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a base64-encoded PKCS#8 private key")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                match BASE64_URL_SAFE_NO_PAD.decode(v) {
                    Ok(bytes) => Ok(PrivatePkcs8KeyDer::from(bytes)),
                    Err(err) => Err(de::Error::custom(err)),
                }
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
    /// One or more subproblems associated with specific identifiers
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc8555#section-6.7.1>
    #[serde(default)]
    pub subproblems: Vec<Subproblem>,
}

impl Problem {
    pub(crate) async fn check<T: DeserializeOwned>(rsp: BytesResponse) -> Result<T, Error> {
        Ok(serde_json::from_slice(&Self::from_response(rsp).await?)?)
    }

    pub(crate) async fn from_response(rsp: BytesResponse) -> Result<Bytes, Error> {
        let status = rsp.parts.status;
        let body = rsp.body().await.map_err(Error::Other)?;
        match status.is_informational() || status.is_success() || status.is_redirection() {
            true => Ok(body),
            false => Err(serde_json::from_slice::<Self>(&body)?.into()),
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("API error")?;
        if let Some(detail) = &self.detail {
            write!(f, ": {detail}")?;
        }

        if let Some(r#type) = &self.r#type {
            write!(f, " ({type})")?;
        }

        if !self.subproblems.is_empty() {
            let count = self.subproblems.len();
            write!(f, ": {count} subproblems: ")?;
            for (i, subproblem) in self.subproblems.iter().enumerate() {
                write!(f, "{subproblem}")?;
                if i != count - 1 {
                    f.write_str(", ")?;
                }
            }
        }

        Ok(())
    }
}

impl std::error::Error for Problem {}

/// An RFC 8555 subproblem document contained within a problem returned by the ACME server
///
/// See <https://www.rfc-editor.org/rfc/rfc8555#section-6.7.1>
#[derive(Clone, Debug, Deserialize)]
pub struct Subproblem {
    /// The identifier associated with this problem
    pub identifier: Option<Identifier>,
    /// One of an enumerated list of problem types
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc8555#section-6.7>
    pub r#type: Option<String>,
    /// A human-readable explanation of the problem
    pub detail: Option<String>,
}

impl fmt::Display for Subproblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(identifier) = &self.identifier {
            write!(f, r#"for "{}""#, identifier.authorized(false))?;
        }

        if let Some(detail) = &self.detail {
            write!(f, ": {detail}")?;
        }

        if let Some(r#type) = &self.r#type {
            write!(f, " ({type})")?;
        }

        Ok(())
    }
}

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

impl KeyOrKeyId<'_> {
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
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
pub struct OrderState {
    /// Current status
    pub status: OrderStatus,
    /// Authorizations for this order.
    ///
    /// There should be one authorization per identifier in the order.
    ///
    /// Callers will usually interact with an [`AuthorizationHandle`] obtained
    /// via [`Order::authorizations()`] instead of using this directly.
    ///
    /// [`AuthorizationHandle`]: crate::AuthorizationHandle
    /// [`Order::authorizations()`]: crate::Order::authorizations()
    pub authorizations: Vec<Authorization>,
    /// Potential error state
    pub error: Option<Problem>,
    /// A finalization URL, to be used once status becomes `Ready`
    pub finalize: String,
    /// The certificate URL, which becomes available after finalization
    pub certificate: Option<String>,
    /// The certificate that this order is replacing, if any
    #[serde(deserialize_with = "deserialize_static_certificate_identifier")]
    #[serde(default)]
    pub replaces: Option<CertificateIdentifier<'static>>,
    /// The profile to be used for the order
    #[serde(default)]
    pub profile: Option<String>,
}

/// A wrapper for [`AuthorizationState`] as held in the [`OrderState`]
///
/// Callers will usually interact with an [`AuthorizationHandle`] obtained
/// via [`Order::authorizations()`] instead of using this directly.
///
/// [`AuthorizationHandle`]: crate::AuthorizationHandle
/// [`Order::authorizations()`]: crate::Order::authorizations()
#[derive(Debug)]
pub struct Authorization {
    /// URL for this authorization
    pub url: String,
    /// Current state of the authorization
    ///
    /// This starts out as `None` when the [`OrderState`] is first deserialized.
    /// It is populated when the authorization is first fetched from the server,
    /// typically via [`Order::authorizations()`].
    ///
    /// [`Order::authorizations()`]: crate::Order::authorizations()
    pub state: Option<AuthorizationState>,
}

impl<'de> Deserialize<'de> for Authorization {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self {
            url: String::deserialize(deserializer)?,
            state: None,
        })
    }
}

/// Input data for [Order](crate::Order) creation
///
/// To be passed into [Account::new_order()](crate::Account::new_order()).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewOrder<'a> {
    /// The [`CertificateIdentifier`] of a previously issued certificate being replaced by the order
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) replaces: Option<CertificateIdentifier<'a>>,
    /// Identifiers to be included in the order
    identifiers: &'a [Identifier],
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<&'a str>,
}

impl<'a> NewOrder<'a> {
    /// Prepare to create a new order for the given identifiers
    ///
    /// To be passed into [Account::new_order()](crate::Account::new_order()).
    pub fn new(identifiers: &'a [Identifier]) -> Self {
        Self {
            identifiers,
            replaces: None,
            profile: None,
        }
    }

    /// Indicate to the ACME server that the `NewOrder` is replacing a previously issued certificate
    ///
    /// The previously issued certificate must be identified by a `EncodedCertificateIdentifier`.
    ///
    /// Some ACME servers may give preferential rate limits to orders that replace
    /// existing certificates, or use this information to determine when it is safe
    /// to revoke a certificate affected by a compliance incident.
    ///
    /// When provided, at least one of the `identifiers` for the new order must have been
    /// present in the certificate being replaced. If the ACME CA does not support the
    /// ACME renewal information (ARI) extension, the [crate::Account::new_order()] method will
    /// return an error.
    pub fn replaces(mut self, replaces: CertificateIdentifier<'a>) -> Self {
        self.replaces = Some(replaces);
        self
    }

    /// Set the profile to be used for the order
    ///
    /// [`Account::new_order()`][crate::Account::new_order()] will yield an error if the ACME
    /// server does not support the profiles extension or if the specified profile is not
    /// supported.
    pub fn profile(mut self, profile: &'a str) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Identifiers to be included in the order
    pub fn identifiers(&self) -> &[Identifier] {
        self.identifiers
    }
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

impl Serialize for RevocationRequest<'_> {
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
/// To be passed into [AccountBuilder::create()](crate::AccountBuilder::create()).
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
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub only_return_existing: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Directory {
    pub(crate) new_nonce: String,
    pub(crate) new_account: String,
    pub(crate) new_order: String,
    // The fields below were added later and old `AccountCredentials` may not have it.
    // Newer deserialized account credentials grab a fresh set of `Directory` on
    // deserialization, so they should be fine. Newer fields should be optional, too.
    pub(crate) new_authz: Option<String>,
    pub(crate) revoke_cert: Option<String>,
    pub(crate) key_change: Option<String>,
    // Endpoint for the ACME renewal information (ARI) extension
    //
    // <https://www.rfc-editor.org/rfc/rfc9773.html>
    pub(crate) renewal_info: Option<String>,
    #[serde(default)]
    pub(crate) meta: Meta,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct Meta {
    #[serde(default)]
    pub(crate) profiles: HashMap<String, String>,
}

/// Profile meta information from the server directory
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug)]
pub struct ProfileMeta<'a> {
    pub name: &'a str,
    pub description: &'a str,
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

/// An ACME authorization's state as described in RFC 8555 (section 7.1.4)
#[derive(Debug, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationState {
    /// The identifier that the account is authorized to represent
    identifier: Identifier,
    /// Current state of the authorization
    pub status: AuthorizationStatus,
    /// Possible challenges for the authorization
    pub challenges: Vec<Challenge>,
    /// Whether the identifier represents a wildcard domain name
    #[serde(default)]
    pub wildcard: bool,
}

impl AuthorizationState {
    /// Creates an [`AuthorizedIdentifier`] for the identifier in this authorization
    pub fn identifier(&self) -> AuthorizedIdentifier<'_> {
        self.identifier.authorized(self.wildcard)
    }
}

/// Status for an [`AuthorizationState`]
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum AuthorizationStatus {
    Pending,
    Valid,
    Invalid,
    Revoked,
    Expired,
    Deactivated,
}

/// Represent an identifier in an ACME [Order](crate::Order)
#[allow(missing_docs)]
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[non_exhaustive]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum Identifier {
    Dns(String),

    /// An IP address (IPv4 or IPv6) identifier
    ///
    /// Note that not all ACME servers will accept an order with an IP address identifier.
    Ip(IpAddr),

    /// Permanent Identifier
    ///
    /// Note that this identifier is only used for attestation.
    PermanentIdentifier(String),

    /// Hardware Module identifier
    ///
    /// Note that this identifier is only used for attestation.
    HardwareModule(String),
}

impl Identifier {
    /// Create an [`AuthorizedIdentifier`], which implements `Display`
    ///
    /// Needs the `wildcard` context bit to determine whether the identifier represents a
    /// wildcard domain.
    pub fn authorized(&self, wildcard: bool) -> AuthorizedIdentifier<'_> {
        AuthorizedIdentifier {
            identifier: self,
            wildcard,
        }
    }
}

/// An [`Identifier`] which knows its `wildcard` context
#[non_exhaustive]
#[derive(Debug)]
pub struct AuthorizedIdentifier<'a> {
    /// The source identifier, missing any wildcard context
    pub identifier: &'a Identifier,
    /// Whether the identifier should be interpreted as a wildcard
    ///
    /// This is only relevant for DNS identifiers and must be false for other
    /// types of identifiers (e.g. IP addresses).
    pub wildcard: bool,
}

impl fmt::Display for AuthorizedIdentifier<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.wildcard, self.identifier) {
            (true, Identifier::Dns(dns)) => f.write_fmt(format_args!("*.{dns}")),
            (false, Identifier::Dns(dns)) => f.write_str(dns),
            (_, Identifier::Ip(addr)) => write!(f, "{addr}"),
            (_, Identifier::PermanentIdentifier(permanent_identifier)) => {
                f.write_str(permanent_identifier)
            }
            (_, Identifier::HardwareModule(hardware_module)) => f.write_str(hardware_module),
        }
    }
}

/// The challenge type
#[allow(missing_docs)]
#[non_exhaustive]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    /// Note: Device attestation support is experimental
    #[serde(rename = "device-attest-01")]
    DeviceAttest01,
    #[serde(untagged)]
    Unknown(String),
}

/// Status of an ACME [Challenge]
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
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

/// A unique certificate identifier for the ACME renewal information (ARI) extension
///
/// See <https://www.rfc-editor.org/rfc/rfc9773.html#section-4.1> for
/// more information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateIdentifier<'a> {
    /// The BASE64URL-encoded authority key identifier (AKI) extension `keyIdentifier` of the certificate
    pub authority_key_identifier: Cow<'a, str>,

    /// The BASE64URL-encoded serial number of the certificate
    pub serial: Cow<'a, str>,
}

impl CertificateIdentifier<'_> {
    /// Encode a unique certificate identifier using the provided authority key ID and serial
    ///
    /// `authority_key_identifier` must be the DER-encoded ASN.1 octet string from the
    /// `keyIdentifier` field of the `AuthorityKeyIdentifier` extension found in the certificate
    /// to be identified.
    ///
    /// `serial` must be the DER-encoded ASN.1 serial number from the certificate to be identified.
    /// Care must be taken to use the **encoded** serial number, not a big integer representation.
    ///
    /// The combination uniquely identifies a certificate within all certificates issued by the
    /// same CA.
    ///
    /// See [RFC 5280 §4.1.2.2], [RFC 5280 §4.2.1.1], and [RFC 9773 §4.1]
    ///
    /// [RFC 5280 §4.1.2.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2
    /// [RFC 5280 §4.2.1.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1
    /// [RFC 9773 §4.1]: https://www.rfc-editor.org/rfc/rfc9773.html#section-4.1
    pub fn new(authority_key_identifier: Der<'_>, serial: Der<'_>) -> Self {
        Self {
            authority_key_identifier: BASE64_URL_SAFE_NO_PAD
                .encode(authority_key_identifier)
                .into(),
            serial: BASE64_URL_SAFE_NO_PAD.encode(serial).into(),
        }
    }

    /// Convert the `CertificateIdentifier` into an owned version with a static lifetime
    pub fn into_owned(self) -> CertificateIdentifier<'static> {
        CertificateIdentifier {
            authority_key_identifier: Cow::Owned(self.authority_key_identifier.into_owned()),
            serial: Cow::Owned(self.serial.into_owned()),
        }
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for CertificateIdentifier<'a> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(deserializer)?;

        let Some((aki, serial)) = s.split_once('.') else {
            return Err(de::Error::invalid_value(
                de::Unexpected::Str(s),
                &"a string containing 2 '.'-delimited parts",
            ));
        };

        if serial.contains('.') {
            return Err(de::Error::invalid_value(
                de::Unexpected::Str(s),
                &"only one '.' delimiter should be present",
            ));
        }

        Ok(CertificateIdentifier {
            authority_key_identifier: Cow::Borrowed(aki),
            serial: Cow::Borrowed(serial),
        })
    }
}

impl Serialize for CertificateIdentifier<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "x509-parser")]
impl<'a> TryFrom<&'a CertificateDer<'_>> for CertificateIdentifier<'_> {
    type Error = String;

    fn try_from(cert: &'a CertificateDer<'_>) -> Result<Self, Self::Error> {
        let (_, parsed_cert) = parse_x509_certificate(cert.as_ref())
            .map_err(|e| format!("failed to parse certificate: {e}"))?;

        let Some(authority_key_identifier) =
            parsed_cert
                .iter_extensions()
                .find_map(|ext| match ext.parsed_extension() {
                    ParsedExtension::AuthorityKeyIdentifier(aki_ext) => aki_ext
                        .key_identifier
                        .as_ref()
                        .map(|aki| Der::from_slice(aki.0)),
                    _ => None,
                })
        else {
            return Err(
                "certificate does not contain an Authority Key Identifier (AKI) extension".into(),
            );
        };

        Ok(Self::new(
            authority_key_identifier,
            Der::from_slice(parsed_cert.tbs_certificate.raw_serial()),
        ))
    }
}

impl fmt::Display for CertificateIdentifier<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.authority_key_identifier)?;
        f.write_char('.')?;
        f.write_str(&self.serial)
    }
}

/// Information about a suggested renewal window for a certificate
///
/// See <https://www.rfc-editor.org/rfc/rfc9773.html#section-4.2>
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "time")]
pub struct RenewalInfo {
    /// The suggested renewal window for a certificate
    pub suggested_window: SuggestedWindow,
    /// A URL to a page explaining why the suggested renewal window has its current value
    #[serde(rename = "explanationURL")]
    pub explanation_url: Option<String>,
}

/// A suggested renewal window for a certificate
///
/// See <https://www.rfc-editor.org/rfc/rfc9773.html#section-4.2>
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "time")]
pub struct SuggestedWindow {
    /// The start [`OffsetDateTime`] of the suggested renewal window
    #[serde(with = "time::serde::rfc3339")]
    pub start: OffsetDateTime,
    /// The end [`OffsetDateTime`] of the suggested renewal window
    #[serde(with = "time::serde::rfc3339")]
    pub end: OffsetDateTime,
}

fn deserialize_static_certificate_identifier<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<CertificateIdentifier<'static>>, D::Error> {
    let Some(cert_id) = Option::<CertificateIdentifier<'_>>::deserialize(deserializer)? else {
        return Ok(None);
    };

    Ok(Some(cert_id.into_owned()))
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum SigningAlgorithm {
    /// ECDSA using P-256 and SHA-256
    Es256,
    /// HMAC with SHA-256,
    Hs256,
}

/// Attestation payload used for device-attest-01
///
/// See <https://datatracker.ietf.org/doc/draft-acme-device-attest/> for details.
pub struct DeviceAttestation<'a> {
    /// CBOR encoded attestation payload
    pub att_obj: Cow<'a, [u8]>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Empty {}

#[cfg(test)]
mod tests {
    #[cfg(feature = "x509-parser")]
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, IsCa, Issuer, KeyIdMethod, KeyPair,
        SerialNumber,
    };

    use super::*;

    // https://datatracker.ietf.org/doc/html/rfc8555#section-7.4
    #[test]
    fn order() {
        const ORDER: &str = r#"{
          "status": "pending",
          "expires": "2016-01-05T14:09:07.99Z",

          "notBefore": "2016-01-01T00:00:00Z",
          "notAfter": "2016-01-08T00:00:00Z",

          "identifiers": [
            { "type": "dns", "value": "www.example.org" },
            { "type": "dns", "value": "example.org" }
          ],

          "authorizations": [
            "https://example.com/acme/authz/PAniVnsZcis",
            "https://example.com/acme/authz/r4HqLzrSrpI"
          ],

          "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
        }"#;

        let obj = serde_json::from_str::<OrderState>(ORDER).unwrap();
        assert_eq!(obj.status, OrderStatus::Pending);
        assert_eq!(obj.authorizations.len(), 2);
        assert_eq!(
            obj.finalize,
            "https://example.com/acme/order/TOlocE8rfgo/finalize"
        );
    }

    // https://datatracker.ietf.org/doc/html/rfc8555#section-7.5.1
    #[test]
    fn authorization() {
        const AUTHORIZATION: &str = r#"{
          "status": "valid",
          "expires": "2018-09-09T14:09:01.13Z",

          "identifier": {
            "type": "dns",
            "value": "www.example.org"
          },

          "challenges": [
            {
              "type": "http-01",
              "url": "https://example.com/acme/chall/prV_B7yEyA4",
              "status": "valid",
              "validated": "2014-12-01T12:05:13.72Z",
              "token": "IlirfxKKXAsHtmzK29Pj8A"
            }
          ]
        }"#;

        let obj = serde_json::from_str::<AuthorizationState>(AUTHORIZATION).unwrap();
        assert_eq!(obj.status, AuthorizationStatus::Valid);
        assert_eq!(obj.identifier, Identifier::Dns("www.example.org".into()));
        assert_eq!(obj.challenges.len(), 1);
    }

    // https://datatracker.ietf.org/doc/html/rfc8555#section-8.4
    #[test]
    fn challenge() {
        const CHALLENGE: &str = r#"{
          "type": "dns-01",
          "url": "https://example.com/acme/chall/Rg5dV14Gh1Q",
          "status": "pending",
          "token": "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
        }"#;

        let obj = serde_json::from_str::<Challenge>(CHALLENGE).unwrap();
        assert_eq!(obj.r#type, ChallengeType::Dns01);
        assert_eq!(obj.url, "https://example.com/acme/chall/Rg5dV14Gh1Q");
        assert_eq!(obj.status, ChallengeStatus::Pending);
        assert_eq!(obj.token, "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA");
    }

    // https://datatracker.ietf.org/doc/html/rfc8555#section-7.6
    #[test]
    fn problem() {
        const PROBLEM: &str = r#"{
          "type": "urn:ietf:params:acme:error:unauthorized",
          "detail": "No authorization provided for name example.org"
        }"#;

        let obj = serde_json::from_str::<Problem>(PROBLEM).unwrap();
        assert_eq!(
            obj.r#type,
            Some("urn:ietf:params:acme:error:unauthorized".into())
        );
        assert_eq!(
            obj.detail,
            Some("No authorization provided for name example.org".into())
        );
        assert!(obj.subproblems.is_empty());
    }

    // https://www.rfc-editor.org/rfc/rfc8555#section-6.7.1
    #[test]
    fn subproblems() {
        const PROBLEM: &str = r#"{
            "type": "urn:ietf:params:acme:error:malformed",
            "detail": "Some of the identifiers requested were rejected",
            "subproblems": [
                {
                    "type": "urn:ietf:params:acme:error:malformed",
                    "detail": "Invalid underscore in DNS name \"_example.org\"",
                    "identifier": {
                        "type": "dns",
                        "value": "_example.org"
                    }
                },
                {
                    "type": "urn:ietf:params:acme:error:rejectedIdentifier",
                    "detail": "This CA will not issue for \"example.net\"",
                    "identifier": {
                        "type": "dns",
                        "value": "example.net"
                    }
                }
            ]
        }"#;

        let obj = serde_json::from_str::<Problem>(PROBLEM).unwrap();
        assert_eq!(
            obj.r#type,
            Some("urn:ietf:params:acme:error:malformed".into())
        );
        assert_eq!(
            obj.detail,
            Some("Some of the identifiers requested were rejected".into())
        );

        let subproblems = &obj.subproblems;
        assert_eq!(subproblems.len(), 2);

        let first_subproblem = subproblems.first().unwrap();
        assert_eq!(
            first_subproblem.identifier,
            Some(Identifier::Dns("_example.org".into()))
        );
        assert_eq!(
            first_subproblem.r#type,
            Some("urn:ietf:params:acme:error:malformed".into())
        );
        assert_eq!(
            first_subproblem.detail,
            Some(r#"Invalid underscore in DNS name "_example.org""#.into())
        );

        let second_subproblem = subproblems.get(1).unwrap();
        assert_eq!(
            second_subproblem.identifier,
            Some(Identifier::Dns("example.net".into()))
        );
        assert_eq!(
            second_subproblem.r#type,
            Some("urn:ietf:params:acme:error:rejectedIdentifier".into())
        );
        assert_eq!(
            second_subproblem.detail,
            Some(r#"This CA will not issue for "example.net""#.into())
        );

        let expected_display = "\
    API error: Some of the identifiers requested were rejected (urn:ietf:params:acme:error:malformed): \
    2 subproblems: \
    for \"_example.org\": Invalid underscore in DNS name \"_example.org\" (urn:ietf:params:acme:error:malformed), \
    for \"example.net\": This CA will not issue for \"example.net\" (urn:ietf:params:acme:error:rejectedIdentifier)";
        assert_eq!(format!("{obj}"), expected_display);
    }

    // https://www.rfc-editor.org/rfc/rfc9773.html#section-4.1
    #[test]
    fn certificate_identifier() {
        const ORDER: &str = r#"{
          "status": "pending",
          "expires": "2016-01-05T14:09:07.99Z",

          "notBefore": "2016-01-01T00:00:00Z",
          "notAfter": "2016-01-08T00:00:00Z",

          "identifiers": [
            { "type": "dns", "value": "www.example.org" },
            { "type": "dns", "value": "example.org" }
          ],

          "authorizations": [
            "https://example.com/acme/authz/PAniVnsZcis",
            "https://example.com/acme/authz/r4HqLzrSrpI"
          ],

          "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize",

          "replaces": "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"
        }"#;

        let order = serde_json::from_str::<OrderState>(ORDER).unwrap();
        let cert_id = order.replaces.unwrap();
        assert_eq!(
            cert_id.authority_key_identifier,
            "aYhba4dGQEHhs3uEe6CuLN4ByNQ"
        );
        assert_eq!(cert_id.serial, "AIdlQyE");

        let serialized = serde_json::to_string(&cert_id).unwrap();
        assert_eq!(serialized, r#""aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE""#);
    }

    #[cfg(feature = "x509-parser")]
    #[test]
    fn encoded_certificate_identifier_from_cert() {
        // Generate a CA key_pair and self-signed cert with a specific subject key identifier.
        let ca_key_id = vec![0xC0, 0xFF, 0xEE];
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_identifier_method = KeyIdMethod::PreSpecified(ca_key_id);
        let ca = Issuer::new(ca_params, ca_key);

        // Generate an end entity certificate issued by the CA, with a specific serial number
        // and an AKI extension.
        let ee_key = KeyPair::generate().unwrap();
        let ee_serial = [0xCA, 0xFE];
        let mut ee_params = CertificateParams::new(["example.com".to_owned()]).unwrap();
        ee_params.distinguished_name = DistinguishedName::new();
        ee_params.serial_number = Some(SerialNumber::from_slice(ee_serial.as_slice()));
        ee_params.use_authority_key_identifier_extension = true;
        let ee_cert = ee_params.signed_by(&ee_key, &ca).unwrap();

        // Extract the AKI and serial number from the EE certificate and create an encoded
        // certificate identifier.
        let encoded = CertificateIdentifier::try_from(ee_cert.der()).unwrap();

        // We should arrive at the expected encoded certificate identifier.
        assert_eq!(format!("{encoded}"), "wP_u.AMr-");
    }

    // https://www.rfc-editor.org/rfc/rfc9773.html#section-4.2
    #[test]
    #[cfg(feature = "time")]
    fn renewal_info() {
        const INFO: &str = r#"{
          "suggestedWindow": {
            "start": "2025-01-02T04:00:00Z",
            "end": "2025-01-03T04:00:00Z"
          },
          "explanationURL": "https://acme.example.com/docs/ari"
        }
        "#;

        let info = serde_json::from_str::<RenewalInfo>(INFO).unwrap();
        assert_eq!(
            info.explanation_url.unwrap(),
            "https://acme.example.com/docs/ari"
        );
        let window = info.suggested_window;
        assert_eq!(window.start.day(), 2);
        assert_eq!(window.end.day(), 3);
    }
}
