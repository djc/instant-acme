//! ACME challenges and challenge type specific handling

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::account::{AccountInner, Key};
use crate::nonce_from_response;
use crate::types::{AuthorizationState, AuthorizedIdentifier, Empty, Error, Identifier, Problem};

/// An ACME challenge as described in RFC 8555 (section 7.1.5)
///
/// <https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.5>
#[derive(Debug, Deserialize)]
pub struct Challenge {
    /// Challenge identifier
    pub url: String,
    /// Challenge type specific state
    #[serde(flatten)]
    pub state: ChallengeState,
    /// Current status
    pub status: ChallengeStatus,
    /// Potential error state
    pub error: Option<Problem>,
}

/// Challenge type specific state
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "type")]
#[non_exhaustive]
pub enum ChallengeState {
    /// State for an RFC 8555 HTTP-01 challenge
    #[serde(rename = "http-01")]
    Http01(http01::Challenge),
    /// State for an RFC 8555 DNS-01 challenge
    #[serde(rename = "dns-01")]
    Dns01(dns01::Challenge),
    /// State for an RFC 8737 TLS-ALPN-01 challenge
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01(tls_alpn01::Challenge),
    /// State for a draft-acme-device-attest-08 challenge
    ///
    /// Note: Device attestation support is experimental
    #[serde(rename = "device-attest-01")]
    DeviceAttest01(device_attest01::Challenge),
    /// An unknown challenge type
    #[serde(other)]
    Unknown,
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

/// A handle for interacting with a challenge of a specific type
///
/// The `T` type parameter is the challenge type specific state type (e.g.
/// [`http01::Challenge`]) and determines which operations are available.
/// Obtain a handle from the accessor for the challenge type on
/// [`AuthorizationHandle`][crate::AuthorizationHandle] (e.g.
/// [`AuthorizationHandle::http01()`][crate::AuthorizationHandle::http01()]).
pub struct ChallengeHandle<'a, T> {
    state: ChallengeHandleState<'a>,
    challenge: &'a T,
}

impl<'a, T> ChallengeHandle<'a, T> {
    pub(crate) fn new(
        authz: &'a AuthorizationState,
        nonce: &'a mut Option<String>,
        account: &'a AccountInner,
    ) -> Option<Self>
    where
        T: ChallengeVariant,
    {
        if !T::supports_identifier(authz.identifier().identifier) {
            return None;
        }

        let (challenge, data) = authz
            .challenges
            .iter()
            .find_map(|c| Some((c, T::from_state(&c.state)?)))?;
        Some(Self {
            state: ChallengeHandleState {
                identifier: authz.identifier(),
                challenge,
                nonce,
                account,
            },
            challenge: data,
        })
    }
}

impl<T> ChallengeHandle<'_, T> {
    /// The underlying ACME challenge
    pub fn challenge(&self) -> &Challenge {
        self.state.challenge
    }

    /// The identifier for this challenge's authorization
    pub fn identifier(&self) -> &AuthorizedIdentifier<'_> {
        &self.state.identifier
    }
}

/// Shared state common to all challenge handles
struct ChallengeHandleState<'a> {
    identifier: AuthorizedIdentifier<'a>,
    challenge: &'a Challenge,
    nonce: &'a mut Option<String>,
    account: &'a AccountInner,
}

impl ChallengeHandleState<'_> {
    /// Notify the server that the given challenge is ready to be completed
    ///
    /// Traditional token-based challenges are acknowledged with an empty object body.
    async fn set_ready(&mut self) -> Result<(), Error> {
        self.respond(&Empty {}).await.map(drop)
    }

    /// Respond to the challenge with a type-specific payload
    async fn respond(&mut self, payload: &impl Serialize) -> Result<ChallengeStatus, Error> {
        let rsp = self
            .account
            .post(Some(payload), self.nonce.take(), &self.challenge.url)
            .await?;

        *self.nonce = nonce_from_response(&rsp);
        let response = Problem::check::<Challenge>(rsp).await?;
        match response.error {
            Some(details) => Err(Error::Api(details)),
            None => Ok(response.status),
        }
    }
}

/// A challenge state type corresponding to one [`ChallengeState`] variant
///
/// Implemented by the challenge state types in the per-challenge type submodules
/// (e.g. [`http01::Challenge`]).
pub(crate) trait ChallengeVariant: Sized {
    /// Get a reference to this state type's data from `state`, if the type matches
    fn from_state(state: &ChallengeState) -> Option<&Self>;

    /// Whether this challenge type supports authorizations for `identifier`
    fn supports_identifier(identifier: &Identifier) -> bool;
}

#[derive(Debug)]
struct KeyAuthorization {
    // The token is stored as the key authorization's prefix; retaining its length lets
    // token() borrow that prefix without allocating a second String.
    token_len: usize,
    value: String,
    digest: [u8; 32],
}

impl KeyAuthorization {
    fn new(token: &str, key: &Key) -> Self {
        let value = format!("{token}.{}", key.thumbprint());
        Self {
            digest: key.provider.sha256.hash(value.as_bytes()),
            token_len: token.len(),
            value,
        }
    }

    fn token(&self) -> &str {
        &self.value[..self.token_len]
    }
}

pub mod http01 {
    //! Support for RFC 8555 http-01 challenges
    //!
    //! See <https://www.rfc-editor.org/rfc/rfc8555#section-8.3>

    use serde::Deserialize;

    use super::{ChallengeHandle, ChallengeState, ChallengeVariant, KeyAuthorization};
    use crate::types::{Error, Identifier};

    /// Challenge state for an http-01 challenge
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
    #[non_exhaustive]
    pub struct Challenge {
        /// A token for constructing a key authorization to complete this challenge
        pub token: String,
    }

    impl ChallengeVariant for Challenge {
        fn from_state(state: &ChallengeState) -> Option<&Self> {
            match state {
                ChallengeState::Http01(data) => Some(data),
                _ => None,
            }
        }

        fn supports_identifier(identifier: &Identifier) -> bool {
            // https://www.rfc-editor.org/info/rfc8555/#section-9.7.8
            // https://www.rfc-editor.org/info/rfc8738/#section-8.2
            matches!(identifier, Identifier::Dns(_) | Identifier::Ip(_))
        }
    }

    impl ChallengeHandle<'_, Challenge> {
        /// Notify the server that the challenge is ready to be completed
        pub async fn set_ready(&mut self) -> Result<(), Error> {
            self.state.set_ready().await
        }

        /// The token for this challenge
        pub fn token(&self) -> &str {
            &self.challenge.token
        }

        /// Create a [`Response`] for this challenge
        pub fn response(&self) -> Response {
            Response::new(&self.challenge.token, &self.state.account.key)
        }
    }

    /// Challenge response data for an http-01 challenge
    #[must_use = "the response data must be provisioned before marking the challenge ready"]
    #[derive(Debug)]
    pub struct Response {
        key_authorization: KeyAuthorization,
    }

    impl Response {
        fn new(token: &str, key: &super::Key) -> Self {
            Self {
                key_authorization: KeyAuthorization::new(token, key),
            }
        }

        /// The challenge token for this challenge response.
        pub fn token(&self) -> &str {
            self.key_authorization.token()
        }

        /// The key authorization content that should be placed in the challenge response file.
        ///
        /// The file should be provisioned at `/.well-known/acme-challenge/<token>` in your
        /// webserver's web root.
        pub fn key_authorization(&self) -> &str {
            &self.key_authorization.value
        }
    }

    /// A handle for interacting with an http-01 challenge
    pub type Handle<'a> = ChallengeHandle<'a, Challenge>;
}

pub mod dns01 {
    //! Support for RFC 8555 dns-01 challenges
    //!
    //! See <https://www.rfc-editor.org/rfc/rfc8555#section-8.4>

    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
    use serde::Deserialize;

    use super::{ChallengeHandle, ChallengeState, ChallengeVariant, KeyAuthorization};
    use crate::account::Key;
    use crate::types::{Error, Identifier};

    /// Challenge state for a dns-01 challenge
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
    #[non_exhaustive]
    pub struct Challenge {
        /// A token for constructing a key authorization to complete this challenge
        pub token: String,
    }

    impl ChallengeVariant for Challenge {
        fn from_state(state: &ChallengeState) -> Option<&Self> {
            match state {
                ChallengeState::Dns01(data) => Some(data),
                _ => None,
            }
        }

        fn supports_identifier(identifier: &Identifier) -> bool {
            // https://www.rfc-editor.org/info/rfc8555/#section-9.7.8
            // https://www.rfc-editor.org/rfc/rfc8738#section-7
            matches!(identifier, Identifier::Dns(_))
        }
    }

    impl ChallengeHandle<'_, Challenge> {
        /// Notify the server that the challenge is ready to be completed
        pub async fn set_ready(&mut self) -> Result<(), Error> {
            self.state.set_ready().await
        }

        /// The token for this challenge
        pub fn token(&self) -> &str {
            &self.challenge.token
        }

        /// Create a [`Response`] for this challenge
        pub fn response(&self) -> Response {
            Response::new(
                self.state.identifier.identifier,
                &self.challenge.token,
                &self.state.account.key,
            )
        }
    }

    /// Challenge response data for a dns-01 challenge
    #[must_use = "the response data must be provisioned before marking the challenge ready"]
    #[derive(Debug)]
    pub struct Response {
        host: String,
        rdata: String,
    }

    impl Response {
        fn new(identifier: &Identifier, token: &str, key: &Key) -> Self {
            let Identifier::Dns(domain) = identifier else {
                unreachable!("DNS-01 only supports domain identifiers");
            };

            let key_authorization = KeyAuthorization::new(token, key);

            Self {
                host: format!("_acme-challenge.{domain}."),
                rdata: BASE64_URL_SAFE_NO_PAD.encode(key_authorization.digest),
            }
        }

        /// Fully qualified hostname for the challenge response TXT record to be provisioned
        ///
        /// Includes a trailing dot.
        pub fn host(&self) -> &str {
            &self.host
        }

        /// The TXT record RDATA to provision for [`Self::host()`]
        ///
        /// This is the base64-encoded SHA256 digest of the challenge key authorization.
        pub fn rdata(&self) -> &str {
            &self.rdata
        }
    }

    /// A handle for interacting with a dns-01 challenge
    pub type Handle<'a> = ChallengeHandle<'a, Challenge>;
}

pub mod tls_alpn01 {
    //! Support for RFC 8737 tls-alpn-01 challenges
    //!
    //! See <https://www.rfc-editor.org/rfc/rfc8737#section-3>

    use serde::Deserialize;

    use super::{ChallengeHandle, ChallengeState, ChallengeVariant, KeyAuthorization};
    use crate::types::{Error, Identifier};

    /// Challenge state for a tls-alpn-01 challenge
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
    #[non_exhaustive]
    pub struct Challenge {
        /// A token for constructing a key authorization to complete this challenge
        pub token: String,
    }

    impl ChallengeVariant for Challenge {
        fn from_state(state: &ChallengeState) -> Option<&Self> {
            match state {
                ChallengeState::TlsAlpn01(data) => Some(data),
                _ => None,
            }
        }

        fn supports_identifier(identifier: &Identifier) -> bool {
            // https://www.rfc-editor.org/info/rfc8737/#section-6.3
            // https://www.rfc-editor.org/info/rfc8738/#section-8.2
            matches!(identifier, Identifier::Dns(_) | Identifier::Ip(_))
        }
    }

    impl ChallengeHandle<'_, Challenge> {
        /// Notify the server that the challenge is ready to be completed
        pub async fn set_ready(&mut self) -> Result<(), Error> {
            self.state.set_ready().await
        }

        /// The token for this challenge
        pub fn token(&self) -> &str {
            &self.challenge.token
        }

        /// Create a [`Response`] for this challenge
        pub fn response(&self) -> Response {
            Response::new(&self.challenge.token, &self.state.account.key)
        }
    }

    /// Challenge response data for a tls-alpn-01 challenge
    #[must_use = "the response data must be provisioned before marking the challenge ready"]
    #[derive(Debug)]
    pub struct Response {
        key_authorization: KeyAuthorization,
    }

    impl Response {
        fn new(token: &str, key: &super::Key) -> Self {
            Self {
                key_authorization: KeyAuthorization::new(token, key),
            }
        }

        /// The unhashed key authorization string
        ///
        /// Typically, you would prefer using [`Self::extension_value`] to construct
        /// a DER encoded id-pe-acmeIdentifier extension.
        ///
        /// This API may be useful when using a higher-level TLS-ALPN-01 certificate generation
        /// API that expects the RFC-8555 §8.1 key authorization string as input.
        pub fn key_authorization(&self) -> &str {
            &self.key_authorization.value
        }

        /// The SHA-256 digest of the RFC-8555 §8.1 key authorization string
        ///
        /// This can be used to construct a DER encoded id-pe-acmeIdentifier extension
        /// for embedding in a provisioned TLS-ALPN-01 challenge response certificate.
        pub fn extension_value(&self) -> &[u8; 32] {
            &self.key_authorization.digest
        }
    }

    /// A handle for interacting with a tls-alpn-01 challenge
    pub type Handle<'a> = ChallengeHandle<'a, Challenge>;
}

pub mod device_attest01 {
    //! Support for draft-ietf-acme-device-attest device-attest-01 challenges
    //!
    //! See <https://datatracker.ietf.org/doc/draft-ietf-acme-device-attest/>
    //!
    //! Note: device attestation support is experimental.

    use std::borrow::Cow;

    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
    use serde::{Deserialize, Serialize};

    use super::{
        ChallengeHandle, ChallengeState, ChallengeStatus, ChallengeVariant, DeviceAttestation,
    };
    use crate::types::{Error, Identifier};

    /// Challenge state for a device-attest-01 challenge
    ///
    /// device-attest-01 challenges carry no additional type specific state.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
    #[non_exhaustive]
    pub struct Challenge {}

    impl ChallengeVariant for Challenge {
        fn from_state(state: &ChallengeState) -> Option<&Self> {
            match state {
                ChallengeState::DeviceAttest01(data) => Some(data),
                _ => None,
            }
        }

        fn supports_identifier(identifier: &Identifier) -> bool {
            // https://datatracker.ietf.org/doc/html/draft-acme-device-attest-08#section-7.2
            matches!(
                identifier,
                Identifier::PermanentIdentifier(_) | Identifier::HardwareModule(_)
            )
        }
    }

    impl ChallengeHandle<'_, Challenge> {
        /// Notify the server that the challenge is ready by sending a device attestation
        ///
        /// See <https://datatracker.ietf.org/doc/draft-ietf-acme-device-attest/> for details.
        ///
        /// `payload` is the device attestation object. Provide the attestation
        /// object as a raw blob; base64 encoding is done by this function.
        pub async fn send_attestation(
            &mut self,
            payload: &DeviceAttestation<'_>,
        ) -> Result<ChallengeStatus, Error> {
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct DeviceAttestationBase64<'a> {
                att_obj: Cow<'a, str>,
            }

            let payload = DeviceAttestationBase64 {
                att_obj: Cow::Owned(BASE64_URL_SAFE_NO_PAD.encode(&payload.att_obj)),
            };

            self.state.respond(&payload).await
        }
    }

    /// A handle for interacting with a device-attest-01 challenge
    pub type Handle<'a> = ChallengeHandle<'a, Challenge>;
}

/// Attestation payload used for device-attest-01
///
/// See <https://datatracker.ietf.org/doc/draft-acme-device-attest/> for details.
pub struct DeviceAttestation<'a> {
    /// CBOR encoded attestation payload
    pub att_obj: Cow<'a, [u8]>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(obj.url, "https://example.com/acme/chall/Rg5dV14Gh1Q");
        assert_eq!(obj.status, ChallengeStatus::Pending);

        let ChallengeState::Dns01(chall_state) = obj.state else {
            panic!("wrong challenge state type");
        };
        assert_eq!(
            chall_state.token,
            "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA",
        );
    }
}
