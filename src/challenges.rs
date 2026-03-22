//! ACME challenges and challenge type specific handling

use std::borrow::Cow;

use serde::Deserialize;

use crate::types::Problem;

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

impl ChallengeState {
    /// Get the token associated with this challenge (if applicable)
    ///
    /// DNS-01, HTTP-01 and TLS-ALPN-01 challenge types offer a token. Other challenge types
    /// do not rely on RFC 8555 key authorizations and will return `None`, expecting the
    /// challenge to be satisfied with another method specific to its type.
    pub fn token(&self) -> Option<&str> {
        Some(match self {
            Self::Http01(http01::Challenge { token })
            | Self::Dns01(dns01::Challenge { token })
            | Self::TlsAlpn01(tls_alpn01::Challenge { token }) => token,
            Self::DeviceAttest01(_) | Self::Unknown => return None,
        })
    }

    /// Get the challenge type associated with this challenge state
    pub fn r#type(&self) -> ChallengeType {
        match self {
            Self::Http01(_) => ChallengeType::Http01,
            Self::Dns01(_) => ChallengeType::Dns01,
            Self::TlsAlpn01(_) => ChallengeType::TlsAlpn01,
            Self::DeviceAttest01(_) => ChallengeType::DeviceAttest01,
            Self::Unknown => ChallengeType::Unknown,
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

pub mod http01 {
    //! Support for RFC 8555 http-01 challenges
    //!
    //! See <https://www.rfc-editor.org/rfc/rfc8555#section-8.3>

    use serde::Deserialize;

    /// Challenge state for an http-01 challenge
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
    #[non_exhaustive]
    pub struct Challenge {
        /// A token for constructing a key authorization to complete this challenge
        pub token: String,
    }
}

pub mod dns01 {
    //! Support for RFC 8555 dns-01 challenges
    //!
    //! See <https://www.rfc-editor.org/rfc/rfc8555#section-8.4>

    use serde::Deserialize;

    /// Challenge state for a dns-01 challenge
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
    #[non_exhaustive]
    pub struct Challenge {
        /// A token for constructing a key authorization to complete this challenge
        pub token: String,
    }
}

pub mod tls_alpn01 {
    //! Support for RFC 8737 tls-alpn-01 challenges
    //!
    //! See <https://www.rfc-editor.org/rfc/rfc8737#section-3>

    use serde::Deserialize;

    /// Challenge state for a tls-alpn-01 challenge
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
    #[non_exhaustive]
    pub struct Challenge {
        /// A token for constructing a key authorization to complete this challenge
        pub token: String,
    }
}

pub mod device_attest01 {
    //! Support for draft-ietf-acme-device-attest device-attest-01 challenges
    //!
    //! See <https://datatracker.ietf.org/doc/draft-ietf-acme-device-attest/>
    //!
    //! Note: device attestation support is experimental.

    use serde::Deserialize;

    /// Challenge state for a device-attest-01 challenge
    ///
    /// device-attest-01 challenges carry no additional type specific state.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
    #[non_exhaustive]
    pub struct Challenge {}
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
        assert_eq!(obj.state.r#type(), ChallengeType::Dns01);
        assert_eq!(obj.url, "https://example.com/acme/chall/Rg5dV14Gh1Q");
        assert_eq!(obj.status, ChallengeStatus::Pending);
        assert_eq!(
            obj.state.token(),
            Some("evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA")
        );
    }
}
