//! ACME challenges and challenge type specific handling

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::account::{AccountInner, Key};
use crate::nonce_from_response;
use crate::types::{
    AuthorizationState, AuthorizedIdentifier, Empty, Error, Identifier, Meta, Problem,
};

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
    /// State for a draft-ietf-acme-dns-persist-03 challenge
    ///
    /// Note: Persistent DNS challenge support is experimental
    #[serde(rename = "dns-persist-01")]
    DnsPersist01(dns_persist01::Challenge),
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

        let (challenge, data) = authz.challenges.iter().find_map(|c| {
            let data = T::from_state(&c.state)?;
            T::is_well_formed(data, account.meta()).then_some((c, data))
        })?;
        Some(Self {
            state: ChallengeHandleState {
                identifier: authz.identifier(),
                subdomain_auth_allowed: authz.subdomain_auth_allowed,
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
    subdomain_auth_allowed: bool,
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

    /// Whether this challenge type's state is well-formed for the given directory metadata
    fn is_well_formed(_state: &Self, _meta: &Meta) -> bool {
        true
    }
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

pub mod dns_persist01 {
    //! Support for draft-ietf-acme-dns-persist dns-persist-01 challenges
    //!
    //! This challenge proves control over a domain or IP address using a persistent
    //! DNS TXT record. Because the record is derived from the account, domain, and CA
    //! instead of a per-challenge token, it can be pre-provisioned and reused.
    //!
    //! See <https://datatracker.ietf.org/doc/html/draft-ietf-acme-dns-persist-03>
    //!
    //! Note: persistent DNS challenge support is experimental and tracks draft -03.
    //!
    //! Draft -01 style challenges, which spell the challenge field
    //! `issuer-domain-names` and use the raw account URL when the directory does
    //! not advertise `accountHashPrefix`, are also accepted. Google Trust
    //! Services currently serves that older dialect.
    //!
    //! # Pre-provisioning
    //!
    //! A record can be created without an order once the account exists:
    //!
    //! ```no_run
    //! # use instant_acme::{Account, Error, Identifier};
    //! # fn example(account: &Account) -> Result<(), Error> {
    //! let identifier = Identifier::Dns("example.com".to_owned());
    //! let response = account.dns_persist_response(&identifier)?;
    //! println!("{} IN TXT {}", response.host(), response.rdata());
    //! # Ok(())
    //! # }
    //! ```
    //!
    //! # Fulfilling an authorization
    //!
    //! ```no_run
    //! # use instant_acme::{AuthorizationHandle, Error};
    //! # async fn example(authz: &mut AuthorizationHandle<'_>) -> Result<(), Error> {
    //! if let Some(mut challenge) = authz.dns_persist01() {
    //!     let response = challenge.response()?;
    //!     // Provision `response.host()` and `response.rdata()` first.
    //!     challenge.set_ready().await?;
    //! }
    //! # Ok(())
    //! # }
    //! ```

    use std::net::{Ipv4Addr, Ipv6Addr};

    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
    use serde::{Deserialize, Serialize};

    use super::{ChallengeHandle, ChallengeState, ChallengeVariant};
    use crate::account::{Account, Key};
    use crate::types::{Error, Identifier, Meta};

    struct BuildOptions<'a> {
        issuer_domain_name: &'a str,
        ancestor_domain: Option<&'a str>,
        wildcard: bool,
        subdomain_auth_allowed: bool,
        domain_omitted: bool,
    }

    /// Challenge state for a dns-persist-01 challenge
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
    #[non_exhaustive]
    pub struct Challenge {
        /// Issuer Domain Names accepted by the CA for this challenge
        ///
        /// The client must choose one of these names for the validation record.
        #[serde(rename = "issuerDomainNames", alias = "issuer-domain-names", default)]
        pub issuer_domain_names: Vec<String>,
    }

    impl ChallengeVariant for Challenge {
        fn from_state(state: &ChallengeState) -> Option<&Self> {
            match state {
                ChallengeState::DnsPersist01(data) => Some(data),
                _ => None,
            }
        }

        fn supports_identifier(identifier: &Identifier) -> bool {
            matches!(identifier, Identifier::Dns(_) | Identifier::Ip(_))
        }

        fn is_well_formed(state: &Self, meta: &Meta) -> bool {
            let names = &state.issuer_domain_names;
            if names.is_empty() || names.len() > 10 || !names.iter().all(|n| is_domain_name(n)) {
                return false;
            }

            // A usable directory baseline must appear in every challenge. An
            // unavailable (missing or nonconforming) baseline is ignored.
            let baseline_usable = !meta.issuer_domain_names.is_empty()
                && meta.issuer_domain_names.len() <= 10
                && meta
                    .issuer_domain_names
                    .iter()
                    .all(|name| is_domain_name(name));
            if baseline_usable
                && meta
                    .issuer_domain_names
                    .iter()
                    .any(|name| !names.contains(name))
            {
                return false;
            }

            // Challenge names must also be CAA identities when those are usable.
            let caa_usable = !meta.caa_identities.is_empty()
                && meta
                    .caa_identities
                    .iter()
                    .all(|caa| normalize_domain(caa).is_some_and(|caa| is_domain_name(&caa)));
            !caa_usable
                || names.iter().all(|name| {
                    meta.caa_identities
                        .iter()
                        .any(|caa| normalize_domain(caa).as_deref() == Some(name.as_str()))
                })
        }
    }

    impl ChallengeHandle<'_, Challenge> {
        /// The Issuer Domain Names accepted by the CA for this challenge
        pub fn issuer_domain_names(&self) -> &[String] {
            &self.challenge.issuer_domain_names
        }

        /// Create a [`Response`] using a directory-advertised Issuer Domain Name
        ///
        /// The first challenge name that is also advertised in the directory is used,
        /// falling back to the first challenge name if the directory has no usable
        /// baseline. Use [`Self::response_with_issuer()`] to choose a name explicitly.
        pub fn response(&self) -> Result<Response, Error> {
            let issuer = self.preferred_issuer().ok_or(Error::Str(
                "dns-persist-01 challenge has no issuer domain name",
            ))?;

            self.response_with_issuer(issuer)
        }

        fn preferred_issuer(&self) -> Option<&str> {
            self.challenge
                .issuer_domain_names
                .iter()
                .find(|name| {
                    self.state
                        .account
                        .meta()
                        .issuer_domain_names
                        .iter()
                        .any(|advertised| advertised == *name)
                })
                .or_else(|| self.challenge.issuer_domain_names.first())
                .map(String::as_str)
        }

        /// Create a [`Response`] using the given Issuer Domain Name
        ///
        /// Returns an error if `issuer_domain_name` is not offered by the challenge.
        /// Directories without a usable `accountHashPrefix` (draft -01) use the
        /// raw account URL in the record.
        pub fn response_with_issuer(&self, issuer_domain_name: &str) -> Result<Response, Error> {
            self.build_response(issuer_domain_name, None, false)
        }

        /// Create a [`Response`] that is not bound to the authorization's domain
        ///
        /// The hashed `accounturi` uses the domain-omitted `*` form, allowing the
        /// same record to be reused across domains at the cost of correlation.
        pub fn response_omitted(&self) -> Result<Response, Error> {
            let issuer = self.preferred_issuer().ok_or(Error::Str(
                "dns-persist-01 challenge has no issuer domain name",
            ))?;
            self.build_response(issuer, None, true)
        }

        /// Create a [`Response`] with an explicit Issuer Domain Name and no domain binding
        pub fn response_with_issuer_omitted(
            &self,
            issuer_domain_name: &str,
        ) -> Result<Response, Error> {
            self.build_response(issuer_domain_name, None, true)
        }

        fn build_response(
            &self,
            issuer_domain_name: &str,
            ancestor_domain: Option<&str>,
            domain_omitted: bool,
        ) -> Result<Response, Error> {
            if !self
                .challenge
                .issuer_domain_names
                .iter()
                .any(|name| name == issuer_domain_name)
            {
                return Err(Error::Str("issuer domain name not offered by challenge"));
            }

            Response::build(
                self.state.identifier.identifier,
                self.state.account.meta(),
                &self.state.account.key,
                self.state.account.id(),
                BuildOptions {
                    issuer_domain_name,
                    ancestor_domain,
                    wildcard: self.state.identifier.wildcard,
                    subdomain_auth_allowed: self.state.subdomain_auth_allowed,
                    domain_omitted,
                },
            )
        }

        /// Create a [`Response`] for a persistent record at an ancestor domain
        ///
        /// `ancestor_domain` must be a proper ancestor of this authorization's
        /// identifier. The generated record automatically includes `policy=wildcard`.
        pub fn response_at_ancestor(&self, ancestor_domain: &str) -> Result<Response, Error> {
            let issuer = self.preferred_issuer().ok_or(Error::Str(
                "dns-persist-01 challenge has no issuer domain name",
            ))?;
            self.response_with_issuer_at_ancestor(issuer, ancestor_domain)
        }

        /// Create a [`Response`] for an explicit Issuer Domain Name and ancestor domain
        ///
        /// The generated record automatically includes `policy=wildcard`.
        pub fn response_with_issuer_at_ancestor(
            &self,
            issuer_domain_name: &str,
            ancestor_domain: &str,
        ) -> Result<Response, Error> {
            self.build_response(issuer_domain_name, Some(ancestor_domain), false)
        }

        /// Notify the server that the challenge is ready for validation
        ///
        /// The response record must already have been provisioned. This validates at
        /// the authorization's own identifier.
        pub async fn set_ready(&mut self) -> Result<(), Error> {
            let resolved = validation_domain(self.state.identifier.identifier)?;
            validate_validation_domain(&resolved.record_domain, resolved.label)?;
            self.state.set_ready().await
        }

        /// Notify the server that a record at `ancestor_domain` is ready for validation
        ///
        /// The response record must already have been provisioned at the ancestor's
        /// Validation Domain Name.
        pub async fn set_ready_at_ancestor(&mut self, ancestor_domain: &str) -> Result<(), Error> {
            let identifier = self.state.identifier.identifier;
            let Identifier::Dns(_) = identifier else {
                return Err(Error::Str(
                    "dns-persist-01 ancestorDomain only applies to DNS identifiers",
                ));
            };

            let ancestor = normalize_domain(ancestor_domain)
                .ok_or(Error::Str("invalid ancestor domain name"))?;
            if ancestor != ancestor_domain {
                return Err(Error::Str(
                    "ancestor domain must be lowercase without trailing dot",
                ));
            }
            if !is_domain_name(&ancestor) || "_validation-persist".len() + 1 + ancestor.len() > 253
            {
                return Err(Error::Str(
                    "invalid ancestor domain name or validation domain name too long",
                ));
            }

            let Identifier::Dns(authorization_domain) = identifier else {
                unreachable!();
            };
            validate_ancestor(authorization_domain, &ancestor)?;

            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct AncestorDomain<'a> {
                ancestor_domain: &'a str,
            }

            self.state
                .respond(&AncestorDomain {
                    ancestor_domain: &ancestor,
                })
                .await
                .map(drop)
        }
    }

    /// Challenge response data for a dns-persist-01 challenge
    #[must_use = "the response data must be provisioned before marking the challenge ready"]
    #[derive(Debug)]
    pub struct Response {
        host: String,
        issuer_domain_name: String,
        accounturi: String,
        ancestor_domain: Option<String>,
        policy_wildcard: bool,
        persist_until: Option<u64>,
        rdata: String,
        provider: &'static crate::crypto::CryptoProvider,
        thumbprint: String,
        account_url: String,
        account_hash_prefix: Option<String>,
        record_domain: String,
        domain_omitted: bool,
    }

    impl Response {
        /// Create a pre-provisioning response using a directory-advertised Issuer Domain Name
        ///
        /// `issuer_domain_name` must be advertised in the server directory metadata
        /// when the directory advertises it. Use [`Self::new_at_ancestor()`] to
        /// validate via an ancestor record.
        ///
        /// `identifier` may be a DNS identifier with a `*.` wildcard prefix, in which
        /// case the generated record automatically includes `policy=wildcard`.
        pub fn new(
            account: &Account,
            identifier: &Identifier,
            issuer_domain_name: &str,
        ) -> Result<Self, Error> {
            if let Some(metadata) = account.dns_persist_metadata() {
                if !metadata
                    .issuer_domain_names
                    .iter()
                    .any(|name| name == issuer_domain_name)
                {
                    return Err(Error::Str("issuer domain name not advertised by directory"));
                }
            }

            Self::build(
                identifier,
                account.inner().meta(),
                &account.inner().key,
                account.inner().id(),
                BuildOptions {
                    issuer_domain_name,
                    ancestor_domain: None,
                    wildcard: false,
                    subdomain_auth_allowed: false,
                    domain_omitted: false,
                },
            )
        }

        /// Create a pre-provisioning response without domain binding
        ///
        /// The hashed `accounturi` uses the domain-omitted `*` form.
        pub fn new_omitted(
            account: &Account,
            identifier: &Identifier,
            issuer_domain_name: &str,
        ) -> Result<Self, Error> {
            if let Some(metadata) = account.dns_persist_metadata() {
                if !metadata
                    .issuer_domain_names
                    .iter()
                    .any(|name| name == issuer_domain_name)
                {
                    return Err(Error::Str("issuer domain name not advertised by directory"));
                }
            }

            Self::build(
                identifier,
                account.inner().meta(),
                &account.inner().key,
                account.inner().id(),
                BuildOptions {
                    issuer_domain_name,
                    ancestor_domain: None,
                    wildcard: false,
                    subdomain_auth_allowed: false,
                    domain_omitted: true,
                },
            )
        }

        /// Create a pre-provisioning response for a record at an ancestor domain
        ///
        /// The generated record automatically includes `policy=wildcard`.
        pub fn new_at_ancestor(
            account: &Account,
            identifier: &Identifier,
            issuer_domain_name: &str,
            ancestor_domain: &str,
        ) -> Result<Self, Error> {
            if let Some(metadata) = account.dns_persist_metadata() {
                if !metadata
                    .issuer_domain_names
                    .iter()
                    .any(|name| name == issuer_domain_name)
                {
                    return Err(Error::Str("issuer domain name not advertised by directory"));
                }
            }

            Self::build(
                identifier,
                account.inner().meta(),
                &account.inner().key,
                account.inner().id(),
                BuildOptions {
                    issuer_domain_name,
                    ancestor_domain: Some(ancestor_domain),
                    wildcard: false,
                    subdomain_auth_allowed: false,
                    domain_omitted: false,
                },
            )
        }

        fn build(
            identifier: &Identifier,
            meta: &Meta,
            key: &Key,
            account_url: &str,
            options: BuildOptions<'_>,
        ) -> Result<Self, Error> {
            let BuildOptions {
                issuer_domain_name,
                ancestor_domain,
                mut wildcard,
                subdomain_auth_allowed,
                domain_omitted,
            } = options;

            let metadata = DnsPersistMetadata::from_meta(meta);

            if !is_domain_name(issuer_domain_name) {
                return Err(Error::Str("invalid issuer domain name"));
            }

            let resolved = validation_domain(identifier)?;
            wildcard |= resolved.wildcard;
            let label = resolved.label;
            let is_dns = resolved.is_dns;

            let record_domain = if let Some(ancestor) = ancestor_domain {
                if !is_dns {
                    return Err(Error::Str(
                        "dns-persist-01 ancestorDomain only applies to DNS identifiers",
                    ));
                }
                let ancestor =
                    normalize_domain(ancestor).ok_or(Error::Str("invalid ancestor domain name"))?;
                if Some(ancestor.as_str()) != ancestor_domain {
                    return Err(Error::Str(
                        "ancestor domain must be lowercase without trailing dot",
                    ));
                }
                validate_ancestor(&resolved.record_domain, &ancestor)?;
                ancestor
            } else {
                resolved.record_domain
            };

            validate_validation_domain(&record_domain, label)?;
            let account_hash_prefix = metadata.map(|metadata| metadata.account_hash_prefix);

            let thumbprint = key.thumbprint().to_owned();
            let accounturi = compute_accounturi(
                key.provider,
                account_hash_prefix,
                if domain_omitted { "*" } else { &record_domain },
                &thumbprint,
                account_url,
            );

            let mut response = Self {
                host: format!("{label}.{record_domain}."),
                issuer_domain_name: issuer_domain_name.to_owned(),
                accounturi,
                ancestor_domain: ancestor_domain.map(str::to_owned),
                policy_wildcard: is_dns
                    && (wildcard || ancestor_domain.is_some() || subdomain_auth_allowed),
                persist_until: None,
                rdata: String::new(),
                provider: key.provider,
                thumbprint,
                account_url: account_url.to_owned(),
                account_hash_prefix: account_hash_prefix.map(str::to_owned),
                record_domain,
                domain_omitted,
            };
            response.rebuild_rdata();
            Ok(response)
        }

        fn rebuild_accounturi(&mut self) {
            self.accounturi = compute_accounturi(
                self.provider,
                self.account_hash_prefix.as_deref(),
                if self.domain_omitted {
                    "*"
                } else {
                    &self.record_domain
                },
                &self.thumbprint,
                &self.account_url,
            );
        }

        fn rebuild_rdata(&mut self) {
            let mut rdata = format!(
                "{}; accounturi={}",
                self.issuer_domain_name, self.accounturi
            );
            if self.policy_wildcard {
                rdata.push_str("; policy=wildcard");
            }
            if let Some(persist_until) = self.persist_until {
                rdata.push_str(&format!("; persistUntil={persist_until}"));
            }
            self.rdata = rdata;
        }

        /// Include `policy=wildcard` in the validation record
        ///
        /// This is already set automatically for wildcard authorizations, ancestor
        /// responses, and RFC 9444 subdomain authorizations. CAs ignore it for IP
        /// records, so it is normally unnecessary there.
        pub fn with_policy_wildcard(mut self) -> Self {
            self.policy_wildcard = true;
            self.rebuild_rdata();
            self
        }

        /// Include a `persistUntil` UNIX timestamp in the validation record
        ///
        /// Fails if `unix_timestamp` exceeds the largest value allowed by the draft
        /// (`2^63 - 1`).
        pub fn with_persist_until(mut self, unix_timestamp: u64) -> Result<Self, Error> {
            if unix_timestamp > i64::MAX as u64 {
                return Err(Error::Str(
                    "persistUntil exceeds the maximum UNIX timestamp",
                ));
            }
            self.persist_until = Some(unix_timestamp);
            self.rebuild_rdata();
            Ok(self)
        }

        /// Remove domain binding from the hashed `accounturi`
        ///
        /// The record can then be reused across domains. The hashed `accounturi` is
        /// recomputed, while `host()` remains for the authorization's own domain, so
        /// publish the record at each desired Validation Domain Name (or alias them
        /// with CNAME).
        pub fn with_domain_omitted(mut self) -> Self {
            self.domain_omitted = true;
            self.rebuild_accounturi();
            self.rebuild_rdata();
            self
        }

        /// Whether the hashed `accounturi` uses the domain-omitted form
        pub fn domain_omitted(&self) -> bool {
            self.domain_omitted
        }

        /// Fully qualified hostname for the challenge response TXT record
        ///
        /// Includes a trailing dot. For DNS identifiers the host is
        /// `_validation-persist.<domain>.`; for IP identifiers it is the reverse
        /// namespace under `_ip-validation-persist`.
        pub fn host(&self) -> &str {
            &self.host
        }

        /// The TXT record RDATA to provision for [`Self::host()`]
        ///
        /// This is a single string. Use [`Self::rdata_chunks()`] when the DNS
        /// implementation requires the 255-octet character-string limit.
        pub fn rdata(&self) -> &str {
            &self.rdata
        }

        /// Split the RDATA into character-strings of at most 255 octets
        ///
        /// Concatenating the returned chunks gives [`Self::rdata()`].
        pub fn rdata_chunks(&self) -> impl Iterator<Item = &str> {
            self.rdata.as_bytes().chunks(255).map(|chunk| {
                // The RDATA is ASCII by construction.
                std::str::from_utf8(chunk).expect("dns-persist-01 RDATA is ASCII")
            })
        }

        /// The Issuer Domain Name included in the record
        pub fn issuer_domain_name(&self) -> &str {
            &self.issuer_domain_name
        }

        /// The hashed account URI included in the record
        pub fn accounturi(&self) -> &str {
            &self.accounturi
        }

        /// The selected ancestor domain, if any
        pub fn ancestor_domain(&self) -> Option<&str> {
            self.ancestor_domain.as_deref()
        }

        /// The `persistUntil` timestamp, if set
        pub fn persist_until(&self) -> Option<u64> {
            self.persist_until
        }

        /// Whether the record includes `policy=wildcard`
        pub fn policy_wildcard(&self) -> bool {
            self.policy_wildcard
        }
    }

    /// dns-persist-01 metadata advertised by an ACME directory
    #[derive(Clone, Copy, Debug)]
    pub struct DnsPersistMetadata<'a> {
        /// Issuer Domain Names advertised for pre-provisioning
        pub issuer_domain_names: &'a [String],
        /// Prefix for account bound hashed URIs
        pub account_hash_prefix: &'a str,
    }

    impl<'a> DnsPersistMetadata<'a> {
        pub(crate) fn from_meta(meta: &'a Meta) -> Option<Self> {
            let issuer_domain_names = meta.issuer_domain_names.as_slice();
            if issuer_domain_names.is_empty()
                || issuer_domain_names.len() > 10
                || !issuer_domain_names.iter().all(|name| is_domain_name(name))
            {
                return None;
            }

            let account_hash_prefix = meta.account_hash_prefix.as_deref()?;
            if !is_valid_hash_prefix(account_hash_prefix) {
                return None;
            }

            Some(Self {
                issuer_domain_names,
                account_hash_prefix,
            })
        }
    }

    /// A handle for interacting with a dns-persist-01 challenge
    pub type Handle<'a> = ChallengeHandle<'a, Challenge>;

    struct ValidationDomain {
        record_domain: String,
        label: &'static str,
        is_dns: bool,
        wildcard: bool,
    }

    /// Resolve the record domain and validation label for an identifier
    fn validation_domain(identifier: &Identifier) -> Result<ValidationDomain, Error> {
        match identifier {
            Identifier::Dns(domain) => {
                let (domain, wildcard) = match domain.strip_prefix("*.") {
                    Some(domain) => (domain, true),
                    None => (domain.as_str(), false),
                };
                let record_domain =
                    normalize_domain(domain).ok_or(Error::Str("invalid DNS identifier"))?;
                Ok(ValidationDomain {
                    record_domain,
                    label: "_validation-persist",
                    is_dns: true,
                    wildcard,
                })
            }
            Identifier::Ip(ip) => Ok(ValidationDomain {
                record_domain: reverse_zone(ip),
                label: "_ip-validation-persist",
                is_dns: false,
                wildcard: false,
            }),
            _ => Err(Error::Str("unsupported dns-persist-01 identifier")),
        }
    }

    /// Check the complete Validation Domain Name against DNS limits
    fn validate_validation_domain(record_domain: &str, label: &str) -> Result<(), Error> {
        if !is_domain_name(record_domain)
            || !record_domain
                .split('.')
                .all(|part| (1..=63).contains(&part.len()))
            || label.len() + 1 + record_domain.len() > 253
        {
            return Err(Error::Str("validation domain name exceeds DNS limits"));
        }
        Ok(())
    }

    fn compute_accounturi(
        provider: &crate::crypto::CryptoProvider,
        account_hash_prefix: Option<&str>,
        domain: &str,
        thumbprint: &str,
        account_url: &str,
    ) -> String {
        let Some(account_hash_prefix) = account_hash_prefix else {
            // Draft -01 used the raw account URL and had no hashing prefix.
            return account_url.to_owned();
        };
        let mut preimage =
            Vec::with_capacity(1 + domain.len() + thumbprint.len() + account_url.len());
        preimage.push(domain.len() as u8);
        preimage.extend_from_slice(domain.as_bytes());
        preimage.extend_from_slice(thumbprint.as_bytes());
        preimage.extend_from_slice(account_url.as_bytes());
        format!(
            "{account_hash_prefix}sha-256/{}",
            BASE64_URL_SAFE_NO_PAD.encode(provider.sha256.hash(&preimage)),
        )
    }

    fn normalize_domain(domain: &str) -> Option<String> {
        let domain = domain.strip_suffix('.').unwrap_or(domain);
        if domain.is_empty() || !domain.is_ascii() {
            return None;
        }
        Some(domain.to_ascii_lowercase())
    }

    fn is_domain_name(domain: &str) -> bool {
        !domain.is_empty()
            && domain.len() <= 253
            && !domain.ends_with('.')
            && domain.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || byte == b'-'
                            || byte == b'_'
                    })
            })
    }

    fn is_valid_hash_prefix(prefix: &str) -> bool {
        !prefix.is_empty()
            && prefix.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'-' | b'.'
                            | b'_'
                            | b'~'
                            | b':'
                            | b'/'
                            | b'?'
                            | b'#'
                            | b'['
                            | b']'
                            | b'@'
                            | b'!'
                            | b'$'
                            | b'&'
                            | b'\''
                            | b'('
                            | b')'
                            | b'*'
                            | b'+'
                            | b','
                            | b'='
                            | b'%'
                    )
            })
    }

    fn validate_ancestor(authorization_domain: &str, ancestor: &str) -> Result<(), Error> {
        if ancestor.len() >= authorization_domain.len()
            || !authorization_domain.ends_with(ancestor)
            || authorization_domain.as_bytes()[authorization_domain.len() - ancestor.len() - 1]
                != b'.'
        {
            return Err(Error::Str(
                "ancestor domain must be a proper whole-label ancestor",
            ));
        }
        Ok(())
    }

    fn reverse_zone(ip: &std::net::IpAddr) -> String {
        match ip {
            std::net::IpAddr::V4(ip) => reverse_ipv4(*ip),
            std::net::IpAddr::V6(ip) => reverse_ipv6(*ip),
        }
    }

    fn reverse_ipv4(ip: Ipv4Addr) -> String {
        let [a, b, c, d] = ip.octets();
        format!("{d}.{c}.{b}.{a}.in-addr.arpa")
    }

    fn reverse_ipv6(ip: Ipv6Addr) -> String {
        let mut zone = String::with_capacity(72);
        for byte in ip.octets().iter().rev() {
            zone.push(char::from(HEX[(byte & 0x0f) as usize]));
            zone.push('.');
            zone.push(char::from(HEX[(byte >> 4) as usize]));
            zone.push('.');
        }
        zone.push_str("ip6.arpa");
        zone
    }

    const HEX: &[u8; 16] = b"0123456789abcdef";

    #[cfg(all(test, any(feature = "aws-lc-rs", feature = "ring")))]
    mod tests {
        use super::*;
        use crate::crypto::{CryptoProvider, SigningKey};
        use crate::types::{Jwk, JwkThumbFields, SigningAlgorithm};

        fn provider() -> &'static CryptoProvider {
            #[cfg(feature = "aws-lc-rs")]
            {
                CryptoProvider::aws_lc_rs()
            }
            #[cfg(all(not(feature = "aws-lc-rs"), feature = "ring"))]
            {
                CryptoProvider::ring()
            }
        }

        // RFC 7638 section 3.1 example key and thumbprint.
        const THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
        const MODULUS: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

        struct FakeKey {
            e: Vec<u8>,
            n: Vec<u8>,
        }

        impl SigningKey for FakeKey {
            fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, Error> {
                Ok(Vec::new())
            }

            fn as_jwk(&self) -> Jwk<'_> {
                Jwk {
                    alg: SigningAlgorithm::Es256,
                    key: JwkThumbFields::Rsa {
                        e: &self.e,
                        n: &self.n,
                    },
                    r#use: "sig",
                }
            }

            fn algorithm(&self) -> SigningAlgorithm {
                SigningAlgorithm::Es256
            }
        }

        fn example_key() -> Key {
            let e = BASE64_URL_SAFE_NO_PAD.decode("AQAB").unwrap();
            let n = BASE64_URL_SAFE_NO_PAD.decode(MODULUS).unwrap();
            let key = Key::new(Box::new(FakeKey { e, n }), provider()).unwrap();
            assert_eq!(key.thumbprint(), THUMBPRINT);
            key
        }

        fn meta() -> Meta {
            Meta {
                issuer_domain_names: vec![
                    "authority.example".to_owned(),
                    "ca.example.net".to_owned(),
                ],
                account_hash_prefix: Some("https://ca.example/account-hash/".to_owned()),
                caa_identities: vec!["authority.example".to_owned()],
                ..Meta::default()
            }
        }

        fn build(
            identifier: Identifier,
            ancestor: Option<&str>,
            wildcard: bool,
            domain_omitted: bool,
        ) -> Result<Response, Error> {
            Response::build(
                &identifier,
                &meta(),
                &example_key(),
                "https://ca.example/acct/123",
                BuildOptions {
                    issuer_domain_name: "authority.example",
                    ancestor_domain: ancestor,
                    wildcard,
                    subdomain_auth_allowed: false,
                    domain_omitted,
                },
            )
        }

        #[test]
        fn deserialize_challenge() {
            let challenge: Challenge = serde_json::from_str(
                r#"{
                  "type": "dns-persist-01",
                  "url": "https://ca.example/acme/chall/5678",
                  "status": "pending",
                  "issuerDomainNames": ["authority.example", "ca.example.net"]
                }"#,
            )
            .unwrap();

            assert_eq!(challenge.issuer_domain_names.len(), 2);
            assert_eq!(challenge.issuer_domain_names[0], "authority.example");

            let missing: Challenge = serde_json::from_str("{}").unwrap();
            assert!(missing.issuer_domain_names.is_empty());
            assert!(!Challenge::is_well_formed(&missing, &meta()));
        }

        #[test]
        fn draft01_spellings_and_raw_accounturi() {
            let challenge: Challenge = serde_json::from_str(
                r#"{
                  "type": "dns-persist-01",
                  "issuer-domain-names": ["authority.example"]
                }"#,
            )
            .unwrap();
            assert_eq!(challenge.issuer_domain_names, ["authority.example"]);

            let parsed_meta: Meta = serde_json::from_str(
                r#"{
                  "issuer-domain-names": ["authority.example"],
                  "account-hash-prefix": "https://ca.example/account-hash/"
                }"#,
            )
            .unwrap();
            assert_eq!(
                parsed_meta.account_hash_prefix.as_deref(),
                Some("https://ca.example/account-hash/")
            );

            // Without an accountHashPrefix, draft -01 uses the raw account URL.
            let draft01_meta = Meta {
                account_hash_prefix: None,
                ..meta()
            };
            let response = Response::build(
                &Identifier::Dns("example.com".to_owned()),
                &draft01_meta,
                &example_key(),
                "https://ca.example/acct/123",
                BuildOptions {
                    issuer_domain_name: "authority.example",
                    ancestor_domain: None,
                    wildcard: false,
                    subdomain_auth_allowed: false,
                    domain_omitted: false,
                },
            )
            .unwrap();

            assert_eq!(response.accounturi(), "https://ca.example/acct/123");
            assert_eq!(
                response.rdata(),
                "authority.example; accounturi=https://ca.example/acct/123"
            );
        }

        #[test]
        fn challenge_malformed() {
            let mk = |names: Vec<String>| Challenge {
                issuer_domain_names: names,
            };
            let meta = meta();

            assert!(!Challenge::is_well_formed(&mk(Vec::new()), &meta));
            assert!(!Challenge::is_well_formed(
                &mk((0..11).map(|i| format!("ca{i}.example")).collect()),
                &meta
            ));
            assert!(!Challenge::is_well_formed(
                &mk(vec!["UPPER.example".to_owned()]),
                &meta
            ));
            assert!(!Challenge::is_well_formed(
                &mk(vec!["authority.example".to_owned()]),
                &meta
            ));

            let no_caa = Meta {
                caa_identities: Vec::new(),
                ..meta.clone()
            };
            assert!(Challenge::is_well_formed(
                &mk(vec![
                    "authority.example".to_owned(),
                    "ca.example.net".to_owned()
                ]),
                &no_caa
            ));

            // An unavailable (nonconforming) baseline is ignored.
            let bad_baseline = Meta {
                issuer_domain_names: vec!["UPPER.example".to_owned()],
                ..meta.clone()
            };
            assert!(Challenge::is_well_formed(
                &mk(vec!["authority.example".to_owned()]),
                &bad_baseline
            ));

            // An unavailable (nonconforming) caaIdentities array is ignored.
            let bad_caa = Meta {
                caa_identities: vec!["NOT A DOMAIN".to_owned()],
                ..meta
            };
            assert!(Challenge::is_well_formed(
                &mk(vec![
                    "authority.example".to_owned(),
                    "ca.example.net".to_owned()
                ]),
                &bad_caa
            ));
        }

        #[test]
        fn draft_hashed_uri_vector() {
            let response = build(
                Identifier::Dns("example.com".to_owned()),
                None,
                false,
                false,
            )
            .unwrap();

            assert_eq!(response.host(), "_validation-persist.example.com.");
            assert_eq!(
                response.rdata(),
                "authority.example; accounturi=https://ca.example/account-hash/sha-256/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw"
            );
            assert!(!response.policy_wildcard());
        }

        #[test]
        fn draft_domain_omitted_vector() {
            let response =
                build(Identifier::Dns("example.com".to_owned()), None, false, true).unwrap();

            assert_eq!(
                response.accounturi(),
                "https://ca.example/account-hash/sha-256/NpDnSwUthQK8zCgFdefYxAdAVPnygMLbs9US6oO-5ug"
            );
        }

        #[test]
        fn draft_ipv4_vector() {
            let response = build(
                Identifier::Ip("192.0.2.1".parse().unwrap()),
                None,
                false,
                false,
            )
            .unwrap();

            assert_eq!(
                response.host(),
                "_ip-validation-persist.1.2.0.192.in-addr.arpa."
            );
            assert!(
                response
                    .rdata()
                    .ends_with("/sha-256/CnwSwHOHJbE-X_FSkydPTw6dGMovluSdRsY3_tmA-0E")
            );
        }

        #[test]
        fn draft_ipv6_vector() {
            let response = build(
                Identifier::Ip("2001:db8::1".parse().unwrap()),
                None,
                false,
                false,
            )
            .unwrap();

            assert_eq!(
                response.host(),
                "_ip-validation-persist.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
            );
            assert!(
                response
                    .rdata()
                    .ends_with("/sha-256/9RLd7iwi0v30KV01dsPwGvSBucGEYgsJhDNCxk8Nb9g")
            );
        }

        #[test]
        fn wildcard_and_persist_until() {
            let response =
                build(Identifier::Dns("example.com".to_owned()), None, true, false).unwrap();
            assert!(response.policy_wildcard());
            assert!(response.rdata().ends_with("; policy=wildcard"));

            let response = response.with_persist_until(1_924_992_000).unwrap();
            assert!(response.rdata().ends_with("; persistUntil=1924992000"));

            assert!(response.with_persist_until(u64::MAX).is_err());
        }

        #[test]
        fn wildcard_identifier_prefix() {
            let response = build(
                Identifier::Dns("*.example.com".to_owned()),
                None,
                false,
                false,
            )
            .unwrap();

            assert_eq!(response.host(), "_validation-persist.example.com.");
            assert!(response.policy_wildcard());
            assert!(response.rdata().ends_with(
                "/sha-256/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw; policy=wildcard"
            ));
        }

        #[test]
        fn domain_normalization() {
            let upper = build(
                Identifier::Dns("XN--FA-HIA.example.".to_owned()),
                None,
                false,
                false,
            )
            .unwrap();
            let lower = build(
                Identifier::Dns("xn--fa-hia.example".to_owned()),
                None,
                false,
                false,
            )
            .unwrap();

            assert_eq!(upper.host(), "_validation-persist.xn--fa-hia.example.");
            assert_eq!(upper.rdata(), lower.rdata());
        }

        #[test]
        fn validation_domain_too_long() {
            let mut labels = Vec::new();
            while labels.join(".").len() < 240 {
                labels.push("a".repeat(60));
            }
            let domain = labels.join(".");
            assert!(
                build(Identifier::Dns(domain.clone()), None, false, false).is_err(),
                "{domain}"
            );
            // An ancestor can shorten the Validation Domain Name enough to fit.
            assert!(
                build(Identifier::Dns(domain), Some("example.com"), false, false).is_err(),
                "ancestor must be part of the identifier"
            );
        }

        #[test]
        fn ancestor_record() {
            let response = build(
                Identifier::Dns("dept.example.com".to_owned()),
                Some("example.com"),
                false,
                false,
            )
            .unwrap();

            assert_eq!(response.host(), "_validation-persist.example.com.");
            assert_eq!(response.ancestor_domain(), Some("example.com"));
            assert!(response.policy_wildcard());
            assert!(response.rdata().ends_with(
                "/sha-256/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw; policy=wildcard"
            ));
        }

        #[test]
        fn invalid_ancestor() {
            for ancestor in [
                "dept.example.com",
                "ample.com",
                "EXAMPLE.com",
                "example.com.",
            ] {
                assert!(
                    build(
                        Identifier::Dns("dept.example.com".to_owned()),
                        Some(ancestor),
                        false,
                        false
                    )
                    .is_err(),
                    "{ancestor}"
                );
            }

            assert!(
                build(
                    Identifier::Ip("192.0.2.1".parse().unwrap()),
                    Some("example.com"),
                    false,
                    false
                )
                .is_err()
            );
        }

        #[test]
        fn rdata_chunks() {
            let mut meta = meta();
            meta.account_hash_prefix = Some(format!("https://ca.example/{}/", "x".repeat(300)));
            let response = Response::build(
                &Identifier::Dns("example.com".to_owned()),
                &meta,
                &example_key(),
                "https://ca.example/acct/123",
                BuildOptions {
                    issuer_domain_name: "authority.example",
                    ancestor_domain: None,
                    wildcard: false,
                    subdomain_auth_allowed: false,
                    domain_omitted: false,
                },
            )
            .unwrap();

            let chunks: Vec<_> = response.rdata_chunks().collect();
            assert!(chunks.len() > 1);
            assert!(chunks.iter().all(|chunk| chunk.len() <= 255));
            assert_eq!(chunks.concat(), response.rdata());
        }

        #[test]
        fn invalid_hash_prefix_falls_back_to_raw_accounturi() {
            for prefix in ["", "https://ca.example/a;b/", "https://ca.example/a\\b/"] {
                let mut meta = meta();
                meta.account_hash_prefix = Some(prefix.to_owned());
                let response = Response::build(
                    &Identifier::Dns("example.com".to_owned()),
                    &meta,
                    &example_key(),
                    "https://ca.example/acct/123",
                    BuildOptions {
                        issuer_domain_name: "authority.example",
                        ancestor_domain: None,
                        wildcard: false,
                        subdomain_auth_allowed: false,
                        domain_omitted: false,
                    },
                )
                .unwrap();
                assert_eq!(
                    response.accounturi(),
                    "https://ca.example/acct/123",
                    "{prefix:?}"
                );
            }
        }

        #[test]
        fn metadata_validation() {
            assert!(DnsPersistMetadata::from_meta(&meta()).is_some());

            let mut invalid = meta();
            invalid.account_hash_prefix = None;
            assert!(DnsPersistMetadata::from_meta(&invalid).is_none());

            let mut invalid = meta();
            invalid.issuer_domain_names.clear();
            assert!(DnsPersistMetadata::from_meta(&invalid).is_none());

            let mut invalid = meta();
            invalid.issuer_domain_names = (0..11).map(|i| format!("ca{i}.example")).collect();
            assert!(DnsPersistMetadata::from_meta(&invalid).is_none());
        }
    }
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
