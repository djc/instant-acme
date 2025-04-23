use std::sync::Arc;

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
use http::header::LOCATION;
#[cfg(feature = "time")]
use http::{Method, Request};
#[cfg(feature = "time")]
use http_body_util::Full;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[cfg(feature = "hyper-rustls")]
use crate::DefaultClient;
use crate::order::Order;
use crate::types::{
    AccountCredentials, AuthorizationStatus, Empty, Header, JoseJson, Jwk, KeyOrKeyId, NewAccount,
    NewAccountPayload, NewOrder, OrderState, Problem, ProfileMeta, RevocationRequest, Signer,
    SigningAlgorithm,
};
#[cfg(feature = "time")]
use crate::types::{CertificateIdentifier, RenewalInfo};
use crate::{BytesResponse, Client, Error, HttpClient, crypto, nonce_from_response};

/// An ACME account as described in RFC 8555 (section 7.1.2)
///
/// Create an [`Account`] with [`Account::create()`] or restore it from serialized data
/// by passing deserialized [`AccountCredentials`] to [`Account::from_credentials()`].
///
/// The [`Account`] type is cheap to clone.
///
/// <https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2>
#[derive(Clone)]
pub struct Account {
    inner: Arc<AccountInner>,
}

impl Account {
    /// Restore an existing account from the given credentials
    ///
    /// The [`AccountCredentials`] type is opaque, but supports deserialization.
    #[cfg(feature = "hyper-rustls")]
    pub async fn from_credentials(credentials: AccountCredentials) -> Result<Self, Error> {
        Ok(Self {
            inner: Arc::new(
                AccountInner::from_credentials(credentials, Box::new(DefaultClient::try_new()?))
                    .await?,
            ),
        })
    }

    /// Restore an existing account from the given credentials and HTTP client
    ///
    /// The [`AccountCredentials`] type is opaque, but supports deserialization.
    pub async fn from_credentials_and_http(
        credentials: AccountCredentials,
        http: Box<dyn HttpClient>,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: Arc::new(AccountInner::from_credentials(credentials, http).await?),
        })
    }

    /// Restore an existing account from the given ID, private key, server URL and HTTP client
    ///
    /// The key must be provided in DER-encoded PKCS#8. This is usually how ECDSA keys are
    /// encoded in PEM files. Use a crate like rustls-pemfile to decode from PEM to DER.
    pub async fn from_parts(
        id: String,
        key_pkcs8_der: &[u8],
        server_url: String,
        http: Box<dyn HttpClient>,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: Arc::new(AccountInner {
                id,
                key: Key::from_pkcs8_der(key_pkcs8_der)?,
                client: Arc::new(Client::new(server_url, http).await?),
            }),
        })
    }

    /// Create a new account on the `server_url` with the information in [`NewAccount`]
    ///
    /// The returned [`AccountCredentials`] can be serialized and stored for later use.
    /// Use [`Account::from_credentials()`] to restore the account from the credentials.
    #[cfg(feature = "hyper-rustls")]
    pub async fn create(
        account: &NewAccount<'_>,
        server_url: String,
        external_account: Option<&ExternalAccountKey>,
    ) -> Result<(Account, AccountCredentials), Error> {
        Self::create_inner(
            account,
            external_account,
            Client::new(server_url, Box::new(DefaultClient::try_new()?)).await?,
        )
        .await
    }

    /// Create a new account with a custom HTTP client
    ///
    /// The returned [`AccountCredentials`] can be serialized and stored for later use.
    /// Use [`Account::from_credentials()`] to restore the account from the credentials.
    pub async fn create_with_http(
        account: &NewAccount<'_>,
        server_url: String,
        external_account: Option<&ExternalAccountKey>,
        http: Box<dyn HttpClient>,
    ) -> Result<(Account, AccountCredentials), Error> {
        Self::create_inner(
            account,
            external_account,
            Client::new(server_url, http).await?,
        )
        .await
    }

    async fn create_inner(
        account: &NewAccount<'_>,
        external_account: Option<&ExternalAccountKey>,
        client: Client,
    ) -> Result<(Account, AccountCredentials), Error> {
        let (key, key_pkcs8) = Key::generate()?;
        let payload = NewAccountPayload {
            new_account: account,
            external_account_binding: external_account
                .map(|eak| {
                    JoseJson::new(
                        Some(&Jwk::new(&key.inner)),
                        eak.header(None, &client.directory.new_account),
                        eak,
                    )
                })
                .transpose()?,
        };

        let rsp = client
            .post(Some(&payload), None, &key, &client.directory.new_account)
            .await?;

        let account_url = rsp
            .parts
            .headers
            .get(LOCATION)
            .and_then(|hv| hv.to_str().ok())
            .map(|s| s.to_owned());

        // The response redirects, we don't need the body
        let _ = Problem::from_response(rsp).await?;
        let id = account_url.ok_or("failed to get account URL")?;
        let credentials = AccountCredentials {
            id: id.clone(),
            key_pkcs8: key_pkcs8.as_ref().to_vec(),
            directory: Some(client.server_url.clone().unwrap()), // New clients always have `server_url`
            // We support deserializing URLs for compatibility with versions pre 0.4,
            // but we prefer to get fresh URLs from the `server_url` for newer credentials.
            urls: None,
        };

        let account = AccountInner {
            client: Arc::new(client),
            key,
            id: id.clone(),
        };

        Ok((
            Self {
                inner: Arc::new(account),
            },
            credentials,
        ))
    }

    /// Create a new order based on the given [`NewOrder`]
    ///
    /// Returns an [`Order`] instance. Use the [`Order::state()`] method to inspect its state.
    pub async fn new_order(&self, order: &NewOrder<'_>) -> Result<Order, Error> {
        if order.replaces.is_some() && self.inner.client.directory.renewal_info.is_none() {
            return Err(Error::Unsupported("ACME renewal information (ARI)"));
        }

        let rsp = self
            .inner
            .post(Some(order), None, &self.inner.client.directory.new_order)
            .await?;

        let nonce = nonce_from_response(&rsp);
        let order_url = rsp
            .parts
            .headers
            .get(LOCATION)
            .and_then(|hv| hv.to_str().ok())
            .map(|s| s.to_owned());

        // We return errors from Problem::check before emitting an error for any further
        // issues (e.g. no order URL, missing replacement field).
        let state = Problem::check::<OrderState>(rsp).await?;

        // Per the ARI spec:
        // "If the Server accepts a new-order request with a "replaces" field, it MUST reflect
        // that field in the response and in subsequent requests for the corresponding Order
        // object."
        if order.replaces.is_some() && order.replaces != state.replaces {
            return Err(Error::Other(
                format!(
                    "replaces field mismatch: expected {expected:?}, found {found:?}",
                    expected = order.replaces,
                    found = state.replaces,
                )
                .into(),
            ));
        }

        Ok(Order {
            account: self.inner.clone(),
            nonce,
            state,
            url: order_url.ok_or("no order URL found")?,
        })
    }

    /// Fetch the order state for an existing order based on the given `url`
    ///
    /// This might fail if the given URL's order belongs to a different account.
    ///
    /// Returns an [`Order`] instance. Use the [`Order::state`] method to inspect its state.
    pub async fn order(&self, url: String) -> Result<Order, Error> {
        let rsp = self.inner.post(None::<&Empty>, None, &url).await?;
        Ok(Order {
            account: self.inner.clone(),
            nonce: nonce_from_response(&rsp),
            // Order of fields matters! We return errors from Problem::check
            // before emitting an error if there is no order url. Or the
            // simple no url error hides the causing error in `Problem::check`.
            state: Problem::check::<OrderState>(rsp).await?,
            url,
        })
    }

    /// Revokes a previously issued certificate
    pub async fn revoke<'a>(&'a self, payload: &RevocationRequest<'a>) -> Result<(), Error> {
        let revoke_url = match self.inner.client.directory.revoke_cert.as_deref() {
            Some(url) => url,
            // This happens because the current account credentials were deserialized from an
            // older version which only serialized a subset of the directory URLs. You should
            // make sure the account credentials include a `directory` field containing a
            // string with the server's directory URL.
            None => return Err("no revokeCert URL found".into()),
        };

        let rsp = self.inner.post(Some(payload), None, revoke_url).await?;
        // The body is empty if the request was successful
        let _ = Problem::from_response(rsp).await?;
        Ok(())
    }

    /// Fetch `RenewalInfo` with a suggested window for renewing an identified certificate
    ///
    /// Clients may use this information to determine when to renew a certificate. If the renewal
    /// window starts in the past, then renewal should be attempted immediately. Otherwise, a
    /// uniformly random point between the window start/end should be selected and used to
    /// schedule a renewal in the future.
    ///
    /// This is only supported by some ACME servers. If the server does not support this feature,
    /// this method will return `Error::Unsupported`.
    ///
    /// See <https://www.ietf.org/archive/id/draft-ietf-acme-ari-07.html#section-4.2-4> for more
    /// information.
    #[cfg(feature = "time")]
    pub async fn renewal_info(
        &self,
        certificate_id: &CertificateIdentifier<'_>,
    ) -> Result<RenewalInfo, Error> {
        let renewal_info_url = match self.inner.client.directory.renewal_info.as_deref() {
            Some(url) => url,
            None => return Err(Error::Unsupported("ACME renewal information (ARI)")),
        };

        // Note: unlike other ACME endpoints, the renewal info endpoint does not require a nonce
        // or any JWS authentication. It's just a Plain-Old-HTTP-GET.
        let request = Request::builder()
            .method(Method::GET)
            .uri(format!("{renewal_info_url}/{certificate_id}"))
            .body(Full::default())?;

        let rsp = self.inner.client.http.request(request).await?;
        Problem::check::<RenewalInfo>(rsp).await
    }

    /// Update the account's authentication key
    ///
    /// This is useful if you want to change the ACME account key of an existing account, e.g.
    /// to mitigate the risk of a key compromise. This method creates a new client key and changes
    /// the key associated with the existing account. `self` will be updated with the new key,
    /// and a fresh set of [`AccountCredentials`] will be returned to update stored credentials.
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.5> for more information.
    pub async fn update_key(&mut self) -> Result<AccountCredentials, Error> {
        let new_key_url = match self.inner.client.directory.key_change.as_deref() {
            Some(url) => url,
            None => return Err("Account key rollover not supported by ACME CA".into()),
        };

        #[derive(Debug, Serialize)]
        struct NewKey<'a> {
            account: &'a str,
            #[serde(rename = "oldKey")]
            old_key: Jwk,
        }

        let (new_key, new_key_pkcs8) = Key::generate()?;
        let mut header = new_key.header(Some("nonce"), new_key_url);
        header.nonce = None;
        let payload = NewKey {
            account: &self.inner.id,
            old_key: Jwk::new(&self.inner.key.inner),
        };

        let body = JoseJson::new(Some(&payload), header, &new_key)?;
        let rsp = self.inner.post(Some(&body), None, new_key_url).await?;
        let _ = Problem::from_response(rsp).await?;

        self.inner = Arc::new(AccountInner {
            client: self.inner.client.clone(),
            key: new_key,
            id: self.inner.id.clone(),
        });

        let (directory, urls) = match &self.inner.client.server_url {
            Some(server_url) => (Some(server_url.clone()), None),
            None => (None, Some(self.inner.client.directory.clone())),
        };

        Ok(AccountCredentials {
            id: self.inner.id.clone(),
            key_pkcs8: new_key_pkcs8.as_ref().to_vec(),
            directory,
            urls,
        })
    }

    /// Updates the account contacts
    ///
    /// This is useful if you want to update the contact information of an existing account
    /// on the ACME server. The contacts argument replaces existing contacts on
    /// the server. By providing an empty array the contacts are removed from the server.
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.2> for more information.
    pub async fn update_contacts<'a>(&self, contacts: &'a [&'a str]) -> Result<(), Error> {
        #[derive(Debug, Serialize)]
        struct Contacts<'a> {
            contact: &'a [&'a str],
        }

        let payload = Contacts { contact: contacts };
        let rsp = self
            .inner
            .post(Some(&payload), None, &self.inner.id)
            .await?;

        #[derive(Debug, Deserialize)]
        struct Account {
            status: AuthorizationStatus,
        }

        let response = Problem::check::<Account>(rsp).await?;
        match response.status {
            AuthorizationStatus::Valid => Ok(()),
            _ => Err("Unexpected account status after updating contact information".into()),
        }
    }

    /// Deactivate the account with the ACME server
    ///
    /// This is useful when you want to cancel an account with the ACME server
    /// because you don't intend to use it further, or because the account key was
    /// compromised.
    ///
    /// After this point no further operations can be performed with the account.
    /// Any existing orders or authorizations created with the ACME server will be
    /// invalidated.
    pub async fn deactivate(self) -> Result<(), Error> {
        #[derive(Serialize)]
        struct DeactivateRequest<'a> {
            status: &'a str,
        }

        let _ = self
            .inner
            .post(
                Some(&DeactivateRequest {
                    status: "deactivated",
                }),
                None,
                self.id(),
            )
            .await?;

        Ok(())
    }

    /// Yield the profiles supported according to the account's server directory
    pub fn profiles(&self) -> impl Iterator<Item = ProfileMeta<'_>> {
        self.inner
            .client
            .directory
            .meta
            .profiles
            .iter()
            .map(|(name, description)| ProfileMeta { name, description })
    }

    /// Get the account ID
    pub fn id(&self) -> &str {
        &self.inner.id
    }
}

pub(crate) struct AccountInner {
    client: Arc<Client>,
    pub(crate) key: Key,
    id: String,
}

impl AccountInner {
    async fn from_credentials(
        credentials: AccountCredentials,
        http: Box<dyn HttpClient>,
    ) -> Result<Self, Error> {
        Ok(Self {
            id: credentials.id,
            key: Key::from_pkcs8_der(credentials.key_pkcs8.as_ref())?,
            client: Arc::new(match (credentials.directory, credentials.urls) {
                (Some(server_url), _) => Client::new(server_url, http).await?,
                (None, Some(directory)) => Client {
                    http,
                    directory,
                    server_url: None,
                },
                (None, None) => return Err("no server URLs found".into()),
            }),
        })
    }

    pub(crate) async fn get<T: DeserializeOwned>(
        &self,
        nonce: &mut Option<String>,
        url: &str,
    ) -> Result<T, Error> {
        let rsp = self.post(None::<&Empty>, nonce.take(), url).await?;
        *nonce = nonce_from_response(&rsp);
        Problem::check(rsp).await
    }

    pub(crate) async fn post(
        &self,
        payload: Option<&impl Serialize>,
        nonce: Option<String>,
        url: &str,
    ) -> Result<BytesResponse, Error> {
        self.client.post(payload, nonce, self, url).await
    }
}

impl Signer for AccountInner {
    type Signature = <Key as Signer>::Signature;

    fn header<'n, 'u: 'n, 's: 'u>(&'s self, nonce: Option<&'n str>, url: &'u str) -> Header<'n> {
        debug_assert!(nonce.is_some());
        Header {
            alg: self.key.signing_algorithm,
            key: KeyOrKeyId::KeyId(&self.id),
            nonce,
            url,
        }
    }

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, Error> {
        self.key.sign(payload)
    }
}

pub(crate) struct Key {
    rng: crypto::SystemRandom,
    signing_algorithm: SigningAlgorithm,
    inner: crypto::EcdsaKeyPair,
    pub(crate) thumb: String,
}

impl Key {
    fn generate() -> Result<(Self, crypto::pkcs8::Document), Error> {
        let rng = crypto::SystemRandom::new();
        let pkcs8 =
            crypto::EcdsaKeyPair::generate_pkcs8(&crypto::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)?;
        Self::new(pkcs8.as_ref(), rng).map(|key| (key, pkcs8))
    }

    fn from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, Error> {
        Self::new(pkcs8_der, crypto::SystemRandom::new())
    }

    fn new(pkcs8_der: &[u8], rng: crypto::SystemRandom) -> Result<Self, Error> {
        let inner = crypto::p256_key_pair_from_pkcs8(pkcs8_der, &rng)?;
        let thumb = BASE64_URL_SAFE_NO_PAD.encode(Jwk::thumb_sha256(&inner)?);
        Ok(Self {
            rng,
            signing_algorithm: SigningAlgorithm::Es256,
            inner,
            thumb,
        })
    }
}

impl Signer for Key {
    type Signature = crypto::Signature;

    fn header<'n, 'u: 'n, 's: 'u>(&'s self, nonce: Option<&'n str>, url: &'u str) -> Header<'n> {
        debug_assert!(nonce.is_some());
        Header {
            alg: self.signing_algorithm,
            key: KeyOrKeyId::from_key(&self.inner),
            nonce,
            url,
        }
    }

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, Error> {
        Ok(self.inner.sign(&self.rng, payload)?)
    }
}

/// A HMAC key used to link account creation requests to an external account
///
/// See RFC 8555 section 7.3.4 for more information.
pub struct ExternalAccountKey {
    id: String,
    key: crypto::hmac::Key,
}

impl ExternalAccountKey {
    /// Create a new external account key
    ///
    /// Note that the `key_value` argument represents the raw key value, so if the caller holds
    /// an encoded key value (for example, using base64), decode it before passing it in.
    pub fn new(id: String, key_value: &[u8]) -> Self {
        Self {
            id,
            key: crypto::hmac::Key::new(crypto::hmac::HMAC_SHA256, key_value),
        }
    }
}

impl Signer for ExternalAccountKey {
    type Signature = crypto::hmac::Tag;

    fn header<'n, 'u: 'n, 's: 'u>(&'s self, nonce: Option<&'n str>, url: &'u str) -> Header<'n> {
        debug_assert_eq!(nonce, None);
        Header {
            alg: SigningAlgorithm::Hs256,
            key: KeyOrKeyId::KeyId(&self.id),
            nonce,
            url,
        }
    }

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, Error> {
        Ok(crypto::hmac::sign(&self.key, payload))
    }
}
