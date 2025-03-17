//! Async pure-Rust ACME (RFC 8555) client.

#![warn(unreachable_pub)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use std::error::Error as StdError;
use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, slice};

use async_trait::async_trait;
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use http::header::{CONTENT_TYPE, LOCATION};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
#[cfg(feature = "hyper-rustls")]
use hyper_util::client::legacy::Client as HyperClient;
#[cfg(feature = "hyper-rustls")]
use hyper_util::client::legacy::connect::{Connect, HttpConnector};
#[cfg(feature = "hyper-rustls")]
use hyper_util::rt::TokioExecutor;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::time::sleep;

mod types;
#[cfg(feature = "time")]
pub use types::RenewalInfo;
pub use types::{
    AccountCredentials, Authorization, AuthorizationState, AuthorizationStatus,
    CertificateIdentifier, Challenge, ChallengeType, Error, Identifier, LetsEncrypt, NewAccount,
    NewOrder, OrderState, OrderStatus, Problem, RevocationReason, RevocationRequest, ZeroSsl,
};
use types::{
    DirectoryUrls, Empty, FinalizeRequest, Header, JoseJson, Jwk, KeyOrKeyId, NewAccountPayload,
    Signer, SigningAlgorithm,
};

/// An ACME order as described in RFC 8555 (section 7.1.3)
///
/// An order is created from an [`Account`] by calling [`Account::new_order()`]. The `Order`
/// type represents the stable identity of an order, while the [`Order::state()`] method
/// gives you access to the current state of the order according to the server.
///
/// <https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3>
pub struct Order {
    account: Arc<AccountInner>,
    nonce: Option<String>,
    url: String,
    state: OrderState,
}

impl Order {
    /// Retrieve the authorizations for this order
    ///
    /// An order will contain one authorization to complete per identifier in the order.
    /// After creating an order, you'll need to retrieve the authorizations so that
    /// you can set up a challenge response for each authorization.
    pub fn authorizations(&mut self) -> Authorizations<'_> {
        Authorizations {
            iter: self.state.authorizations.iter_mut(),
            nonce: &mut self.nonce,
            account: &self.account,
        }
    }

    /// Request a certificate from the given Certificate Signing Request (CSR)
    ///
    /// Creating a CSR is outside of the scope of instant-acme. Make sure you pass in a
    /// DER representation of the CSR in `csr_der`. Call `certificate()` to retrieve the
    /// certificate chain once the order is in the appropriate state.
    pub async fn finalize(&mut self, csr_der: &[u8]) -> Result<(), Error> {
        let rsp = self
            .account
            .post(
                Some(&FinalizeRequest::new(csr_der)),
                self.nonce.take(),
                &self.state.finalize,
            )
            .await?;

        self.nonce = nonce_from_response(&rsp);
        self.state = Problem::check::<OrderState>(rsp).await?;
        Ok(())
    }

    /// Get the certificate for this order
    ///
    /// If the cached order state is in `ready` or `processing` state, this will poll the server
    /// for the latest state. If the order is still in `processing` state after that, this will
    /// return `Ok(None)`. If the order is in `valid` state, this will attempt to retrieve
    /// the certificate from the server and return it as a `String`. If the order contains
    /// an error or ends up in any state other than `valid` or `processing`, return an error.
    pub async fn certificate(&mut self) -> Result<Option<String>, Error> {
        if matches!(self.state.status, OrderStatus::Processing) {
            let rsp = self
                .account
                .post(None::<&Empty>, self.nonce.take(), &self.url)
                .await?;
            self.nonce = nonce_from_response(&rsp);
            self.state = Problem::check::<OrderState>(rsp).await?;
        }

        if let Some(error) = &self.state.error {
            return Err(Error::Api(error.clone()));
        } else if self.state.status == OrderStatus::Processing {
            return Ok(None);
        } else if self.state.status != OrderStatus::Valid {
            return Err(Error::Str("invalid order state"));
        }

        let cert_url = match &self.state.certificate {
            Some(cert_url) => cert_url,
            None => return Err(Error::Str("no certificate URL found")),
        };

        let rsp = self
            .account
            .post(None::<&Empty>, self.nonce.take(), cert_url)
            .await?;

        self.nonce = nonce_from_response(&rsp);
        let body = Problem::from_response(rsp).await?;
        Ok(Some(
            String::from_utf8(body.to_vec())
                .map_err(|_| "unable to decode certificate as UTF-8")?,
        ))
    }

    /// Poll the order with exponential backoff until in a final state
    ///
    /// Refresh the order state from the server for `tries` times, waiting `delay` before the
    /// first attempt and increasing the delay by a factor of 2 for each subsequent attempt.
    ///
    /// Yields the [`OrderStatus`] immediately if `Ready` or `Invalid`, or after `tries` attempts.
    ///
    /// (Empirically, we've had good results with 5 tries and an initial delay of 250ms.)
    pub async fn poll(&mut self, mut tries: u8, mut delay: Duration) -> Result<OrderStatus, Error> {
        loop {
            sleep(delay).await;
            let state = self.refresh().await?;
            if let OrderStatus::Ready | OrderStatus::Invalid = state.status {
                return Ok(state.status);
            } else if tries <= 1 {
                return Ok(state.status);
            }

            delay *= 2;
            tries -= 1;
        }
    }

    /// Refresh the current state of the order
    pub async fn refresh(&mut self) -> Result<&OrderState, Error> {
        let rsp = self
            .account
            .post(None::<&Empty>, self.nonce.take(), &self.url)
            .await?;

        self.nonce = nonce_from_response(&rsp);
        self.state = Problem::check::<OrderState>(rsp).await?;
        Ok(&self.state)
    }

    /// Extract the URL and last known state from the `Order`
    pub fn into_parts(self) -> (String, OrderState) {
        (self.url, self.state)
    }

    /// Get the last known state of the order
    ///
    /// Call `refresh()` to get the latest state from the server.
    pub fn state(&mut self) -> &OrderState {
        &self.state
    }

    /// Get the URL of the order
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// An stream-like interface that yields an [`Order`]'s authoritations
///
/// Call [`next()`] to get the next authorization in the order. If the order state
/// does not yet contain the state of the authorization, it will be fetched from the server.
///
/// [`next()`]: Authorizations::next()
pub struct Authorizations<'a> {
    iter: slice::IterMut<'a, Authorization>,
    nonce: &'a mut Option<String>,
    account: &'a AccountInner,
}

impl Authorizations<'_> {
    /// Yield the next [`AuthorizationHandle`], fetching its state if we don't have it yet.
    pub async fn next(&mut self) -> Option<Result<AuthorizationHandle<'_>, Error>> {
        let authz = self.iter.next()?;
        if authz.state.is_none() {
            match self.account.get(self.nonce, &authz.url).await {
                Ok(state) => authz.state = Some(state),
                Err(e) => return Some(Err(e)),
            }
        }

        Some(Ok(AuthorizationHandle {
            // The `unwrap()` here is safe: the code above will either set it to `Some` or yield
            // an error to the caller if it was `None` upon entering this method. I attempted to
            // use `Option::insert()` which did not pass the borrow checker for reasons that I
            // think have to do with the let scope extension that got fixed for 2024 edition.
            // For now, our MSRV does not allow the use of the new edition.
            state: authz.state.as_mut().unwrap(),
            url: &authz.url,
            nonce: self.nonce,
            account: self.account,
        }))
    }
}

/// An ACME authorization as described in RFC 8555 (section 7.1.4)
///
/// Authorizations are retrieved from an associated [`Order`] by calling
/// [`Order::authorizations()`]. This type dereferences to the underlying
/// [`AuthorizationState`] for easy access to the authorization's state.
///
/// For each authorization, you'll need to:
///
/// * Select which [`ChallengeType`] you want to complete
/// * Call [`AuthorizationHandle::challenge()`] to get a [`ChallengeHandle`]
/// * Use the `ChallengeHandle` to complete the authorization's challenge
///
/// <https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3>
pub struct AuthorizationHandle<'a> {
    state: &'a mut AuthorizationState,
    url: &'a str,
    nonce: &'a mut Option<String>,
    account: &'a AccountInner,
}

impl<'a> AuthorizationHandle<'a> {
    /// Refresh the current state of the authorization
    pub async fn refresh(&mut self) -> Result<&AuthorizationState, Error> {
        let rsp = self
            .account
            .post(None::<&Empty>, self.nonce.take(), self.url)
            .await?;

        *self.nonce = nonce_from_response(&rsp);
        *self.state = Problem::check::<AuthorizationState>(rsp).await?;
        Ok(self.state)
    }

    /// Deactivate a pending or valid authorization
    ///
    /// Returns the updated [`AuthorizationState`] if the deactivation was successful.
    /// If the authorization was not pending or valid, an error is returned.
    ///
    /// Once deactivated the authorization and associated challenges can not be updated
    /// further.
    ///
    /// This is useful when you want to cancel a pending authorization attempt you wish
    /// to abandon, or if you wish to revoke valid authorization for an identifier to
    /// force future uses of the identifier by the same ACME account to require
    /// re-verification with fresh authorizations/challenges.
    pub async fn deactivate(&mut self) -> Result<&AuthorizationState, Error> {
        if !matches!(
            self.state.status,
            AuthorizationStatus::Pending | AuthorizationStatus::Valid
        ) {
            return Err(Error::Other("authorization not pending or valid".into()));
        }

        #[derive(Serialize)]
        struct DeactivateRequest {
            status: AuthorizationStatus,
        }

        let rsp = self
            .account
            .post(
                Some(&DeactivateRequest {
                    status: AuthorizationStatus::Deactivated,
                }),
                self.nonce.take(),
                self.url,
            )
            .await?;

        *self.nonce = nonce_from_response(&rsp);
        *self.state = Problem::check::<AuthorizationState>(rsp).await?;
        match self.state.status {
            AuthorizationStatus::Deactivated => Ok(self.state),
            _ => Err(Error::Other(
                "authorization was not deactivated by ACME server".into(),
            )),
        }
    }

    /// Get a [`ChallengeHandle`] for the given `type`
    ///
    /// Yields an object to interact with the challenge for the given type, if available.
    pub fn challenge(&'a mut self, r#type: ChallengeType) -> Option<ChallengeHandle<'a>> {
        let challenge = self.state.challenges.iter().find(|c| c.r#type == r#type)?;
        Some(ChallengeHandle {
            identifier: &self.state.identifier,
            challenge,
            nonce: self.nonce,
            account: self.account,
        })
    }

    /// Get the URL of the authorization
    pub fn url(&self) -> &str {
        self.url
    }
}

impl Deref for AuthorizationHandle<'_> {
    type Target = AuthorizationState;

    fn deref(&self) -> &Self::Target {
        self.state
    }
}

/// Wrapper type for interacting with a [`Challenge`]'s state
///
/// For each challenge, you'll need to:
///
/// * Obtain the [`ChallengeHandle::key_authorization()`] for the challenge response
/// * Set up the challenge response in your infrastructure (details vary by challenge type)
/// * Call [`ChallengeHandle::set_ready()`] for that challenge after setup is complete
///
/// After the challenges have been set to ready, call [`Order::poll()`] to wait until the order is
/// ready to be finalized (or to learn if it becomes invalid). Once it is ready, call
/// [`Order::finalize()`] to get the certificate.
///
/// Dereferences to the underlying [`Challenge`] for easy access to the challenge's state.
pub struct ChallengeHandle<'a> {
    identifier: &'a Identifier,
    challenge: &'a Challenge,
    nonce: &'a mut Option<String>,
    account: &'a AccountInner,
}

impl ChallengeHandle<'_> {
    /// Notify the server that the given challenge is ready to be completed
    pub async fn set_ready(&mut self) -> Result<(), Error> {
        let rsp = self
            .account
            .post(Some(&Empty {}), self.nonce.take(), &self.challenge.url)
            .await?;

        *self.nonce = nonce_from_response(&rsp);
        let _ = Problem::check::<Challenge>(rsp).await?;
        Ok(())
    }

    /// Create a [`KeyAuthorization`] for this challenge
    ///
    /// Combines a challenge's token with the thumbprint of the account's public key to compute
    /// the challenge's `KeyAuthorization`. The `KeyAuthorization` must be used to provision the
    /// expected challenge response based on the challenge type in use.
    pub fn key_authorization(&self) -> KeyAuthorization {
        KeyAuthorization::new(self.challenge, &self.account.key)
    }

    /// The identifier for this challenge's authorization
    pub fn identifier(&self) -> &Identifier {
        self.identifier
    }
}

impl Deref for ChallengeHandle<'_> {
    type Target = Challenge;

    fn deref(&self) -> &Self::Target {
        self.challenge
    }
}

/// An ACME account as described in RFC 8555 (section 7.1.2)
///
/// Create an [`Account`] with [`Account::create()`] or restore it from serialized data
/// by passing deserialized [`AccountCredentials`] to [`Account::from_credentials()`].
///
/// Alternatively, you can load an account using the private key using [`Account::load()`].
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
        directory_url: &str,
        http: Box<dyn HttpClient>,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: Arc::new(AccountInner {
                id,
                key: Key::from_pkcs8_der(key_pkcs8_der)?,
                client: Client::new(directory_url, http).await?,
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
        server_url: &str,
        external_account: Option<&ExternalAccountKey>,
    ) -> Result<(Account, AccountCredentials), Error> {
        Self::create_inner(
            account,
            Key::generate()?,
            external_account,
            Client::new(server_url, Box::new(DefaultClient::try_new()?)).await?,
            server_url,
        )
        .await
    }

    /// Create a new account with a custom HTTP client
    ///
    /// The returned [`AccountCredentials`] can be serialized and stored for later use.
    /// Use [`Account::from_credentials()`] to restore the account from the credentials.
    pub async fn create_with_http(
        account: &NewAccount<'_>,
        server_url: &str,
        external_account: Option<&ExternalAccountKey>,
        http: Box<dyn HttpClient>,
    ) -> Result<(Account, AccountCredentials), Error> {
        Self::create_inner(
            account,
            Key::generate()?,
            external_account,
            Client::new(server_url, http).await?,
            server_url,
        )
        .await
    }

    /// Load a new account by private key, with a default or custom HTTP client
    ///
    /// https://www.rfc-editor.org/rfc/rfc8555#section-7.3.1
    ///
    /// The returned [`AccountCredentials`] can be serialized and stored for later use.
    /// Use [`Account::from_credentials()`] to restore the account from the credentials.
    pub async fn load(
        private_key_pkcs8_der: &[u8],
        server_url: &str,
        http: Option<Box<dyn HttpClient>>,
    ) -> Result<(Account, AccountCredentials), Error> {
        let client = match http {
            Some(http) => Client::new(server_url, http).await?,
            None => Client::new(server_url, Box::new(DefaultClient::try_new()?)).await?,
        };

        let key = Key::from_pkcs8_der(private_key_pkcs8_der)?;
        let pkcs8 = key.to_pkcs8_der()?;
        let ignored_account = NewAccount {
            only_return_existing: true,
            contact: &[],
            terms_of_service_agreed: true,
        };

        Self::create_inner(
            &ignored_account, // This field is ignored as per rfc8555 7.3.1
            (key, pkcs8),
            None,             // This field is ignored as per rfc8555 7.3.1
            client,
            server_url,
        )
        .await
    }

    async fn create_inner(
        account: &NewAccount<'_>,
        (key, key_pkcs8): (Key, crypto::pkcs8::Document),
        external_account: Option<&ExternalAccountKey>,
        client: Client,
        server_url: &str,
    ) -> Result<(Account, AccountCredentials), Error> {
        let payload = NewAccountPayload {
            new_account: account,
            external_account_binding: external_account
                .map(|eak| {
                    JoseJson::new(
                        Some(&Jwk::new(&key.inner)),
                        eak.header(None, &client.urls.new_account),
                        eak,
                    )
                })
                .transpose()?,
        };

        let rsp = client
            .post(Some(&payload), None, &key, &client.urls.new_account)
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
            directory: Some(server_url.to_owned()),
            // We support deserializing URLs for compatibility with versions pre 0.4,
            // but we prefer to get fresh URLs from the `server_url` for newer credentials.
            urls: None,
        };

        let account = AccountInner {
            client,
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
        if order.replaces.is_some() && self.inner.client.urls.renewal_info.is_none() {
            return Err(Error::Unsupported("ACME renewal information (ARI)"));
        }

        let rsp = self
            .inner
            .post(Some(order), None, &self.inner.client.urls.new_order)
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
        // In practice, Let's Encrypt staging/production are not properly reflecting this field
        // so we enforce it matches only when the server sends it.
        // TODO(@cpu): tighten this up once Let's Encrypt is fixed.
        if order.replaces.is_some() && state.replaces.is_some() && order.replaces != state.replaces
        {
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
        let revoke_url = match self.inner.client.urls.revoke_cert.as_deref() {
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
        let renewal_info_url = match self.inner.client.urls.renewal_info.as_deref() {
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

    /// Get the account ID
    pub fn id(&self) -> &str {
        &self.inner.id
    }
}

struct AccountInner {
    client: Client,
    key: Key,
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
            client: match (credentials.directory, credentials.urls) {
                (Some(server_url), _) => Client::new(&server_url, http).await?,
                (None, Some(urls)) => Client { http, urls },
                (None, None) => return Err("no server URLs found".into()),
            },
        })
    }

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

struct Client {
    http: Box<dyn HttpClient>,
    urls: DirectoryUrls,
}

impl Client {
    async fn new(server_url: &str, http: Box<dyn HttpClient>) -> Result<Self, Error> {
        let req = Request::builder()
            .uri(server_url)
            .body(Full::default())
            .expect("infallible error should not occur");
        let rsp = http.request(req).await?;
        let body = rsp.body().await.map_err(Error::Other)?;
        Ok(Client {
            http,
            urls: serde_json::from_slice(&body)?,
        })
    }

    async fn post(
        &self,
        payload: Option<&impl Serialize>,
        mut nonce: Option<String>,
        signer: &impl Signer,
        url: &str,
    ) -> Result<BytesResponse, Error> {
        let mut retries = 3;
        loop {
            let mut response = self
                .post_attempt(payload, nonce.clone(), signer, url)
                .await?;
            if response.parts.status != StatusCode::BAD_REQUEST {
                return Ok(response);
            }
            let body = response.body.into_bytes().await.map_err(Error::Other)?;
            let problem = serde_json::from_slice::<Problem>(&body)?;
            if let Some("urn:ietf:params:acme:error:badNonce") = problem.r#type.as_deref() {
                retries -= 1;
                if retries != 0 {
                    // Retrieve the new nonce. If it isn't there (it
                    // should be, the spec requires it) then we will
                    // manually refresh a new one in `post_attempt`
                    // due to `nonce` being `None` but getting it from
                    // the response saves us making that request.
                    nonce = nonce_from_response(&response);
                    continue;
                }
            }

            return Ok(BytesResponse {
                parts: response.parts,
                body: Box::new(body),
            });
        }
    }

    async fn post_attempt(
        &self,
        payload: Option<&impl Serialize>,
        nonce: Option<String>,
        signer: &impl Signer,
        url: &str,
    ) -> Result<BytesResponse, Error> {
        let nonce = self.nonce(nonce).await?;
        let body = JoseJson::new(payload, signer.header(Some(&nonce), url), signer)?;
        let request = Request::builder()
            .method(Method::POST)
            .uri(url)
            .header(CONTENT_TYPE, JOSE_JSON)
            .body(Full::from(serde_json::to_vec(&body)?))?;

        self.http.request(request).await
    }

    async fn nonce(&self, nonce: Option<String>) -> Result<String, Error> {
        if let Some(nonce) = nonce {
            return Ok(nonce);
        }

        let request = Request::builder()
            .method(Method::HEAD)
            .uri(&self.urls.new_nonce)
            .body(Full::default())
            .expect("infallible error should not occur");

        let rsp = self.http.request(request).await?;
        // https://datatracker.ietf.org/doc/html/rfc8555#section-7.2
        // "The server's response MUST include a Replay-Nonce header field containing a fresh
        // nonce and SHOULD have status code 200 (OK)."
        if rsp.parts.status != StatusCode::OK {
            return Err("error response from newNonce resource".into());
        }

        match nonce_from_response(&rsp) {
            Some(nonce) => Ok(nonce),
            None => Err("no nonce found in newNonce response".into()),
        }
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("client", &"..")
            .field("urls", &self.urls)
            .finish()
    }
}

struct Key {
    rng: crypto::SystemRandom,
    signing_algorithm: SigningAlgorithm,
    inner: crypto::EcdsaKeyPair,
    thumb: String,
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

    fn to_pkcs8_der(&self) -> Result<crypto::pkcs8::Document, Error> {
        Ok(self.inner.to_pkcs8v1()?)
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

/// The response value to use for challenge responses
///
/// Refer to the methods below to see which encoding to use for your challenge type.
///
/// <https://datatracker.ietf.org/doc/html/rfc8555#section-8.1>
pub struct KeyAuthorization(String);

impl KeyAuthorization {
    fn new(challenge: &Challenge, key: &Key) -> Self {
        Self(format!("{}.{}", challenge.token, &key.thumb))
    }

    /// Get the key authorization value
    ///
    /// This can be used for HTTP-01 challenge responses.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the SHA-256 digest of the key authorization
    ///
    /// This can be used for TLS-ALPN-01 challenge responses.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc8737#section-3>
    pub fn digest(&self) -> impl AsRef<[u8]> {
        crypto::digest(&crypto::SHA256, self.0.as_bytes())
    }

    /// Get the base64-encoded SHA256 digest of the key authorization
    ///
    /// This can be used for DNS-01 challenge responses.
    pub fn dns_value(&self) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(self.digest())
    }
}

impl fmt::Debug for KeyAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KeyAuthorization").finish()
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

fn nonce_from_response(rsp: &BytesResponse) -> Option<String> {
    rsp.parts
        .headers
        .get(REPLAY_NONCE)
        .and_then(|hv| String::from_utf8(hv.as_ref().to_vec()).ok())
}

#[cfg(feature = "hyper-rustls")]
struct DefaultClient(HyperClient<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>);

#[cfg(feature = "hyper-rustls")]
impl DefaultClient {
    fn try_new() -> Result<Self, Error> {
        Ok(Self(
            HyperClient::builder(TokioExecutor::new()).build(
                hyper_rustls::HttpsConnectorBuilder::new()
                    .with_native_roots()
                    .map_err(|e| Error::Other(Box::new(e)))?
                    .https_only()
                    .enable_http1()
                    .enable_http2()
                    .build(),
            ),
        ))
    }
}

#[cfg(feature = "hyper-rustls")]
impl HttpClient for DefaultClient {
    fn request(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let fut = self.0.request(req);
        Box::pin(async move {
            match fut.await {
                Ok(rsp) => Ok(BytesResponse::from(rsp)),
                Err(e) => Err(e.into()),
            }
        })
    }
}

/// A HTTP client abstraction
pub trait HttpClient: Send + Sync + 'static {
    /// Send the given request and return the response
    fn request(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>>;
}

#[cfg(feature = "hyper-rustls")]
impl<C: Connect + Clone + Send + Sync + 'static> HttpClient for HyperClient<C, Full<Bytes>> {
    fn request(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let fut = self.request(req);
        Box::pin(async move {
            match fut.await {
                Ok(rsp) => Ok(BytesResponse::from(rsp)),
                Err(e) => Err(e.into()),
            }
        })
    }
}

/// Response with object safe body type
pub struct BytesResponse {
    /// Response status and header
    pub parts: http::response::Parts,
    /// Response body
    pub body: Box<dyn BytesBody>,
}

impl BytesResponse {
    pub(crate) async fn body(mut self) -> Result<Bytes, Box<dyn StdError + Send + Sync + 'static>> {
        self.body.into_bytes().await
    }
}

impl<B> From<Response<B>> for BytesResponse
where
    B: http_body::Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn StdError + Send + Sync + 'static>>,
{
    fn from(rsp: Response<B>) -> Self {
        let (parts, body) = rsp.into_parts();
        Self {
            parts,
            body: Box::new(BodyWrapper { inner: Some(body) }),
        }
    }
}

struct BodyWrapper<B> {
    inner: Option<B>,
}

#[async_trait]
impl<B> BytesBody for BodyWrapper<B>
where
    B: http_body::Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn StdError + Send + Sync + 'static>>,
{
    async fn into_bytes(&mut self) -> Result<Bytes, Box<dyn StdError + Send + Sync + 'static>> {
        let Some(body) = self.inner.take() else {
            return Ok(Bytes::new());
        };

        match body.collect().await {
            Ok(body) => Ok(body.to_bytes()),
            Err(e) => Err(e.into()),
        }
    }
}

#[async_trait]
impl BytesBody for Bytes {
    async fn into_bytes(&mut self) -> Result<Bytes, Box<dyn StdError + Send + Sync + 'static>> {
        Ok(self.to_owned())
    }
}

/// Object safe body trait
#[async_trait]
pub trait BytesBody: Send {
    /// Convert the body into [`Bytes`]
    ///
    /// This consumes the body. The behavior for calling this method multiple times is undefined.
    #[allow(clippy::wrong_self_convention)] // async_trait doesn't support taking `self`
    async fn into_bytes(&mut self) -> Result<Bytes, Box<dyn StdError + Send + Sync + 'static>>;
}

mod crypto {
    #[cfg(feature = "aws-lc-rs")]
    pub(crate) use aws_lc_rs as ring_like;
    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    pub(crate) use ring as ring_like;

    pub(crate) use ring_like::digest::{Digest, SHA256, digest};
    pub(crate) use ring_like::error::{KeyRejected, Unspecified};
    pub(crate) use ring_like::rand::SystemRandom;
    pub(crate) use ring_like::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
    pub(crate) use ring_like::signature::{KeyPair, Signature};
    pub(crate) use ring_like::{hmac, pkcs8};

    #[cfg(feature = "aws-lc-rs")]
    pub(crate) fn p256_key_pair_from_pkcs8(
        pkcs8: &[u8],
        _: &SystemRandom,
    ) -> Result<EcdsaKeyPair, KeyRejected> {
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8)
    }

    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    pub(crate) fn p256_key_pair_from_pkcs8(
        pkcs8: &[u8],
        rng: &SystemRandom,
    ) -> Result<EcdsaKeyPair, KeyRejected> {
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, rng)
    }
}

const JOSE_JSON: &str = "application/jose+json";
const REPLAY_NONCE: &str = "Replay-Nonce";

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deserialize_old_credentials() -> Result<(), Error> {
        const CREDENTIALS: &str = r#"{"id":"id","key_pkcs8":"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJVWC_QzOTCS5vtsJp2IG-UDc8cdDfeoKtxSZxaznM-mhRANCAAQenCPoGgPFTdPJ7VLLKt56RxPlYT1wNXnHc54PEyBg3LxKaH0-sJkX0mL8LyPEdsfL_Oz4TxHkWLJGrXVtNhfH","urls":{"newNonce":"new-nonce","newAccount":"new-acct","newOrder":"new-order", "revokeCert": "revoke-cert"}}"#;
        Account::from_credentials(serde_json::from_str::<AccountCredentials>(CREDENTIALS)?).await?;
        Ok(())
    }

    #[tokio::test]
    async fn deserialize_new_credentials() -> Result<(), Error> {
        const CREDENTIALS: &str = r#"{"id":"id","key_pkcs8":"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJVWC_QzOTCS5vtsJp2IG-UDc8cdDfeoKtxSZxaznM-mhRANCAAQenCPoGgPFTdPJ7VLLKt56RxPlYT1wNXnHc54PEyBg3LxKaH0-sJkX0mL8LyPEdsfL_Oz4TxHkWLJGrXVtNhfH","directory":"https://acme-staging-v02.api.letsencrypt.org/directory"}"#;
        Account::from_credentials(serde_json::from_str::<AccountCredentials>(CREDENTIALS)?).await?;
        Ok(())
    }
}
