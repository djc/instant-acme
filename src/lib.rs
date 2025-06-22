//! Async pure-Rust ACME (RFC 8555) client.

#![warn(unreachable_pub)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use async_trait::async_trait;
use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
#[cfg(feature = "hyper-rustls")]
use hyper_util::client::legacy::Client as HyperClient;
#[cfg(feature = "hyper-rustls")]
use hyper_util::client::legacy::connect::{Connect, HttpConnector};
#[cfg(feature = "hyper-rustls")]
use hyper_util::rt::TokioExecutor;
use serde::Serialize;

mod account;
use account::Key;
pub use account::{Account, AccountBuilder, ExternalAccountKey};
mod order;
pub use order::{
    AuthorizationHandle, Authorizations, ChallengeHandle, Identifiers, KeyAuthorization, Order,
    RetryPolicy,
};
mod types;
#[cfg(feature = "time")]
pub use types::RenewalInfo;
pub use types::{
    AccountCredentials, Authorization, AuthorizationState, AuthorizationStatus,
    AuthorizedIdentifier, CertificateIdentifier, Challenge, ChallengeType, Error, Identifier,
    LetsEncrypt, NewAccount, NewOrder, OrderState, OrderStatus, Problem, ProfileMeta,
    RevocationReason, RevocationRequest, ZeroSsl,
};
use types::{Directory, JoseJson, Signer};

struct Client {
    http: Box<dyn HttpClient>,
    directory: Directory,
    server_url: Option<String>,
}

impl Client {
    async fn new(server_url: String, http: Box<dyn HttpClient>) -> Result<Self, Error> {
        let req = Request::builder()
            .uri(&server_url)
            .body(Full::default())
            .expect("infallible error should not occur");
        let rsp = http.request(req).await?;
        let body = rsp.body().await.map_err(Error::Other)?;
        Ok(Client {
            http,
            directory: serde_json::from_slice(&body)?,
            server_url: Some(server_url),
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
            .uri(&self.directory.new_nonce)
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
            .field("directory", &self.directory)
            .finish()
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
                    .try_with_platform_verifier()
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
        Account::builder()?
            .from_credentials(serde_json::from_str::<AccountCredentials>(CREDENTIALS)?)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn deserialize_new_credentials() -> Result<(), Error> {
        const CREDENTIALS: &str = r#"{"id":"id","key_pkcs8":"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJVWC_QzOTCS5vtsJp2IG-UDc8cdDfeoKtxSZxaznM-mhRANCAAQenCPoGgPFTdPJ7VLLKt56RxPlYT1wNXnHc54PEyBg3LxKaH0-sJkX0mL8LyPEdsfL_Oz4TxHkWLJGrXVtNhfH","directory":"https://acme-staging-v02.api.letsencrypt.org/directory"}"#;
        Account::builder()?
            .from_credentials(serde_json::from_str::<AccountCredentials>(CREDENTIALS)?)
            .await?;
        Ok(())
    }
}
