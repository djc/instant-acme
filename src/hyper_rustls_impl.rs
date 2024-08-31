use crate::*;

use hyper_util::client::legacy::connect::Connect;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};

struct DefaultClient(HyperClient<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>);

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

impl HttpClient for DefaultClient {
    fn request(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Bytes>, Error>> + Send>> {
        Box::pin(_response_future(self.0.request(req)))
    }
}

impl<C: Connect + Clone + Send + Sync + 'static> HttpClient for HyperClient<C, Full<Bytes>> {
    fn request(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Bytes>, Error>> + Send>> {
        Box::pin(_response_future(self.request(req)))
    }
}

impl Account {
    /// Restore an existing account from the given credentials
    ///
    /// The [`AccountCredentials`] type is opaque, but supports deserialization.
        pub async fn from_credentials(credentials: AccountCredentials) -> Result<Self, Error> {
        Ok(Self {
            inner: Arc::new(
                AccountInner::from_credentials(credentials, Box::new(DefaultClient::try_new()?))
                    .await?,
            ),
        })
    }

    /// Create a new account on the `server_url` with the information in [`NewAccount`]
    ///
    /// The returned [`AccountCredentials`] can be serialized and stored for later use.
    /// Use [`Account::from_credentials()`] to restore the account from the credentials.
        pub async fn create(
        account: &NewAccount<'_>,
        server_url: &str,
        external_account: Option<&ExternalAccountKey>,
    ) -> Result<(Account, AccountCredentials), Error> {
        Self::create_inner(
            account,
            external_account,
            Client::new(server_url, Box::new(DefaultClient::try_new()?)).await?,
            server_url,
        )
        .await
    }
}

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
