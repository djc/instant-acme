use std::{io, time::Duration};

use clap::Parser;
use rustls::Certificate;
use tokio::time::sleep;
use tracing::{error, info};

use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    // let opts = Options::parse();

    // Create a new account. This will generate a fresh ECDSA key for you.
    // Alternatively, restore an account from serialized credentials by
    // using `Account::from_credentials()`.

    // let account = Account::create(
    //     &NewAccount {
    //         contact: &[],
    //         terms_of_service_agreed: true,
    //         only_return_existing: false,
    //     },
    //     LetsEncrypt::Staging.url(),
    // )
    // .await?;

    let creds = serde_json::from_str(ACCOUNT).unwrap();
    let account = Account::from_credentials(creds).unwrap();

    let certs = rustls_pemfile::certs(&mut CERT).unwrap();
    let cert = certs[0].clone();
    account.revoke(&Certificate(cert)).await.unwrap();

    // info!(
    //     "account credentials:\n\n{}",
    //     serde_json::to_string_pretty(&ACCOUNT.credentials()).unwrap()
    // );

    Ok(())
}

/// SMTP server
#[derive(Parser)]
struct Options {
    // #[clap(long)]
    // name: String,
}

const CERT: &[u8] = b"-----BEGIN CERTIFICATE-----
MIID8TCCA3igAwIBAgITAPrsbmSSkWU08+AFKwWnHLCgCjAKBggqhkjOPQQDAzBV
MQswCQYDVQQGEwJVUzEgMB4GA1UEChMXKFNUQUdJTkcpIExldCdzIEVuY3J5cHQx
JDAiBgNVBAMTGyhTVEFHSU5HKSBFcnNhdHogRWRhbWFtZSBFMTAeFw0yMjExMzAx
NzM2NTlaFw0yMzAyMjgxNzM2NThaMCExHzAdBgNVBAMTFnNhZ2U4OS5tZXNzd2l0
aGRucy5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS9Vx9GxJCvGffEZqgW
mEtBx6s8kUTGQp+K7afTae1sz/GrOnRnNYwGkQaRRaRkNiU6SoPSpaIEF7SppfLE
VQ+Ro4ICWTCCAlUwDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMB
BggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTFI9bBN5i1NTThtA//
R7C3wt5ooDAfBgNVHSMEGDAWgBTr+SXCgChm4m0IkjLzwuGtw/81RTBdBggrBgEF
BQcBAQRRME8wJQYIKwYBBQUHMAGGGWh0dHA6Ly9zdGctZTEuby5sZW5jci5vcmcw
JgYIKwYBBQUHMAKGGmh0dHA6Ly9zdGctZTEuaS5sZW5jci5vcmcvMCEGA1UdEQQa
MBiCFnNhZ2U4OS5tZXNzd2l0aGRucy5jb20wTAYDVR0gBEUwQzAIBgZngQwBAgEw
NwYLKwYBBAGC3xMBAQEwKDAmBggrBgEFBQcCARYaaHR0cDovL2Nwcy5sZXRzZW5j
cnlwdC5vcmcwggEEBgorBgEEAdZ5AgQCBIH1BIHyAPAAdQDBgyQL8aRQx2+7AHJp
3Kw74ipIBdTb4Elmw8irxEewDAAAAYTJ0+x7AAAEAwBGMEQCIG9fm12nxSRo6Gik
ctP/4ee/xGivaY9YXO3Fj0gbMe1LAiBRBKCBBJ7INzVY2YFcfva0Uz373huQWmmP
7Cac9jPSRQB3ALDMg+Wl+X1rr3wJzChJBIcqx+iLEyxjULfG/SbhbGx3AAABhMnT
7GcAAAQDAEgwRgIhAPS0KdNvGSq1DCHRf9Uvp31YMkyFGInt6tMGVdJBqjVeAiEA
z812Z02g52+1vB3SbtT/Oo7Lgoal3GqvlsWf7JexST0wCgYIKoZIzj0EAwMDZwAw
ZAIwMGkJw9GmlG1qYrelKfeSnknSFphAoLHQCpnrhOjkYozDXk73tt/jl+5bo9dG
oPTQAjAh39Ocli9GwFDC+UP4aZBr1WDLGGodGpGMlPGBfqLLNMCqNiCf5BZC2xSC
TINoHwU=
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIDCzCCApGgAwIBAgIRALRY4992FVxZJKOJ3bpffWIwCgYIKoZIzj0EAwMwaDEL
MAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0
eSBSZXNlYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Nj
b2xpIFgyMB4XDTIwMDkwNDAwMDAwMFoXDTI1MDkxNTE2MDAwMFowVTELMAkGA1UE
BhMCVVMxIDAeBgNVBAoTFyhTVEFHSU5HKSBMZXQncyBFbmNyeXB0MSQwIgYDVQQD
ExsoU1RBR0lORykgRXJzYXR6IEVkYW1hbWUgRTEwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAAT9v/PJUtHOTk28nXCXrpP665vI4Z094h8o7R+5E6yNajZa0UubqjpZFoGq
u785/vGXj6mdfIzc9boITGusZCSWeMj5ySMZGZkS+VSvf8VQqj+3YdEu4PLZEjBA
ivRFpEejggEQMIIBDDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUH
AwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOv5JcKA
KGbibQiSMvPC4a3D/zVFMB8GA1UdIwQYMBaAFN7Ro1lkDsGaNqNG7rAQdu+ul5Vm
MDYGCCsGAQUFBwEBBCowKDAmBggrBgEFBQcwAoYaaHR0cDovL3N0Zy14Mi5pLmxl
bmNyLm9yZy8wKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL3N0Zy14Mi5jLmxlbmNy
Lm9yZy8wIgYDVR0gBBswGTAIBgZngQwBAgEwDQYLKwYBBAGC3xMBAQEwCgYIKoZI
zj0EAwMDaAAwZQIwXcZbdgxcGH9rTErfSTkXfBKKygU0yO7OpbuNeY1id0FZ/hRY
N5fdLOGuc+aHfCsMAjEA0P/xwKr6NQ9MN7vrfGAzO397PApdqfM7VdFK18aEu1xm
3HMFKzIR8eEPsMx4smMl
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIEmTCCAoGgAwIBAgIRAJJVIr2Em/sOzhBD2bEnEJwwDQYJKoZIhvcNAQELBQAw
ZjELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1
cml0eSBSZXNlYXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcpIFByZXRlbmQg
UGVhciBYMTAeFw0yMDA5MDQwMDAwMDBaFw0yNTA5MTUxNjAwMDBaMGgxCzAJBgNV
BAYTAlVTMTMwMQYDVQQKEyooU1RBR0lORykgSW50ZXJuZXQgU2VjdXJpdHkgUmVz
ZWFyY2ggR3JvdXAxJDAiBgNVBAMTGyhTVEFHSU5HKSBCb2d1cyBCcm9jY29saSBY
MjB2MBAGByqGSM49AgEGBSuBBAAiA2IABDr0vsNZAswMWDiWwNOgMNBxT9rSwSyj
6BUKkfQDLJJdZwtve+XkKsnEfgAr2HpQPK38BVzmzB2Fydt1ywfnQIzyVTidjnLI
01ajuHXA1rvq0NlSC3ZyUWMqZ1dTDE4VcaOB7TCB6jAOBgNVHQ8BAf8EBAMCAQYw
DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3tGjWWQOwZo2o0busBB2766XlWYw
HwYDVR0jBBgwFoAUtfNl8v6wCpIf+zx980SgrGMlwxQwNgYIKwYBBQUHAQEEKjAo
MCYGCCsGAQUFBzAChhpodHRwOi8vc3RnLXgxLmkubGVuY3Iub3JnLzArBgNVHR8E
JDAiMCCgHqAchhpodHRwOi8vc3RnLXgxLmMubGVuY3Iub3JnLzAiBgNVHSAEGzAZ
MAgGBmeBDAECATANBgsrBgEEAYLfEwEBATANBgkqhkiG9w0BAQsFAAOCAgEAMkp5
etLOxM4+a6EqX2hmAd+yNUSNCA7+MYn/VrwJnpkWe8zuC+fILYMYRuByWs/zeFmo
56Jc7td5N9I+QN0rYSeEbgdTAMeaBjZ3P6eJxM1Aa76Abrj5ULfq8XhOE37SYgFb
ZS9YPOQ4wuisCXHrrmu4ZdZJmzXIQX562xBeJxf0o4LBqS2C3SmpkPY+f8lTtmFO
/I6qSSl8T5XyNE385zNXaRd8rMJqNC9fIHDjPeJMIaou0TZYT0uNb9OZ7ZhT7smQ
SaHcGxtK0SVmJvGNagc6RldrHFbemLbwVpeI4NopRHynQqzkVtsfAlK8VD92SYbp
olFsJZWuHVkHgccuI1Hx0+RUp1VGj1PPV+0JmGZeG2ybLloU2rjjMbRmkNjTxub2
U1vzCGpBSaBfYQLjLHDwQk1AqRENlZxDqCkXFro8eqT6TFHdtw27KIT+ov1Qyofi
q3Uj1w7tPpcFMSDfiWNRE0XGYCjELDo19oPqQthIMQ5X+/3YpCqZceR4vMR6n9ol
Lp/0KmjAzqU+LqD2fmFLttKvZUxW8aECTGIcDHGCPJDklwDW3l7DUQ08Wj5Fh/KE
f5c9fF3u87WUAJu4Vh9C+ewXZtzL0LD46lYgpn7fv5w9sLS4zQ3CIC3udjJ5Gc/v
8VhPQaU1Enn7NW+4IHnfSeP6G5rzLEtl0PreC4k=
-----END CERTIFICATE-----";

const ACCOUNT: &str = "
{
    \"id\": \"https://acme-staging-v02.api.letsencrypt.org/acme/acct/78060154\",
    \"key_pkcs8\": \"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvjyueuqwXkRd0jjqRsYO6cIwvIctiPt1gqlLgMppwiehRANCAATUfP9I90-kJqSfW0ocUSG8Rmt6Du4U6goTdfx7as2ThDAsCYnFJlqOqe2RKJfeHfjMD_0Ks0N_PAFey8agM41h\",
    \"urls\": {
        \"newNonce\": \"https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce\",
        \"newAccount\": \"https://acme-staging-v02.api.letsencrypt.org/acme/new-acct\",
        \"newOrder\": \"https://acme-staging-v02.api.letsencrypt.org/acme/new-order\",
        \"revokeCert\": \"https://acme-staging-v02.api.letsencrypt.org/acme/revoke-cert\"
    }
}
";
