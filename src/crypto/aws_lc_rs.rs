use rustls_pki_types::PrivatePkcs8KeyDer;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use aws_lc_rs::{digest, hmac};

use super::{HmacSha256, Sha256, SigningKey, SigningKeyProvider};
use crate::Error;
use crate::types::{Jwk, JwkThumbFields, SigningAlgorithm};

pub(crate) static PROVIDER: &super::CryptoProvider = &super::CryptoProvider {
    signing_key: &P256SigningKeyProvider,
    sha256: &BuiltinSha256,
    hmac_sha256: &BuiltinHmacSha256,
};

struct P256SigningKeyProvider;

impl SigningKeyProvider for P256SigningKeyProvider {
    fn load_key(&self, pkcs8: PrivatePkcs8KeyDer<'static>) -> Result<Box<dyn SigningKey>, Error> {
        let rng = SystemRandom::new();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.secret_pkcs8_der())
                .map_err(|_| Error::KeyRejected)?;
        Ok(Box::new(P256Key { key_pair, rng }))
    }

    fn generate_key(&self) -> Result<(Box<dyn SigningKey>, PrivatePkcs8KeyDer<'static>), Error> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| Error::Crypto)?;
        let pkcs8_der = PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec());
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
            .map_err(|_| Error::KeyRejected)?;
        Ok((Box::new(P256Key { key_pair, rng }), pkcs8_der))
    }
}

struct P256Key {
    key_pair: EcdsaKeyPair,
    rng: SystemRandom,
}

impl SigningKey for P256Key {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.key_pair
            .sign(&self.rng, data)
            .map(|sig| sig.as_ref().to_vec())
            .map_err(|_| Error::Crypto)
    }

    fn jws_algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Es256
    }

    fn as_jwk(&self) -> Jwk<'_> {
        let (x, y) = self.key_pair.public_key().as_ref()[1..].split_at(32);
        Jwk {
            alg: SigningAlgorithm::Es256,
            key: JwkThumbFields::Ec {
                crv: "P-256",
                kty: "EC",
                x,
                y,
            },
            r#use: "sig",
        }
    }
}

struct BuiltinSha256;

impl Sha256 for BuiltinSha256 {
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        digest::digest(&digest::SHA256, data)
            .as_ref()
            .try_into()
            .expect("SHA-256 output is always 32 bytes")
    }
}

struct BuiltinHmacSha256;

impl HmacSha256 for BuiltinHmacSha256 {
    fn sign(&self, key: &[u8], data: &[u8]) -> [u8; 32] {
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        hmac::sign(&hmac_key, data)
            .as_ref()
            .try_into()
            .expect("HMAC-SHA-256 output is always 32 bytes")
    }
}
