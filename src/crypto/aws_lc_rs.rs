use rustls_pki_types::PrivatePkcs8KeyDer;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use aws_lc_rs::{digest, hmac};

use super::{HmacKey, HmacKeyProvider, SigningKey, SigningKeyProvider};
use crate::Error;
use crate::types::{EcCurve, Jwk, JwkThumbFields, SigningAlgorithm};

pub(crate) static PROVIDER: &super::CryptoProvider = &super::CryptoProvider {
    signing_key: &P256SigningKeyProvider,
    sha256: &Sha256,
    hmac: &HmacSha256Provider,
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
        match self.key_pair.sign(&self.rng, data) {
            Ok(sig) => Ok(sig.as_ref().to_vec()),
            Err(_) => Err(Error::Crypto),
        }
    }

    fn as_jwk(&self) -> Jwk<'_> {
        let (x, y) = self.key_pair.public_key().as_ref()[1..].split_at(32);
        Jwk {
            alg: SigningAlgorithm::Es256,
            key: JwkThumbFields::Ec {
                crv: EcCurve::P256,
                x,
                y,
            },
            r#use: "sig",
        }
    }

    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Es256
    }
}

struct Sha256;

impl super::Sha256 for Sha256 {
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        digest::digest(&digest::SHA256, data)
            .as_ref()
            .try_into()
            .expect("SHA-256 output is always 32 bytes")
    }
}

struct HmacSha256Provider;

impl HmacKeyProvider for HmacSha256Provider {
    fn load_key(&self, key_value: &[u8]) -> Box<dyn HmacKey> {
        Box::new(HmacSha256Key(hmac::Key::new(hmac::HMAC_SHA256, key_value)))
    }
}

struct HmacSha256Key(hmac::Key);

impl HmacKey for HmacSha256Key {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Hs256
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        hmac::sign(&self.0, data).as_ref().to_vec()
    }
}
