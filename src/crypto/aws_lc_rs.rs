use rustls_pki_types::PrivatePkcs8KeyDer;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair, ML_DSA_44_SIGNING, PqdsaKeyPair,
    PqdsaSigningAlgorithm,
};
use aws_lc_rs::{digest, hmac};

use super::{CryptoProvider, HmacKey, HmacKeyProvider, SigningKey, SigningKeyProvider};
use crate::Error;
use crate::types::{EcCurve, Jwk, JwkKeyParameters, SigningAlgorithm};

pub(crate) static PROVIDER: &CryptoProvider = &CryptoProvider {
    key_provider: &P256SigningKeyProvider,
    sha256: &Sha256,
    hmac: &HmacSha256Provider,
};

pub(crate) static ML_DSA_44_PROVIDER: &CryptoProvider = &CryptoProvider {
    key_provider: &MlDsaSigningKeyProvider {
        algorithm: &ML_DSA_44_SIGNING,
        jose_algorithm: SigningAlgorithm::MlDsa44,
    },
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
            key: JwkKeyParameters::Ec {
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

struct MlDsaSigningKeyProvider {
    algorithm: &'static PqdsaSigningAlgorithm,
    jose_algorithm: SigningAlgorithm,
}

impl SigningKeyProvider for MlDsaSigningKeyProvider {
    fn load_key(&self, pkcs8: PrivatePkcs8KeyDer<'static>) -> Result<Box<dyn SigningKey>, Error> {
        let key_pair = PqdsaKeyPair::from_pkcs8(self.algorithm, pkcs8.secret_pkcs8_der())
            .map_err(|_| Error::KeyRejected)?;
        Ok(Box::new(MlDsaKey {
            key_pair,
            jose_algorithm: self.jose_algorithm,
        }))
    }

    fn generate_key(&self) -> Result<(Box<dyn SigningKey>, PrivatePkcs8KeyDer<'static>), Error> {
        let key_pair = PqdsaKeyPair::generate(self.algorithm).map_err(|_| Error::Crypto)?;
        let pkcs8 = key_pair.to_pkcs8v1().map_err(|_| Error::Crypto)?;
        let pkcs8_der = PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec());
        Ok((
            Box::new(MlDsaKey {
                key_pair,
                jose_algorithm: self.jose_algorithm,
            }),
            pkcs8_der,
        ))
    }
}

struct MlDsaKey {
    key_pair: PqdsaKeyPair,
    jose_algorithm: SigningAlgorithm,
}

impl SigningKey for MlDsaKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut signature = vec![0; self.key_pair.algorithm().signature_len()];
        let len = self
            .key_pair
            .sign(data, &mut signature)
            .map_err(|_| Error::Crypto)?;
        signature.truncate(len);
        Ok(signature)
    }

    fn as_jwk(&self) -> Jwk<'_> {
        Jwk {
            alg: self.jose_algorithm,
            key: JwkKeyParameters::Akp {
                public_key: self.key_pair.public_key().as_ref(),
            },
            r#use: "sig",
        }
    }

    fn algorithm(&self) -> SigningAlgorithm {
        self.jose_algorithm
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
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        hmac::sign(&self.0, data).as_ref().to_vec()
    }

    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Hs256
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::signature::{ML_DSA_44, UnparsedPublicKey};

    use super::*;

    #[test]
    fn mldsa44_round_trip() {
        let message = b"complete JWS signing input";
        let (key, pkcs8) = ML_DSA_44_PROVIDER.key_provider.generate_key().unwrap();
        let JwkKeyParameters::Akp { public_key } = key.as_jwk().key else {
            panic!("ML-DSA provider returned a non-AKP JWK");
        };
        assert_eq!(public_key.len(), ML_DSA_44_SIGNING.public_key_len());
        let signature = key.sign(message).unwrap();
        assert_eq!(signature.len(), ML_DSA_44_SIGNING.signature_len());
        UnparsedPublicKey::new(&ML_DSA_44, public_key)
            .verify(message, &signature)
            .unwrap();

        let expected_jwk = serde_json::to_string(&key.as_jwk()).unwrap();
        let loaded = ML_DSA_44_PROVIDER.key_provider.load_key(pkcs8).unwrap();
        assert_eq!(
            serde_json::to_string(&loaded.as_jwk()).unwrap(),
            expected_jwk
        );
        let loaded_signature = loaded.sign(message).unwrap();
        let JwkKeyParameters::Akp { public_key } = loaded.as_jwk().key else {
            panic!("ML-DSA provider returned a non-AKP JWK");
        };
        UnparsedPublicKey::new(&ML_DSA_44, public_key)
            .verify(message, &loaded_signature)
            .unwrap();
    }
}
