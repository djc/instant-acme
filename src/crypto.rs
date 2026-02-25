use std::fmt;

use rustls_pki_types::PrivatePkcs8KeyDer;

use crate::Error;
use crate::types::{Jwk, SigningAlgorithm};

#[cfg(feature = "aws-lc-rs")]
mod aws_lc_rs;

#[cfg(feature = "ring")]
mod ring;

/// Cryptographic provider for ACME operations.
///
/// Use [`CryptoProvider::aws_lc_rs()`] or [`CryptoProvider::ring()`] for the built-in backend,
/// or populate the fields manually for a custom backend.
pub struct CryptoProvider {
    /// Load and generate signing keys.
    pub signing_key: &'static dyn SigningKeyProvider,
    /// SHA-256 hash for ACME protocol operations.
    ///
    /// Used for JWK thumbprints ([RFC 7638]) and challenge digests ([RFC 8555 section 8.1]).
    /// This is independent of the signing algorithm used for account keys.
    ///
    /// [RFC 7638]: https://www.rfc-editor.org/rfc/rfc7638
    /// [RFC 8555 section 8.1]: https://www.rfc-editor.org/rfc/rfc8555#section-8.1
    pub sha256: &'static dyn Sha256,
    /// HMAC-SHA-256 for External Account Binding.
    ///
    /// See [RFC 8555 section 7.3.4].
    ///
    /// [RFC 8555 section 7.3.4]: https://www.rfc-editor.org/rfc/rfc8555#section-7.3.4
    pub hmac_sha256: &'static dyn HmacSha256,
}

impl CryptoProvider {
    /// A `CryptoProvider` using ECDSA P-256 account keys backed by aws-lc-rs.
    #[cfg(feature = "aws-lc-rs")]
    pub fn aws_lc_rs() -> &'static Self {
        aws_lc_rs::PROVIDER
    }

    /// A `CryptoProvider` using ECDSA P-256 account keys backed by ring.
    #[cfg(feature = "ring")]
    pub fn ring() -> &'static Self {
        ring::PROVIDER
    }
}

impl fmt::Debug for CryptoProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CryptoProvider").finish_non_exhaustive()
    }
}

/// Load existing account keys and generate new ones.
///
/// Implementations are backend-specific (ring, aws-lc-rs, openssl, etc.)
/// and key-type-specific (P-256, Ed25519, RSA, etc.).
pub trait SigningKeyProvider: Send + Sync {
    /// Load a signing key from PKCS#8 DER encoding.
    fn load_key(&self, pkcs8: PrivatePkcs8KeyDer<'static>) -> Result<Box<dyn SigningKey>, Error>;

    /// Generate a new key pair, returning the key and its PKCS#8 DER encoding.
    fn generate_key(&self) -> Result<(Box<dyn SigningKey>, PrivatePkcs8KeyDer<'static>), Error>;
}

/// A signing key for ACME account operations.
///
/// Bundles signing, JWS algorithm identification, and JWK serialization.
/// Implement this trait to support any key type (P-256, P-384, Ed25519, RSA, etc.)
/// without changes to instant-acme.
pub trait SigningKey: Send + Sync {
    /// Sign the given data using this key's algorithm.
    ///
    /// The implementation handles hashing internally where required
    /// (e.g., SHA-256 for ES256, SHA-512 for Ed25519).
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// The JWS `alg` header value (e.g., `ES256`).
    fn jws_algorithm(&self) -> SigningAlgorithm;

    /// Serialize the public key as a JWK JSON object for the `jwk` JWS header.
    fn as_jwk(&self) -> Jwk<'_>;
}

/// SHA-256 hash function for ACME protocol operations.
///
/// Used for JWK thumbprints ([RFC 7638]) and challenge digests ([RFC 8555]).
///
/// [RFC 7638]: https://www.rfc-editor.org/rfc/rfc7638
/// [RFC 8555]: https://www.rfc-editor.org/rfc/rfc8555
pub trait Sha256: Send + Sync {
    /// Compute the SHA-256 digest of the given data.
    fn hash(&self, data: &[u8]) -> [u8; 32];
}

/// HMAC-SHA-256 for ACME External Account Binding.
///
/// See [RFC 8555 section 7.3.4].
///
/// [RFC 8555 section 7.3.4]: https://www.rfc-editor.org/rfc/rfc8555#section-7.3.4
pub trait HmacSha256: Send + Sync {
    /// Compute HMAC-SHA-256 of `data` using the given `key`.
    fn sign(&self, key: &[u8], data: &[u8]) -> [u8; 32];
}
