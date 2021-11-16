use blake3;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_TABLE, ristretto::CompressedRistretto};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

/// This lets us use the XOF output from our hash function as a source of randomness.
struct HashRng(blake3::OutputReader);

impl HashRng {
    /// create a new HashRng from a blake3 hasher.
    ///
    /// This will finalize the hasher itself, creating the XOF.
    pub fn new(hasher: blake3::Hasher) -> Self {
        HashRng(hasher.finalize_xof())
    }
}

impl RngCore for HashRng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Because we're using BLAKE3's XOF as our underlying source of randomness,
/// we're cryptographically secure.
impl CryptoRng for HashRng {}

/// This represents the kind of Error that can happen when signing.
pub enum Error {
    /// An invalid public key was found when deserializing.
    InvalidPublicKey,
    /// A signature failed to verify, for some reason.
    ///
    /// We intentionally provide minimal detail on why this signature failed, to
    /// thwart any attacks using this extra information.
    InvalidSignature,
}

/// The number of bytes in a private key.
pub const PRIVATE_KEY_SIZE: usize = 32;
/// The number of bytes in a public key.
pub const PUBLIC_KEY_SIZE: usize = 32;
// The number of bytes in the hedge factor for signatures.
const HEDGE_SIZE: usize = 32;
/// The number of bytes in a signature.
pub const SIGNATURE_SIZE: usize = 64;

/// PrivateKey represents the key used for generating signatures.
///
/// This key should not be shared with anyone else. Doing so will allow them
/// to create signatures with this key.
#[derive(Clone)]
pub struct PrivateKey {
    /// bytes holds the raw data of our private key.
    ///
    /// Instead of a scalar, our private key presents a raw seed which can be used
    /// to derive other elements as needed for signing.
    bytes: [u8; PRIVATE_KEY_SIZE],
}

// We use different contexts to disambiguate different instance of key derivation.
const DERIVE_HASHING_KEY_CONTEXT: &'static str = "toy-coin 2021-11-11 derive hashing key";
const DERIVE_SCALAR_CONTEXT: &'static str = "toy-coin 2021-11-11 derive scalar";

impl PrivateKey {
    /// derive the private scalar associated with this seed.
    fn derive_scalar(&self) -> Scalar {
        let mut hasher = blake3::Hasher::new_derive_key(DERIVE_SCALAR_CONTEXT);
        hasher.update(&self.bytes);
        Scalar::random(&mut HashRng::new(hasher))
    }

    /// create a new PrivateKey from randomness.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut key = PrivateKey {
            bytes: [0; PRIVATE_KEY_SIZE],
        };
        rng.fill_bytes(&mut key.bytes);
        key
    }

    /// create a signature over a given message.
    ///
    /// This signature can be independently verified by anyone with the public key.
    /// The signature will fail to verify with a different public key, or with a different message.
    ///
    /// Randomness is passed for hedged signatures. This provides additional security
    /// against fault attacks, compared to plain deterministic signatures.
    pub fn sign<R: RngCore + CryptoRng>(&self, rng: &mut R, message: &[u8]) -> Signature {
        let private_scalar = self.derive_scalar();
        let public_point_compressed = (&private_scalar * &RISTRETTO_BASEPOINT_TABLE).compress();

        let hashing_key: [u8; blake3::KEY_LEN] =
            blake3::derive_key(DERIVE_HASHING_KEY_CONTEXT, &self.bytes);
        // To generate our random Scalar, we rely on either the integrity of the hash computation,
        // in which case bad randomness is fine, or the integrity of the randomness, in which case
        // faulting the hash function is ok.
        let mut hedge = [0; HEDGE_SIZE];
        rng.fill_bytes(&mut hedge);
        let surprise = Scalar::random(&mut HashRng::new(
            blake3::Hasher::new_keyed(&hashing_key)
                .update(message)
                .update(&hedge)
                .to_owned(),
        ));
        let surprise_point_compressed = (&surprise * &RISTRETTO_BASEPOINT_TABLE).compress();

        let challenge = Scalar::random(&mut HashRng::new(
            blake3::Hasher::new()
                .update(public_point_compressed.as_bytes())
                .update(surprise_point_compressed.as_bytes())
                .update(message)
                .to_owned(),
        ));

        let response = surprise + challenge * private_scalar;

        let mut signature = Signature([0; 64]);
        signature.0[..32].clone_from_slice(surprise_point_compressed.as_bytes());
        signature.0[32..].clone_from_slice(response.as_bytes());

        signature
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(&self.derive_scalar() * &RISTRETTO_BASEPOINT_TABLE)
    }
}

pub struct Signature([u8; SIGNATURE_SIZE]);

pub struct PublicKey(RistrettoPoint);

impl PublicKey {
    pub fn verify(&self, signature: &Signature, message: &[u8]) -> Result<(), Error> {
        let surprise_point_compressed = CompressedRistretto::from_slice(&signature.0[..32]);
        let response = Scalar::from_canonical_bytes(signature.0[32..].try_into().unwrap())
            .ok_or(Error::InvalidSignature)?;

        let challenge = Scalar::random(&mut HashRng::new(
            blake3::Hasher::new()
                .update(self.0.compress().as_bytes())
                .update(surprise_point_compressed.as_bytes())
                .update(message)
                .to_owned(),
        ));

        let should_be_surprise_point =
            RistrettoPoint::vartime_double_scalar_mul_basepoint(&-challenge, &self.0, &response);

        if !bool::from(
            should_be_surprise_point
                .compress()
                .ct_eq(&surprise_point_compressed),
        ) {
            return Err(Error::InvalidSignature);
        }

        Ok(())
    }
}

impl<'a> TryFrom<&'a [u8]> for PublicKey {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() != PUBLIC_KEY_SIZE {
            return Err(Error::InvalidPublicKey);
        }
        let compressed = CompressedRistretto::from_slice(value);
        let decompressed = compressed.decompress().ok_or(Error::InvalidPublicKey)?;
        if decompressed.is_identity() {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Self(decompressed))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_signing_message_verifies() {
        let message = b"hello world";
        let private_key = PrivateKey::random(&mut OsRng);
        let public_key = private_key.public_key();
        let signature = private_key.sign(&mut OsRng, message);
        assert!(public_key.verify(&signature, message).is_ok());
    }

    #[test]
    fn test_signing_message_does_not_verify_with_different_message() {
        let message1 = b"hello world";
        let message2 = b"bonjour monde";
        let private_key = PrivateKey::random(&mut OsRng);
        let public_key = private_key.public_key();
        let signature = private_key.sign(&mut OsRng, message1);
        assert!(public_key.verify(&signature, message2).is_err());
    }

    #[test]
    fn test_signing_message_does_not_verify_with_different_key() {
        let message = b"hello world";
        let private_key = PrivateKey::random(&mut OsRng);
        let public_key = PrivateKey::random(&mut OsRng).public_key();
        let signature = private_key.sign(&mut OsRng, message);
        assert!(public_key.verify(&signature, message).is_err());
    }
}
