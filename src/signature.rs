use blake3;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_TABLE, ristretto::CompressedRistretto};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

struct HashRng(blake3::OutputReader);

impl HashRng {
    fn new(hasher: blake3::Hasher) -> Self {
        HashRng(hasher.finalize_xof())
    }
}

impl RngCore for HashRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
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

pub enum Error {
    InvalidPublicKey,
    InvalidSignature,
}

const PRIVATE_KEY_SIZE: usize = 32;
const PUBLIC_KEY_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 64;

/// PrivateKey represents the key used for generating signatures.
///
/// This key should not be shared with anyone else.
#[derive(Clone)]
pub struct PrivateKey {
    /// bytes holds the raw data of our private key.
    ///
    /// Instead of a scalar, our private key presents a raw seed which can be used
    /// to derive other elements as needed for signing.
    bytes: [u8; PRIVATE_KEY_SIZE],
}

const DERIVE_HASHING_KEY_CONTEXT: &'static str = "toy-coin 2021-11-11 derive hashing key";
const DERIVE_SCALAR_CONTEXT: &'static str = "toy-coin 2021-11-11 derive scalar";

impl PrivateKey {
    fn derive_scalar(&self) -> Scalar {
        let mut hasher = blake3::Hasher::new_derive_key(DERIVE_SCALAR_CONTEXT);
        hasher.update(&self.bytes);
        Scalar::random(&mut HashRng::new(hasher))
    }

    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut key = PrivateKey {
            bytes: [0; PRIVATE_KEY_SIZE],
        };
        rng.fill_bytes(&mut key.bytes);
        key
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let private_scalar = self.derive_scalar();
        let public_point_compressed = (&private_scalar * &RISTRETTO_BASEPOINT_TABLE).compress();

        let hashing_key: [u8; blake3::KEY_LEN] =
            blake3::derive_key(DERIVE_HASHING_KEY_CONTEXT, &self.bytes);
        let surprise = Scalar::random(&mut HashRng::new(
            blake3::Hasher::new_keyed(&hashing_key)
                .update(message)
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
        let signature = private_key.sign(message);
        assert!(public_key.verify(&signature, message).is_ok());
    }

    #[test]
    fn test_signing_message_does_not_verify_with_different_message() {
        let message1 = b"hello world";
        let message2 = b"bonjour monde";
        let private_key = PrivateKey::random(&mut OsRng);
        let public_key = private_key.public_key();
        let signature = private_key.sign(message1);
        assert!(public_key.verify(&signature, message2).is_err());
    }

    #[test]
    fn test_signing_message_does_not_verify_with_different_key() {
        let message = b"hello world";
        let private_key = PrivateKey::random(&mut OsRng);
        let public_key = PrivateKey::random(&mut OsRng).public_key();
        let signature = private_key.sign(message);
        assert!(public_key.verify(&signature, message).is_err());
    }
}
