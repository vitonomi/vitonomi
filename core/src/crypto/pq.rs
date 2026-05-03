//! Post-quantum primitives: **ML-DSA-65** signatures and
//! **ML-KEM-768** key encapsulation, wrapped to expose byte-array
//! types and constant-time public-key comparison without leaking the
//! upstream `ml-dsa` / `ml-kem` crates beyond `core::crypto`.
//!
//! Implementation note: both upstream crates are pure Rust (no
//! NEON/AVX intrinsics), which is required for correct execution on
//! ARM Cortex-A72 (Pi 4) and other older aarch64 cores. The
//! `pqcrypto` family compiles PQClean's C code with optimised SIMD
//! variants that SIGILL on these CPUs — do not switch back without
//! validating on Pi hardware.
//!
//! Secret key serialisation format:
//! - ML-DSA-65 secret key = 32-byte BIP-39-style seed `xi`. The
//!   expanded signing key is regenerated from the seed each time
//!   it's used (FIPS 204 KeyGen_internal).
//! - ML-KEM-768 secret key = 64-byte seed (`d || z`). The expanded
//!   decapsulation key is regenerated from the seed each time.
//!
//! These compact seed-based forms are what the key blob and the
//! seed-phrase recovery path will eventually carry.

use ml_dsa::signature::{Keypair as _, Signer as _, Verifier as _};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, KeyGen as _, MlDsa65, Signature as MlDsaSig,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate as _, KeyExport as _};
use ml_kem::{
    Ciphertext as MlKemCiphertext, DecapsulationKey, EncapsulationKey, MlKem768, Seed as MlKemSeed,
    B32 as KemB32,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::random::fill_random;
use crate::encoding::constant_time_eq;
use crate::errors::CryptoError;

// ─── ML-DSA-65 ──────────────────────────────────────────────────────

/// ML-DSA-65 public key (signature verifying key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlDsa65PublicKey(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl MlDsa65PublicKey {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

/// ML-DSA-65 secret key (32-byte FIPS 204 seed `xi`). Zeroised on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsa65SecretKey(pub Vec<u8>);

impl MlDsa65SecretKey {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// ML-DSA-65 detached signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlDsa65Signature(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl MlDsa65Signature {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// ML-DSA-65 keypair.
pub struct MlDsa65Keypair {
    pub public: MlDsa65PublicKey,
    pub secret: MlDsa65SecretKey,
}

/// Generate a fresh ML-DSA-65 keypair from the platform RNG (FIPS 204
/// KeyGen_internal seeded with 32 random bytes).
///
/// # Errors
///
/// Returns `CryptoError::Random` if the platform RNG fails.
pub fn ml_dsa_65_keypair() -> Result<MlDsa65Keypair, CryptoError> {
    let mut xi = [0u8; 32];
    fill_random(&mut xi)?;
    let signing = MlDsa65::from_seed(&Array::from(xi));
    let pk_bytes = signing.verifying_key().encode().as_slice().to_vec();
    Ok(MlDsa65Keypair {
        public: MlDsa65PublicKey(pk_bytes),
        secret: MlDsa65SecretKey(xi.to_vec()),
    })
}

fn ml_dsa_65_signing_from_seed(
    sk: &MlDsa65SecretKey,
) -> Result<MlDsaSigningKey<MlDsa65>, CryptoError> {
    if sk.0.len() != 32 {
        return Err(CryptoError::Signature(
            "secret key must be a 32-byte FIPS 204 seed".into(),
        ));
    }
    let mut xi = [0u8; 32];
    xi.copy_from_slice(&sk.0);
    Ok(MlDsa65::from_seed(&Array::from(xi)))
}

/// Sign `message` with `sk`. Detached signature.
///
/// # Errors
///
/// Returns `CryptoError::Signature` if the secret key is malformed
/// or signing fails.
pub fn ml_dsa_65_sign(
    sk: &MlDsa65SecretKey,
    message: &[u8],
) -> Result<MlDsa65Signature, CryptoError> {
    let signing = ml_dsa_65_signing_from_seed(sk)?;
    let sig = signing
        .try_sign(message)
        .map_err(|e| CryptoError::Signature(format!("sign: {e}")))?;
    Ok(MlDsa65Signature(sig.encode().as_slice().to_vec()))
}

/// Verify `sig` against `pk` for `message`.
///
/// # Errors
///
/// Returns `CryptoError::SignatureInvalid` on verification failure.
pub fn ml_dsa_65_verify(
    pk: &MlDsa65PublicKey,
    sig: &MlDsa65Signature,
    message: &[u8],
) -> Result<(), CryptoError> {
    let pk_arr = EncodedVerifyingKey::<MlDsa65>::try_from(pk.0.as_slice())
        .map_err(|_| CryptoError::SignatureInvalid)?;
    let verifying = MlDsaVerifyingKey::<MlDsa65>::decode(&pk_arr);
    let sig_arr = EncodedSignature::<MlDsa65>::try_from(sig.0.as_slice())
        .map_err(|_| CryptoError::SignatureInvalid)?;
    let parsed = MlDsaSig::<MlDsa65>::decode(&sig_arr).ok_or(CryptoError::SignatureInvalid)?;
    verifying
        .verify(message, &parsed)
        .map_err(|_| CryptoError::SignatureInvalid)
}

// ─── ML-KEM-768 ─────────────────────────────────────────────────────

/// ML-KEM-768 public (encapsulation) key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlKem768PublicKey(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl MlKem768PublicKey {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

/// ML-KEM-768 secret (decapsulation) key (64-byte seed `d || z`).
/// Zeroised on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKem768SecretKey(pub Vec<u8>);

impl MlKem768SecretKey {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// ML-KEM-768 ciphertext (KEM encapsulation output).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlKem768Ciphertext(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// 32-byte shared secret produced by KEM encaps/decaps.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKem768SharedSecret(pub Vec<u8>);

/// ML-KEM-768 keypair.
pub struct MlKem768Keypair {
    pub public: MlKem768PublicKey,
    pub secret: MlKem768SecretKey,
}

/// Generate a fresh ML-KEM-768 keypair from the platform RNG (FIPS
/// 203 KeyGen seeded with `d || z`).
///
/// # Errors
///
/// Returns `CryptoError::Random` if the platform RNG fails.
pub fn ml_kem_768_keypair() -> Result<MlKem768Keypair, CryptoError> {
    let mut seed = [0u8; 64];
    fill_random(&mut seed)?;
    let dk = DecapsulationKey::<MlKem768>::from_seed(MlKemSeed::from(seed));
    let ek = dk.encapsulation_key();
    let pk_bytes = ek.to_bytes().as_slice().to_vec();
    Ok(MlKem768Keypair {
        public: MlKem768PublicKey(pk_bytes),
        secret: MlKem768SecretKey(seed.to_vec()),
    })
}

/// Encapsulate to `pk`: yields a shared secret + ciphertext.
///
/// # Errors
///
/// Returns `CryptoError::Kem` if the public key is malformed.
pub fn ml_kem_768_encaps(
    pk: &MlKem768PublicKey,
) -> Result<(MlKem768SharedSecret, MlKem768Ciphertext), CryptoError> {
    let key = ml_kem::kem::Key::<EncapsulationKey<MlKem768>>::try_from(pk.0.as_slice())
        .map_err(|_| CryptoError::Kem("pk decode: bad length".into()))?;
    let ek = EncapsulationKey::<MlKem768>::new(&key)
        .map_err(|e| CryptoError::Kem(format!("pk init: {e:?}")))?;
    // Generate the 32-byte randomness `m` ourselves to dodge the
    // rand_core trait-version skew between `rand_core` 0.9 and the
    // older `kem` crate version pinned by ml-kem.
    let mut m_bytes = [0u8; 32];
    fill_random(&mut m_bytes)?;
    let m: KemB32 = Array::from(m_bytes);
    let (ct, ss) = ek.encapsulate_deterministic(&m);
    Ok((
        MlKem768SharedSecret(ss.as_slice().to_vec()),
        MlKem768Ciphertext(ct.as_slice().to_vec()),
    ))
}

/// Decapsulate `ct` with `sk`: recovers the shared secret.
///
/// # Errors
///
/// Returns `CryptoError::Kem` on malformed key/ciphertext.
pub fn ml_kem_768_decaps(
    sk: &MlKem768SecretKey,
    ct: &MlKem768Ciphertext,
) -> Result<MlKem768SharedSecret, CryptoError> {
    if sk.0.len() != 64 {
        return Err(CryptoError::Kem("secret key must be 64-byte seed".into()));
    }
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&sk.0);
    let dk = DecapsulationKey::<MlKem768>::from_seed(MlKemSeed::from(seed));
    let ct_arr = MlKemCiphertext::<MlKem768>::try_from(ct.0.as_slice())
        .map_err(|_| CryptoError::Kem("ct decode: bad length".into()))?;
    let ss = dk.decapsulate(&ct_arr);
    Ok(MlKem768SharedSecret(ss.as_slice().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsa_round_trip() {
        let kp = ml_dsa_65_keypair().unwrap();
        let msg = b"hello";
        let sig = ml_dsa_65_sign(&kp.secret, msg).unwrap();
        ml_dsa_65_verify(&kp.public, &sig, msg).expect("valid signature");
    }

    #[test]
    fn dsa_rejects_tampered_message() {
        let kp = ml_dsa_65_keypair().unwrap();
        let sig = ml_dsa_65_sign(&kp.secret, b"alpha").unwrap();
        let r = ml_dsa_65_verify(&kp.public, &sig, b"alphb");
        assert!(matches!(r, Err(CryptoError::SignatureInvalid)));
    }

    #[test]
    fn dsa_rejects_tampered_signature() {
        let kp = ml_dsa_65_keypair().unwrap();
        let mut sig = ml_dsa_65_sign(&kp.secret, b"alpha").unwrap();
        sig.0[0] ^= 0x01;
        assert!(matches!(
            ml_dsa_65_verify(&kp.public, &sig, b"alpha"),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn dsa_rejects_wrong_key() {
        let kp1 = ml_dsa_65_keypair().unwrap();
        let kp2 = ml_dsa_65_keypair().unwrap();
        let sig = ml_dsa_65_sign(&kp1.secret, b"alpha").unwrap();
        assert!(matches!(
            ml_dsa_65_verify(&kp2.public, &sig, b"alpha"),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn dsa_seed_round_trip() {
        // Sign + verify with a *fresh* signing key reconstructed from
        // the persisted secret-key seed bytes — proves the seed-only
        // serialisation is sufficient.
        let kp = ml_dsa_65_keypair().unwrap();
        let sig_a = ml_dsa_65_sign(&kp.secret, b"alpha").unwrap();
        let cloned_seed = MlDsa65SecretKey(kp.secret.0.clone());
        let sig_b = ml_dsa_65_sign(&cloned_seed, b"alpha").unwrap();
        // ML-DSA's deterministic signing makes these byte-identical.
        assert_eq!(sig_a.as_bytes(), sig_b.as_bytes());
    }

    #[test]
    fn kem_round_trip() {
        let kp = ml_kem_768_keypair().unwrap();
        let (ss1, ct) = ml_kem_768_encaps(&kp.public).unwrap();
        let ss2 = ml_kem_768_decaps(&kp.secret, &ct).unwrap();
        assert_eq!(ss1.0, ss2.0, "encaps + decaps should match");
        assert!(!ss1.0.is_empty());
    }

    #[test]
    fn kem_rejects_wrong_secret_key() {
        let kp1 = ml_kem_768_keypair().unwrap();
        let kp2 = ml_kem_768_keypair().unwrap();
        let (ss1, ct) = ml_kem_768_encaps(&kp1.public).unwrap();
        // Implicit-rejection: decaps with wrong sk yields a *different*
        // shared secret rather than an error.
        let ss_wrong = ml_kem_768_decaps(&kp2.secret, &ct).unwrap();
        assert_ne!(ss1.0, ss_wrong.0);
    }

    #[test]
    fn algorithm_confusion_dsa_pubkey_is_not_kem_pubkey() {
        let dsa = ml_dsa_65_keypair().unwrap();
        let dsa_pk = MlKem768PublicKey(dsa.public.0.clone());
        let r = ml_kem_768_encaps(&dsa_pk);
        assert!(matches!(r, Err(CryptoError::Kem(_))));
    }
}
