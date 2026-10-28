//! crypto — the `_encryptData` crypto pipeline: ephemeral P-256 keygen,
//! ECDH, HKDF-SHA256 key/IV derivation, AES-256-GCM encryption, and the
//! full token generation entry point.
//!
//! Daemon pipeline being ported (README, Chapter 3):
//!
//! 1. `aks_ref_key_create(keybag, 11, 4, 0, 0, &refKey)` — ephemeral keypair
//!    from the AppleKeyStore keybag (software P-256 here; see
//!    [`generate_ephemeral`]).
//! 2. `aks_ref_key_compute_key(refKey, 0, 0, devicePubBytes, devicePubLen)`
//!    — ECDH against the fetched server public key (see [`ecdh_shared`]).
//! 3. `cchkdf(ccsha256_di(), sharedLen, sharedSecret, 0, NULL, 0x2C, out)` —
//!    HKDF-SHA256 to 44 bytes = 32-byte AES key + 12-byte GCM IV (see
//!    [`derive_key_iv`]).
//! 4. `ccgcm_one_shot(..., 12, aesIV, 0, NULL, payloadLen, payloadBuf,
//!    outBuf + 154, 16, outBuf + 1)` — AES-256-GCM, no AAD, 16-byte tag
//!    (see [`encrypt_payload`]).
//! 5. Buffer assembly — see [`crate::token`].
//!
//! Parity: `_encryptData` crypto call chain (CommonCrypto `cchkdf` /
//! `ccgcm_one_shot`, AppleKeyStore `aks_ref_key_*`).
//! Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3.

use std::fs::File;
use std::io::Read;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use p256::ecdh::{EphemeralSecret, SharedSecret};
use p256::elliptic_curve::rand_core::{self, CryptoRng, RngCore};
use p256::EncodedPoint;
use sha2::Sha256;

use crate::constants::{AES_KEY_LEN, GCM_IV_LEN, GCM_TAG_LEN, HKDF_OUTPUT_LEN, SERVER_PUBKEY_LEN};
use crate::token::{assemble_token, build_payload, TOKEN_VERSION};

/// Errors surfaced by the token pipeline.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// Server public key is not a 65-byte uncompressed SEC1 P-256 point
    /// (`0x04 || X || Y`) — checked where `_encryptData` validates
    /// `devicePubKeyData`/`ecdhPubLen` (DeviceCheckError -2).
    #[error("server public key must be a 65-byte uncompressed SEC1 P-256 point (0x04 || X || Y)")]
    InvalidServerPubKey,
    /// Ephemeral public key is not a 65-byte uncompressed SEC1 P-256 point.
    #[error("ephemeral public key must be a 65-byte uncompressed SEC1 P-256 point (0x04 || X || Y)")]
    InvalidEphemeralKey,
    /// Token payload length field does not match the ciphertext extent, or
    /// the payload does not follow the `_encryptData` layout.
    #[error("payload does not match the _encryptData token layout (154 + payload_len bytes)")]
    InvalidPayload,
    /// Primitive crypto failure (HKDF/AES-GCM), message mirrors the
    /// `DeviceCheckError` NSError the daemon would return.
    #[error("crypto failure: {0}")]
    Crypto(String),
    /// A buffer is too small to hold the required layout (token minimum is
    /// 235 bytes; the daemon returned `DeviceCheckError` -1 for the
    /// equivalent allocation failures).
    #[error("buffer too small for a DeviceCheck token (minimum 235 bytes)")]
    BufferTooSmall,
}

/// OS-entropy RNG backing [`generate_ephemeral`].
///
/// `p256`'s ecdh API needs a `rand_core::CryptoRngCore`, but the workspace's
/// `rand_core` is pulled in without the `getrandom` feature (elliptic-curve
/// depends on it with `default-features = false`), so `OsRng` is not
/// available and adding `rand`/`rand_core`/`getrandom` as direct deps is
/// out of scope. We therefore read entropy straight from `/dev/urandom` via
/// std and implement the trait by hand.
struct OsUrandom;

impl OsUrandom {
    fn fill_from_os(dest: &mut [u8]) -> std::io::Result<()> {
        let mut f = File::open("/dev/urandom")?;
        f.read_exact(dest)
    }
}

impl RngCore for OsUrandom {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        Self::fill_from_os(dest).expect("failed to read entropy from /dev/urandom");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Self::fill_from_os(dest).map_err(rand_core::Error::new)
    }
}

impl CryptoRng for OsUrandom {}

/// Generate the ephemeral ECDH keypair used for the token.
///
/// Stand-in for the AppleKeyStore call chain
/// `aks_ref_key_create(keybag, 11, 4, 0, 0, &refKey)` +
/// `aks_ref_key_get_public_key(refKey, &len)` (which must return exactly 65
/// bytes, else `DeviceCheckError` -2): here a software P-256 keypair is
/// generated from `/dev/urandom`.
///
/// Returns the secret plus the public key as a 65-byte uncompressed SEC1
/// point (`0x04 || X || Y`). `p256::EncodedPoint` produced via
/// `EncodedPoint::from(public_key)` is uncompressed by default, matching the
/// `aks_ref_key_get_public_key` encoding.
///
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3.
pub fn generate_ephemeral() -> (EphemeralSecret, [u8; SERVER_PUBKEY_LEN]) {
    let mut rng = OsUrandom;
    let secret = EphemeralSecret::random(&mut rng);
    let point = EncodedPoint::from(secret.public_key());

    let mut pk = [0u8; SERVER_PUBKEY_LEN];
    pk.copy_from_slice(point.as_bytes());
    (secret, pk)
}

/// Compute the ECDH shared secret between the ephemeral key and the server
/// public key (`aks_ref_key_compute_key(refKey, 0, 0, devicePubBytes,
/// devicePubLen)` in the README).
///
/// `server_pk` must be the 65-byte uncompressed SEC1 encoding of the server
/// P-256 point (the MESU asset `com.apple.devicecheck.pubvalue` value or the
/// hard-coded fallback key).
///
/// NOTE on the README's "+2 offset": the writeup reads the aks shared-secret
/// buffer as `sharedSecret = (uint8_t *)refKey + 2` with
/// `sharedLen = devicePubLen - 2`, and the comment "skip first 2 bytes (per
/// disassembly analysis)". That is internally inconsistent as written: the
/// `0x04` uncompressed-point prefix it alludes to is one byte, and
/// `65 - 2 = 63` is neither a raw 32-byte shared secret nor the 64-byte
/// `X || Y` tail. Rust's `p256::ecdh` returns the canonical shared secret:
/// the raw 32-byte x-coordinate (`SharedSecret::raw_secret_bytes`), which is
/// what an aks buffer would hold after any header bytes; [`derive_key_iv`]
/// HKDFs exactly the bytes it is handed, so either interpretation stays
/// reproducible.
///
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3.
pub fn ecdh_shared(secret: &EphemeralSecret, server_pk: &[u8]) -> Result<SharedSecret, TokenError> {
    if server_pk.len() != SERVER_PUBKEY_LEN {
        return Err(TokenError::InvalidServerPubKey);
    }
    let server_pub = p256::PublicKey::from_sec1_bytes(server_pk)
        .map_err(|_| TokenError::InvalidServerPubKey)?;
    // p256::ecdh::diffie_hellman(sc, affine) under the hood; the
    // EphemeralSecret method is the public way to reach it.
    Ok(secret.diffie_hellman(&server_pub))
}

/// Derive the AES-256 key (32 bytes) and GCM IV (12 bytes) from the ECDH
/// shared secret, mirroring
/// `cchkdf(ccsha256_di(), sharedLen, sharedSecret, 0, NULL, 0x2C, hkdfOut)`:
/// HKDF-SHA256 with an empty salt (the call passes `saltLen = 0, NULL`) and
/// an empty info string, expanding to 44 bytes (`0x2C`), split as
/// `hkdfOut[0..32] = aesKey`, `hkdfOut[32..44] = aesIV`.
///
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3.
pub fn derive_key_iv(shared: &[u8]) -> ([u8; AES_KEY_LEN], [u8; GCM_IV_LEN]) {
    // Hkdf::new(None, ikm) == extract with an empty/zero salt, matching
    // cchkdf's saltLen=0/NULL invocation.
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut okm = [0u8; HKDF_OUTPUT_LEN];
    hk.expand(&[], &mut okm)
        .expect("HKDF-SHA256 expand to 44 bytes is always valid (44 < 255 * 32)");

    let mut key = [0u8; AES_KEY_LEN];
    key.copy_from_slice(&okm[..AES_KEY_LEN]);
    let mut iv = [0u8; GCM_IV_LEN];
    iv.copy_from_slice(&okm[AES_KEY_LEN..HKDF_OUTPUT_LEN]);
    (key, iv)
}

/// Encrypt the plaintext payload with AES-256-GCM, mirroring
/// `ccgcm_one_shot(gcm, 32, aesKey, 12, aesIV, 0, NULL, payloadLen,
/// payloadBuf, outBuf + 154, 16, outBuf + 1)`: 256-bit key, 12-byte IV, no
/// AAD, 16-byte tag.
///
/// Returns `(ciphertext, tag)`; the caller places them at token offsets
/// +154 and +1 respectively via [`assemble_token`].
///
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3.
pub fn encrypt_payload(
    key: &[u8; AES_KEY_LEN],
    iv: &[u8; GCM_IV_LEN],
    payload: &[u8],
) -> Result<(Vec<u8>, [u8; GCM_TAG_LEN]), TokenError> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let nonce = GenericArray::from_slice(iv);

    let mut buffer = payload.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, b"", &mut buffer)
        .map_err(|e| TokenError::Crypto(format!("AES-256-GCM encrypt failed: {e}")))?;

    let mut tag_out = [0u8; GCM_TAG_LEN];
    tag_out.copy_from_slice(tag.as_slice());
    Ok((buffer, tag_out))
}

/// Run the full token pipeline end to end — the Rust equivalent of
/// `-[DCCertificateGenerator _encryptData:serverSyncedDate:error:]` with the
/// certificate chain already generated:
///
/// ephemeral keygen (aks ref key) → ECDH vs `server_pk` → HKDF-SHA256 →
/// payload build → AES-256-GCM → token assembly.
///
/// `server_pk` is the DeviceCheck server public key (65-byte uncompressed
/// SEC1 point): the MESU asset value or, in practice, the hard-coded
/// fallback at offset 0xDC50 of DeviceCheckInternal (see
/// [`crate::constants::FALLBACK_SERVER_PUBKEY_HEX`]).
///
/// NOTE on the token's "+5 static public key" slot: the README's
/// `_encryptData` copies `self.publicKey` — the same fetched server key used
/// as the ECDH peer — into `outBuf + 5` (labelled "device's static public
/// key" in the writeup's comments). In the real daemon the long-term
/// identity material lives in the system keychain (service "2bit-identity",
/// system group `systemgroup.com.apple.mobileactivationd`); this port
/// follows the README literally and uses `server_pk` for both the ECDH peer
/// and the +5 copy. Callers that hold a distinct static key can assemble a
/// token themselves via [`assemble_token`], which takes `static_pk` as an
/// explicit argument.
///
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3.
pub fn generate_token(
    server_pk: &[u8],
    cert_chain: &[u8],
    app_id: &str,
    server_synced_date: u64,
) -> Result<Vec<u8>, TokenError> {
    if server_pk.len() != SERVER_PUBKEY_LEN {
        return Err(TokenError::InvalidServerPubKey);
    }

    let (eph_secret, eph_pk) = generate_ephemeral();
    let shared = ecdh_shared(&eph_secret, server_pk)?;
    let (key, iv) = derive_key_iv(shared.raw_secret_bytes());

    let payload = build_payload(cert_chain, app_id, server_synced_date);
    let (ciphertext, tag) = encrypt_payload(&key, &iv, &payload)?;

    let mut static_pk = [0u8; SERVER_PUBKEY_LEN];
    static_pk.copy_from_slice(server_pk); // length checked above

    Ok(assemble_token(
        TOKEN_VERSION,
        &tag,
        &static_pk,
        &eph_pk,
        &ciphertext,
    ))
}
