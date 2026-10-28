//! devicecheck — Rust port of Apple's `devicecheckd` DeviceCheck token
//! generation, reverse engineered end to end from `DCDevice` down to the
//! encrypted opaque blob.
//!
//! Daemon flow being mirrored (README, Chapters 1-3):
//!
//! 1. `-[DCDevice generateTokenWithCompletionHandler:]` opens an
//!    `NSXPCConnection` to the mach service `com.apple.devicecheckd`
//!    ([`constants::XPC_MACH_SERVICE`]) and calls
//!    `fetchOpaqueBlobWithCompletion:` on the
//!    `TDCDeviceMetadataDaemonConnection` interface.
//! 2. `-[DCClientHandler fetchOpaqueBlobWithCompletion]` checks
//!    `DeviceIdentityIsSupported` (hard-coded `return 1`), then
//!    `_generateAppIDFromCurrentConnection` builds the client app ID —
//!    `"<TeamID>.<BundleIdentifier>"` when the team ID is valid and not
//!    `"0000000000"`, else `"<BundleIdentifier>"` — and hands a
//!    `DCContext`/`DCDDeviceMetadata` pair to
//!    `generateEncryptedBlobWithCompletion:`.
//! 3. `-[DCCryptoProxyImpl fetchOpaqueBlobWithContext:completion:]` fetches
//!    the server public key via `-[DCAssetFetcher
//!    fetchPublicKeyAssetWithCompletion:]` (MESU catalog
//!    `com_apple_MobileAsset_DeviceCheck`, asset version 1, keys
//!    `com.apple.devicecheck.pubvalue` / `com.apple.devicecheck.refreshtimer`,
//!    with a `xpc_activity_register("com.apple.devicecheck.notify", ...)`
//!    refresh schedule) and falls back to the hard-coded 65-byte key
//!    embedded at offset 0xDC50 of DeviceCheckInternal
//!    ([`constants::FALLBACK_SERVER_PUBKEY_HEX`]).
//! 4. `-[DCCertificateGenerator _generateCertificateChainWithCompletion:]`
//!    pulls the two-certificate BAA chain ("Basic Attestation User Sub CA1"
//!    under "Basic Attestation User Root CA1") from the keychain via
//!    `DeviceIdentityIssueClientCertificateWithCompletion` (items named
//!    `"<label>-rk"/"-leaf"/-…` in service `2bit-identity`).
//! 5. `_encryptData:serverSyncedDate:error:` builds the token:
//!    ephemeral AppleKeyStore key (`aks_ref_key_create(keybag, 11, 4, 0, 0)`,
//!    `aks_ref_key_get_public_key` → 65 bytes, `aks_ref_key_compute_key`
//!    ECDH vs the server key), `cchkdf` HKDF-SHA256 to 44 bytes
//!    (32-byte AES-256 key + 12-byte GCM IV), payload
//!    `[65 zero bytes | u64 timestamp | u32 chain len | u32 app-id len |
//!    chain || app-id]`, `ccgcm_one_shot` AES-256-GCM (no AAD, 16-byte tag),
//!    and the final buffer
//!    `[u32 version=2 (clobbered to 1 byte by the tag) | tag@+1 |
//!    static key@+5 | gap | eph key@+85 | u32 payload len@+150 |
//!    ciphertext@+154]` — see [`token`] for the exact offsets.
//! 6. The blob travels back over XPC as the token apps receive from
//!    `DCDevice`.
//!
//! This crate implements the offline-cryptographic core (steps 5) plus the
//! constant surface of the daemon (steps 1-4) for the T8030 emulator stack;
//! XPC, keychain and MESU transports are out of scope here and live with the
//! surrounding emulator services.
//!
//! Parity: devicecheckd / DeviceCheckInternal.framework — `DCDevice` →
//! `DCClientHandler` → `DCCryptoProxyImpl` → `DCAssetFetcher` →
//! `DCCertificateGenerator::_encryptData` token pipeline.
//! Source: andrd3v/dcdev README (devicecheckd RE), Chapters 1-4.
//!
//! Start with:
//! * [`crypto::generate_token`] — full offline token pipeline.
//! * [`token::parse_token`] — decode a token back into its fields.
//! * [`constants`] / [`entitlements`] — extracted daemon constants.

pub mod constants;
pub mod crypto;
pub mod entitlements;
pub mod token;

pub use crypto::{
    derive_key_iv, ecdh_shared, encrypt_payload, generate_ephemeral, generate_token, TokenError,
};
pub use token::{assemble_token, build_payload, parse_token, TokenView};

/// Demo token built with the hard-coded fallback server public key, a fake
/// 100-byte DER-ish "certificate chain" of `0x30` bytes, the daemon's own
/// bundle ID as app ID, and epoch 2025-01-01T00:00:00Z — the byte-level
/// smoke path for the CLI (`demo` subcommand) without any keychain, MESU or
/// XPC involvement.
///
/// Every ingredient except the ephemeral key is fixed, so the token is
/// reproducible except for its ciphertext (fresh ephemeral key + timestamp
/// are baked into the layout).
///
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapters 2-3.
pub fn demo_token() -> Result<Vec<u8>, TokenError> {
    let mut server_pk = [0u8; constants::SERVER_PUBKEY_LEN];
    // Unreachable error arm: FALLBACK_SERVER_PUBKEY_HEX is a compile-time
    // known-good 65-byte hex string.
    hex::decode_to_slice(constants::FALLBACK_SERVER_PUBKEY_HEX, &mut server_pk)
        .map_err(|_| TokenError::InvalidServerPubKey)?;

    generate_token(
        &server_pk,
        &[0x30u8; 100],
        "com.apple.devicecheck.demo",
        1_735_689_600,
    )
}
