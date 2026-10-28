//! constants — string/blob constants lifted from `devicecheckd` and
//! `DeviceCheckInternal.framework`.
//!
//! Everything here is host-side constant data for the T8030 emulator stack:
//! the hard-coded fallback server public key, the MESU asset-catalog keys the
//! `DCAssetFetcher` queries, the XPC/endpoint strings, the keychain naming
//! scheme, and the numeric parameters of the AppleKeyStore / CommonCrypto
//! call chain used by `_encryptData`.
//!
//! Parity: devicecheckd + DeviceCheckInternal.framework string tables and
//! `-[DCAssetFetcher]` / `-[DCXPCActivityController]` / `-[DCClientHandler]`
//! constant usage (host constants, no logic mirrored here).
//! Source: andrd3v/dcdev README (devicecheckd RE), Chapters 1-3.

// ---------------------------------------------------------------------------
// Server public key (Chapter 2)
// ---------------------------------------------------------------------------

/// Hard-coded fallback DeviceCheck server public key.
///
/// Embedded in `__37__DCCryptoProxyImpl__fetchPublicKey___block_invoke` as
/// `+[NSData dataWithBytes:length:](&fallback_server_pubkey, 65)`; the blob
/// sits at offset `0xDC50` in the DeviceCheckInternal binary and is identical
/// across macOS, iOS and iPadOS builds (README, Chapter 2).
///
/// Encoding: 65-byte uncompressed SEC1 P-256 point (`0x04 || X || Y`).
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 2.
pub const FALLBACK_SERVER_PUBKEY_HEX: &str = "0450d934fa67bcf6f2dfbf96629e0a7238e9205d75f28cfcd84f35a6592bbe058a9c0f8edbca2acb67efb774971ca45f7d856a694fb1b9c40b94fb2e7a5a9498b0";

/// Length of [`FALLBACK_SERVER_PUBKEY_HEX`] when decoded: 65 bytes
/// (uncompressed SEC1 P-256 point). AppleKeyStore's
/// `aks_ref_key_get_public_key` return value is checked against this same
/// length by `_encryptData` (README, Chapter 3, error code -2 on mismatch).
pub const SERVER_PUBKEY_LEN: usize = 65;

// ---------------------------------------------------------------------------
// MESU asset catalog (Chapter 2, DCAssetFetcher)
// ---------------------------------------------------------------------------

/// MESU asset catalog URL queried by `-[DCAssetFetcher _assetQuery]` for the
/// `com_apple_MobileAsset_DeviceCheck` asset type.
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 2.
pub const MESU_CATALOG_URL: &str = "https://mesu.apple.com/assets/com_apple_MobileAsset_DeviceCheck/com_apple_MobileAsset_DeviceCheck.xml";

/// Asset plist key holding the catalog format version; `-[DCAsset
/// assetWithMobileAsset:]` requires an `NSNumber` with integer value 1.
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 2.
pub const ASSET_KEY_VERSION: &str = "com.apple.MobileAsset.AssetVersion";

/// Required value of [`ASSET_KEY_VERSION`]; any other version makes
/// `assetWithMobileAsset:` return nil (=> fetcherror -3200).
pub const ASSET_REQUIRED_VERSION: i64 = 1;

/// Asset plist key holding the server public key as `NSData`
/// (`pubKeyData.length` must be non-zero).
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 2.
pub const ASSET_KEY_PUBVALUE: &str = "com.apple.devicecheck.pubvalue";

/// Asset plist key holding the public-key refresh interval (`NSNumber`,
/// seconds); feeds `-[DCXPCActivityController updateActivityScheduleWithAsset:]`.
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 2.
pub const ASSET_KEY_REFRESH_TIMER: &str = "com.apple.devicecheck.refreshtimer";

// ---------------------------------------------------------------------------
// XPC service and activity (Chapters 1-2)
// ---------------------------------------------------------------------------

/// Mach service name of the daemon (`NSXPCConnection
/// initWithMachServiceName:options:` from `-[DCDevice
/// generateTokenWithCompletionHandler:]`).
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 1.
pub const XPC_MACH_SERVICE: &str = "com.apple.devicecheckd";

/// `xpc_activity_register` name used by
/// `-[DCXPCActivityController updateActivityScheduleWithAsset:]` to schedule
/// periodic public-key refreshes.
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 2.
pub const XPC_ACTIVITY_NAME: &str = "com.apple.devicecheck.notify";

/// Activity criteria key: refresh interval (seconds, from
/// `com.apple.devicecheck.refreshtimer`).
pub const XPC_ACTIVITY_INTERVAL: &str = "xpc_activity_interval";

/// Activity criteria key: repeating activity (`@YES`).
pub const XPC_ACTIVITY_REPEATING: &str = "xpc_activity_repeating";

/// Activity criteria key: network required (`@YES`).
pub const XPC_ACTIVITY_REQUIRE_NETWORK: &str = "xpc_activity_require_network";

/// Selectors exposed by the `TDCDeviceMetadataDaemonConnection` XPC
/// interface that `DCXPCListener`/`DCClientHandler` dispatch on. The token
/// flow only exercises `fetchOpaqueBlobWithCompletion:`, the rest belong to
/// the App Attest / BAA / support surface of the same daemon.
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapters 1 and 3 context.
pub const XPC_INTERFACE_SELECTORS: &[&str] = &[
    "fetchOpaqueBlobWithCompletion:",
    "isSupportedDeviceWithCompletion:",
    "appAttestationCreateKey:completion:",
    "appAttestationAttestKey:keyId:clientDataHash:completion:",
    "appAttestationAssert:keyId:clientDataHash:completion:",
    "appAttestationIsSupportedWithCompletion:",
    "baaSignatureForData:completion:",
    "baaSignaturesForData:completion:",
];

// ---------------------------------------------------------------------------
// Error domains and codes (Chapters 2-3)
// ---------------------------------------------------------------------------

/// `NSError` domain used by the asset fetching path (`DCAssetFetcher`).
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 2.
pub const FETCH_ERROR_DOMAIN: &str = "com.apple.twobit.fetcherror";

/// `-[_handleSuccessForQuery:completion:]`: zero query results.
pub const FETCH_ERR_NO_RESULTS: i64 = -3100;

/// `-[_handleMissingMetadataWithContext:completion:]`: asset catalog missing
/// and refresh not allowed.
pub const FETCH_ERR_CATALOG_MISSING: i64 = -3101;

/// `-_validateAsset:error:` / `assetWithMobileAsset:` returned nil.
pub const FETCH_ERR_ASSET_VALIDATION: i64 = -3200;

/// `-[_queryMetadataWithContext:completion:]` metadata-missing sentinel.
/// The README shows the literal `0xFFFFFFFFFFFFF448`, i.e. -3000 in
/// two's complement; transcribed as written.
pub const FETCH_ERR_METADATA_MISSING: i64 = 0xFFFFFFFFFFFFF448u64 as i64;

/// `NSError` domain used inside `-[DCCertificateGenerator
/// _encryptData:serverSyncedDate:error:]` for the alloc / key-size / aks /
/// GCM failures below.
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3.
pub const DEVICECHECK_ERROR_DOMAIN: &str = "DeviceCheckError";

/// `DeviceCheckError` code: `calloc` failure for the output or payload buffer.
pub const DEVICECHECK_ERR_ALLOC: i64 = -1;

/// `DeviceCheckError` code: `aks_ref_key_get_public_key` returned a length
/// other than 65.
pub const DEVICECHECK_ERR_PUBKEY_SIZE: i64 = -2;

// ---------------------------------------------------------------------------
// Keychain naming (Chapters 1 and 3)
// ---------------------------------------------------------------------------

/// Keychain service under which the two-bit identity items live
/// (`SecItemAdd`/`SecItemCopyMatching` service attribute).
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3 context.
pub const KEYCHAIN_SERVICE: &str = "2bit-identity";

/// Keychain access groups declared by devicecheckd's entitlements (see
/// [`crate::entitlements`]). Note the first entry is spelled
/// `lockdown-identities`.
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3 context.
pub const KEYCHAIN_ACCESS_GROUPS: &[&str] = &[
    "lockdown-identities",
    "2bit-identity",
    "com.apple.appattest.identities",
];

/// System keychain group shared with mobileactivationd
/// (`com.apple.security.system-groups` entitlement).
pub const KEYCHAIN_SYSTEM_GROUP: &str = "systemgroup.com.apple.mobileactivationd";

/// Keychain item label suffixes used by the identity store: items are named
/// `"<label><suffix>"` with `label` derived from the client identity.
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3 context.
pub const KEYCHAIN_ITEM_SUFFIXES: &[&str] = &[
    "-rk",
    "-leaf",
    "-intermediate",
    "-combined",
    "-monotonic-clock",
    "-server-timestamp",
    "-rtc-reset-count",
];

/// `CFPreferences`/defaults keys honored by the daemon.
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3 context.
pub const DEFAULTS_KEY_IGNORE_EXISTING_KEYCHAIN_ITEMS: &str = "kDCIgnoreExistingKeychainItems";
/// See [`DEFAULTS_KEY_IGNORE_EXISTING_KEYCHAIN_ITEMS`].
pub const DEFAULTS_KEY_ENABLE_EXTENDED_BINARY_LOGS: &str = "kDCEnableExtendedBinaryLogs";

// ---------------------------------------------------------------------------
// Humbug BAA endpoint (Chapter 3 context)
// ---------------------------------------------------------------------------

/// Apple "humbug" BAA (basic attestation) endpoint POSTed to when the daemon
/// needs server-side attestation plumbing.
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3 context.
pub const HUMBUG_BAA_URL: &str = "https://humb.apple.com/humbug/baa";

/// Content-Type of the humbug BAA request body.
pub const HUMBUG_CONTENT_TYPE: &str = "application/xml";

/// User-Agent presented to the humbug BAA endpoint.
pub const HUMBUG_USER_AGENT: &str = "iOS Device Activator (MobileActivation-832.2.1)";

/// HTTP header carrying the per-device identifier on humbug BAA requests.
pub const HUMBUG_HEADER_DEVICE_ID: &str = "x-jmet-deviceid";

// ---------------------------------------------------------------------------
// App ID rule (Chapter 1, DCClientHandler)
// ---------------------------------------------------------------------------

/// Team-ID sentinel: `-[DCClientHandler _generateAppIDFromCurrentConnection]`
/// builds `"<TeamID>.<BundleIdentifier>"` only when the team ID is present
/// (entitlement `application-identifier`, falling back to
/// `SecTaskCopyTeamIdentifier` + `SecTaskCopySigningIdentifier`) and is not
/// this all-zeros placeholder; otherwise the bare
/// `"<BundleIdentifier>"` is used.
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 1.
pub const TEAM_ID_PLACEHOLDER: &str = "0000000000";

/// Separator between team ID and bundle identifier in the client app ID.
pub const APP_ID_SEPARATOR: &str = ".";

// ---------------------------------------------------------------------------
// AppleKeyStore / CommonCrypto parameters (Chapter 3, _encryptData)
// ---------------------------------------------------------------------------

/// `aks_ref_key_create` argument block transcribed from the README's
/// `_encryptData`: `aks_ref_key_create(keybag, 11, 4, 0, 0, &refKey)`.
/// The `keybag` handle itself comes from `-[self keybagHandle]` at runtime
/// and is not a compile-time constant.
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3.
pub const AKS_REF_KEY_ARG1: i32 = 11;
/// See [`AKS_REF_KEY_ARG1`].
pub const AKS_REF_KEY_ARG2: i32 = 4;
/// See [`AKS_REF_KEY_ARG1`].
pub const AKS_REF_KEY_ARG3: i32 = 0;
/// See [`AKS_REF_KEY_ARG1`].
pub const AKS_REF_KEY_ARG4: i32 = 0;

/// Number of leading bytes the README says are skipped when reading the
/// AppleKeyStore ECDH shared-secret buffer:
/// `sharedSecret = (uint8_t *)refKey + 2; sharedLen = devicePubLen - 2`.
///
/// NOTE (apparent inconsistency, documented per the README as written): the
/// writeup's comment equates the `+2` with skipping the `0x04` uncompressed
/// point prefix, but `0x04` is a single byte and `65 - 2 = 63` bytes is not
/// the canonical 32-byte P-256 shared secret either. The Rust port feeds the
/// raw 32-byte x-coordinate produced by `p256::ecdh` into HKDF instead; see
/// `crate::crypto::ecdh_shared`.
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3.
pub const AKS_SHARED_SECRET_SKIP_BYTES: usize = 2;

/// HKDF output length: `cchkdf(ccsha256_di(), sharedLen, sharedSecret, 0,
/// NULL, 0x2C, hkdfOut)` — 44 bytes = 32-byte AES-256 key + 12-byte GCM IV.
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3.
pub const HKDF_OUTPUT_LEN: usize = 0x2C;

/// AES-256 key length carved from the front of the HKDF output.
pub const AES_KEY_LEN: usize = 32;

/// AES-GCM IV length carved from the tail of the HKDF output.
pub const GCM_IV_LEN: usize = 12;

/// AES-GCM tag length passed to `ccgcm_one_shot` (no AAD).
pub const GCM_TAG_LEN: usize = 16;
