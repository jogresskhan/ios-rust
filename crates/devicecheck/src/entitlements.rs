//! entitlements — extracted `devicecheckd` entitlements plist and the XPC
//! client allowlist, kept as fixture data for the emulator stack.
//!
//! The daemon's entitlements explain where its privileges come from: system
//! keychain access, the mobileactivationd bridge, MobileGestalt protected
//! keys, and the MESU `com.apple.MobileAsset.DeviceCheck` asset type used by
//! the `DCAssetFetcher` (README Chapter 2).
//!
//! Parity: devicecheckd embedded entitlements plist + `DCXPCListener` client
//! validation list.
//! Source: andrd3v/dcdev README (devicecheckd RE), Chapters 1-3.

/// Full extracted entitlements plist of `/usr/libexec/devicecheckd`, as an
/// XML property list string (dict of key/string | key/true | key/array).
///
/// Transcribed key-for-key:
///
/// * `application-identifier` = `com.apple.devicecheckd`
/// * `com.apple.appattest.spi` = true
/// * `com.apple.keystore.sik.access` = true
/// * `com.apple.mobileactivationd.bridge` = true
/// * `com.apple.mobileactivationd.device-identifiers` = true
/// * `com.apple.mobileactivationd.spi` = true
/// * `com.apple.private.MobileGestalt.AllowedProtectedKeys` =
///   `UniqueChipID`, `SerialNumber`
/// * `com.apple.private.assets.accessible-asset-types` =
///   `com.apple.MobileAsset.DeviceCheck`  (MESU asset fetch, README Ch. 2)
/// * `com.apple.private.security.bootpolicy` = true
/// * `com.apple.private.system-keychain` = true
/// * `com.apple.security.attestation.access` = true
/// * `com.apple.security.exception.mach-lookup.global-name` =
///   `com.apple.mobileactivationd`, `com.apple.lsd.xpc`
/// * `com.apple.security.system-groups` =
///   `systemgroup.com.apple.mobileactivationd`
/// * `keychain-access-groups` =
///   `lockdown-identities`, `2bit-identity`, `com.apple.appattest.identities`
/// * `platform-application` = true
/// * `seatbelt-profiles` = `devicecheckd`
///
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapters 1-3.
pub const DEVICECHECKD_ENTITLEMENTS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>application-identifier</key>
	<string>com.apple.devicecheckd</string>
	<key>com.apple.appattest.spi</key>
	<true/>
	<key>com.apple.keystore.sik.access</key>
	<true/>
	<key>com.apple.mobileactivationd.bridge</key>
	<true/>
	<key>com.apple.mobileactivationd.device-identifiers</key>
	<true/>
	<key>com.apple.mobileactivationd.spi</key>
	<true/>
	<key>com.apple.private.MobileGestalt.AllowedProtectedKeys</key>
	<array>
		<string>UniqueChipID</string>
		<string>SerialNumber</string>
	</array>
	<key>com.apple.private.assets.accessible-asset-types</key>
	<array>
		<string>com.apple.MobileAsset.DeviceCheck</string>
	</array>
	<key>com.apple.private.security.bootpolicy</key>
	<true/>
	<key>com.apple.private.system-keychain</key>
	<true/>
	<key>com.apple.security.attestation.access</key>
	<true/>
	<key>com.apple.security.exception.mach-lookup.global-name</key>
	<array>
		<string>com.apple.mobileactivationd</string>
		<string>com.apple.lsd.xpc</string>
	</array>
	<key>com.apple.security.system-groups</key>
	<array>
		<string>systemgroup.com.apple.mobileactivationd</string>
	</array>
	<key>keychain-access-groups</key>
	<array>
		<string>lockdown-identities</string>
		<string>2bit-identity</string>
		<string>com.apple.appattest.identities</string>
	</array>
	<key>platform-application</key>
	<true/>
	<key>seatbelt-profiles</key>
	<array>
		<string>devicecheckd</string>
	</array>
</dict>
</plist>
"#;

/// XPC clients the daemon's listener accepts connections from (the set
/// checked by `-[DCXPCListener listener:shouldAcceptNewConnection:]`).
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 1.
pub const CLIENT_ALLOWLIST: &[&str] = &[
    "devicecheckd",
    "mobileactivationd",
    "fairplaydeviceidentityd",
    "identityservicesd",
    "findmydeviced",
    "FindMyDeviceIdentityXPCService",
    "coreidvd",
    "idcredd",
    "nfcd",
    "passd",
    "lskdd",
    "remotemanagementd",
    "bluetoothd",
    "teslad",
    "itunesstored",
    "ProvenanceCombo",
    "ssetest",
    "seserviced",
    "repaird",
    "sharedfpd",
    "searchpartyd",
    "transparencyd",
];
