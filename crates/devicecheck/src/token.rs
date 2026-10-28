//! token — DeviceCheck token buffer layout, transcribed from the README's
//! reconstruction of `-[DCCertificateGenerator _encryptData:serverSyncedDate:error:]`.
//!
//! Two buffers are involved (README, Chapter 3):
//!
//! * the **plaintext payload** (length `cert_chain_len + app_id_len + 81`),
//!   built by [`build_payload`] and fed to AES-256-GCM as the message;
//! * the **output token** (length `cert_chain_len + app_id_len + 235`, i.e.
//!   `payload_len + 154`), assembled by [`assemble_token`] around the GCM
//!   ciphertext and tag.
//!
//! Byte-exact layout below. All multi-byte fields are written by the README
//! with plain C stores (`*((uint32_t *)ptr) = v;`), i.e. **native-endian
//! stores on arm64 (little-endian)**; no `OSSwap`/`htobe` calls appear in the
//! writeup, so this port uses little-endian. Flagged as an ambiguity: if the
//! real daemon byte-swapped, only a server-side parser would show it, but the
//! README literally shows native stores.
//!
//! Parity: `-[DCCertificateGenerator _encryptData:serverSyncedDate:error:]`
//! buffer construction (DeviceCheckInternal.framework).
//! Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3.

use crate::constants::{GCM_TAG_LEN, SERVER_PUBKEY_LEN};
use crate::crypto::TokenError;

/// Version/type value stored at token offset +0. The README writes it as a
/// u32 store `*((uint32_t *)outBuf) = 2;` — see [`assemble_token`] for the
/// overlap analysis.
pub const TOKEN_VERSION: u8 = 2;

// --- plaintext payload offsets (README `_encryptData`, payloadBuf) ---------
//
//   +0   .. +65  : 65 zero bytes (calloc'd, never written — reason unknown
//                  from the RE; reserved/legacy padding)
//   +65  .. +73  : u64 server-synced timestamp, epoch seconds
//                  `*((uint64_t *)(payloadBuf + 65)) = (uint64_t)timestamp;`
//   +73  .. +77  : u32 cert-chain length
//                  `*((uint32_t *)(payloadBuf + 73)) = (uint32_t)inputLen;`
//   +77  .. +81  : u32 client-app-id length
//                  `*((uint32_t *)(payloadBuf + 77)) = (uint32_t)clientAppLen;`
//   +81  .. +81+n: cert chain bytes   (`memcpy(payloadBuf + 81, ...)`)
//   next m bytes : app id UTF-8 bytes (`memcpy(payloadBuf + 81 + inputLen, ...)`)

/// Payload offset of the u64 server-synced timestamp.
pub const PAYLOAD_TIMESTAMP_OFF: usize = 65;
/// Payload offset of the u32 certificate-chain length.
pub const PAYLOAD_CERT_CHAIN_LEN_OFF: usize = 73;
/// Payload offset of the u32 client-app-id length.
pub const PAYLOAD_APP_ID_LEN_OFF: usize = 77;
/// Payload offset where cert chain || app id bytes begin.
pub const PAYLOAD_BODY_OFF: usize = 81;
/// Fixed 81-byte payload prefix (65 zero bytes + 8 + 4 + 4 length fields);
/// `size_t payloadLen = inputLen + clientAppLen + 81;`.
pub const PAYLOAD_HEADER_LEN: usize = 81;

// --- token offsets (README `_encryptData`, outBuf) --------------------------
//
// README write order (must be reproduced — two writes overlap destructively,
// and which write wins depends on the order):
//
//   1. `*((uint32_t *)outBuf) = 2;`
//   2. `*((uint32_t *)(outBuf + 150)) = (uint32_t)payloadLen;`
//   3. `memcpy(outBuf + 5, devicePubKeyData.bytes, devicePubKeyData.length);`
//   4. `memcpy(outBuf + 85, ecdhPub, ecdhPubLen);`
//   5. `ccgcm_one_shot(..., payloadLen, payloadBuf, outBuf + 154, 16, outBuf + 1);`
//      — ciphertext at +154, and the 16-byte tag at +1 written LAST.
//
// Final (persisted) layout:
//
//   +0   .. +1   : version/type. The README's u32 store `= 2` has its upper
//                  three bytes clobbered by the tag written in step 5, so
//                  persisted tokens carry only the low byte (0x02) at +0 —
//                  the "version" is in practice a 1-byte type field.
//   +1   .. +17  : 16-byte AES-256-GCM tag (intact; written last)
//                  (`ccgcm_one_shot(..., 16, outBuf + 1)`)
//   +5   .. +70  : device "static" public key, 65 bytes
//                  `memcpy(outBuf + 5, devicePubKeyData.bytes, ...)`
//                  NOTE 1: the README copies `self.publicKey` here — the same
//                  fetched server key that is used as the ECDH peer. In the
//                  real daemon the long-term identity key material lives in
//                  the system keychain (service "2bit-identity", see
//                  [`crate::constants::KEYCHAIN_SERVICE`]).
//                  NOTE 2 (destructive overlap): the tag written LAST in
//                  step 5 lands on +1..+17 and therefore overwrites the
//                  static key's first 12 bytes (+5..+17 = tag[4..16] in the
//                  final token); only static_pk[12..64] survives at
//                  +17..+70. Harmless for the protocol — the server knows
//                  its own public key, and the field it actually needs (the
//                  ephemeral key at +85) is untouched — but the +5 slot
//                  cannot be read back verbatim from a real token.
//   +70  .. +85  : 15 zero bytes — gap left by `calloc` (the static key ends
//                  at +70, the ephemeral key starts at +85; never written by
//                  the reconstructed function)
//   +85  .. +150 : ephemeral ECDH public key, 65 bytes
//                  `memcpy(outBuf + 85, ecdhPub, ecdhPubLen);`
//   +150 .. +154 : u32 payload length
//                  `*((uint32_t *)(outBuf + 150)) = (uint32_t)payloadLen;`
//   +154 .. end  : GCM ciphertext of the payload (payloadLen bytes)
//                  (`ccgcm_one_shot(..., payloadLen, payloadBuf, outBuf + 154, ...)`)

/// Token offset of the 16-byte AES-GCM tag.
pub const TOKEN_TAG_OFF: usize = 1;
/// Token offset of the device static public key.
pub const TOKEN_STATIC_PK_OFF: usize = 5;
/// Token offset of the ephemeral ECDH public key.
pub const TOKEN_EPHEMERAL_PK_OFF: usize = 85;
/// Token offset of the u32 payload length field.
pub const TOKEN_PAYLOAD_LEN_OFF: usize = 150;
/// Token offset where the ciphertext begins.
pub const TOKEN_CIPHERTEXT_OFF: usize = 154;
/// Fixed token prefix: 154 bytes before the ciphertext
/// (`outputLen = inputLen + clientAppLen + 235 = payloadLen + 154`).
pub const TOKEN_HEADER_LEN: usize = 154;
/// Smallest possible token: 154-byte header + 81-byte minimum payload
/// (empty cert chain, empty app id).
pub const TOKEN_MIN_LEN: usize = TOKEN_HEADER_LEN + PAYLOAD_HEADER_LEN;

/// Copy `src` (which must be at least `N` bytes) into a fixed-size array.
fn copy_into<const N: usize>(src: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&src[..N]);
    out
}

/// Build the plaintext payload buffer exactly as `_encryptData` does, in the
/// README's write order (lengths and body first, timestamp last — the order
/// is unobservable since the offsets are distinct).
///
/// * `[0..65)` stays zero (calloc'd prefix, never written).
/// * `+65`: `server_synced_date` as u64. The README derives it from
///   `[serverDate timeIntervalSince1970]` (an `NSTimeInterval`, fractional
///   seconds) truncated by a `(uint64_t)` cast; this port takes whole epoch
///   seconds directly.
/// * `+73`/`+77`: cert-chain and app-id lengths (u32 LE).
/// * `+81`: cert chain bytes, then app-id UTF-8 bytes.
///
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3.
pub fn build_payload(cert_chain: &[u8], app_id: &str, server_synced_date: u64) -> Vec<u8> {
    let app_id = app_id.as_bytes();
    let cert_chain_len =
        u32::try_from(cert_chain.len()).expect("cert chain length exceeds u32 (README stores u32)");
    let app_id_len =
        u32::try_from(app_id.len()).expect("app id length exceeds u32 (README stores u32)");

    let mut payload = vec![0u8; cert_chain.len() + app_id.len() + PAYLOAD_HEADER_LEN];

    // README write order:
    //   *((uint32_t *)(payloadBuf + 73)) = (uint32_t)inputLen;
    //   memcpy(payloadBuf + 81, inputBytes, inputLen);
    //   *((uint32_t *)(payloadBuf + 77)) = (uint32_t)clientAppLen;
    //   memcpy(payloadBuf + 81 + inputLen, clientAppBytes, clientAppLen);
    //   *((uint64_t *)(payloadBuf + 65)) = (uint64_t)timestamp;
    payload[PAYLOAD_CERT_CHAIN_LEN_OFF..PAYLOAD_CERT_CHAIN_LEN_OFF + 4]
        .copy_from_slice(&cert_chain_len.to_le_bytes());
    payload[PAYLOAD_BODY_OFF..PAYLOAD_BODY_OFF + cert_chain.len()].copy_from_slice(cert_chain);
    payload[PAYLOAD_APP_ID_LEN_OFF..PAYLOAD_APP_ID_LEN_OFF + 4]
        .copy_from_slice(&app_id_len.to_le_bytes());
    payload[PAYLOAD_BODY_OFF + cert_chain.len()..].copy_from_slice(app_id);
    payload[PAYLOAD_TIMESTAMP_OFF..PAYLOAD_TIMESTAMP_OFF + 8]
        .copy_from_slice(&server_synced_date.to_le_bytes());

    payload
}

/// Assemble the output token buffer around the GCM ciphertext and tag,
/// reproducing `_encryptData`'s writes to `outBuf` byte-for-byte — including
/// their order, because the final buffer is order-dependent:
///
/// 1. version u32 LE at +0 (`*((uint32_t *)outBuf) = 2;`)
/// 2. payload length u32 LE at +150 (`*((uint32_t *)(outBuf + 150)) = payloadLen;`)
/// 3. static public key at +5..+70 (`memcpy(outBuf + 5, ...)`)
/// 4. ephemeral public key at +85..+150 (`memcpy(outBuf + 85, ...)`)
/// 5. ciphertext at +154.. and then the tag at +1..+17, written LAST exactly
///    as `ccgcm_one_shot(..., outBuf + 154, 16, outBuf + 1)` does.
///
/// Step 5 clobbers two earlier writes (documented quirk of the README
/// layout, reproduced on purpose):
///
/// * the version u32 loses its upper three bytes — only the low byte
///   (0x02 for [`TOKEN_VERSION`]) survives at +0, so the "version" is in
///   practice a 1-byte type field;
/// * the tag overwrites `static_pk[0..12]` (the tag's bytes 4..16 land at
///   +5..+17), so only `static_pk[12..64]` survives at +17..+70. Harmless
///   for the protocol (the server knows its own key) but the +5 slot is not
///   recoverable verbatim from the final token.
///
/// Total length: `payload.len() + 154` == `cert_chain_len + app_id_len + 235`.
///
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3.
pub fn assemble_token(
    version_byte: u8,
    tag: &[u8; GCM_TAG_LEN],
    static_pk: &[u8; SERVER_PUBKEY_LEN],
    ephemeral_pk: &[u8; SERVER_PUBKEY_LEN],
    payload: &[u8],
) -> Vec<u8> {
    let payload_len =
        u32::try_from(payload.len()).expect("payload length exceeds u32 (README stores u32)");

    let mut out = vec![0u8; payload.len() + TOKEN_HEADER_LEN];

    // 1. *((uint32_t *)outBuf) = 2;            (native/LE store)
    out[0..4].copy_from_slice(&u32::from(version_byte).to_le_bytes());
    // 2. *((uint32_t *)(outBuf + 150)) = (uint32_t)payloadLen;
    out[TOKEN_PAYLOAD_LEN_OFF..TOKEN_PAYLOAD_LEN_OFF + 4]
        .copy_from_slice(&payload_len.to_le_bytes());
    // 3. memcpy(outBuf + 5, devicePubKeyData.bytes, devicePubKeyData.length);
    out[TOKEN_STATIC_PK_OFF..TOKEN_STATIC_PK_OFF + SERVER_PUBKEY_LEN].copy_from_slice(static_pk);
    // 4. memcpy(outBuf + 85, ecdhPub, ecdhPubLen);
    out[TOKEN_EPHEMERAL_PK_OFF..TOKEN_EPHEMERAL_PK_OFF + SERVER_PUBKEY_LEN]
        .copy_from_slice(ephemeral_pk);
    // outBuf[70..85] remains zero (calloc gap in the README layout)
    // 5. ccgcm_one_shot(..., payloadLen, payloadBuf, outBuf + 154, 16, outBuf + 1);
    //    — ciphertext first, then the tag; written last, clobbering
    //    out[1..4] of the version u32 and out[5..17] of the static key.
    out[TOKEN_CIPHERTEXT_OFF..].copy_from_slice(payload);
    out[TOKEN_TAG_OFF..TOKEN_TAG_OFF + GCM_TAG_LEN].copy_from_slice(tag);

    out
}

/// Decoded view of a token produced by [`parse_token`].
///
/// The three fixed regions (`tag`, `static_pk`, `ephemeral_pk`) are copied
/// out; `ciphertext` borrows the input token. The 15-byte zero gap at
/// +70..+85 is not surfaced (it is calloc residue in the README layout) and
/// is not validated by [`parse_token`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenView<'a> {
    /// Version/type byte at +0 (low byte of the README's u32 store; the
    /// upper three bytes are tag ciphertext in persisted tokens).
    pub version_byte: u8,
    /// 16-byte AES-256-GCM tag (+1..+17).
    pub tag: [u8; GCM_TAG_LEN],
    /// Device "static" public key slot as it appears in the final token at
    /// +5 (65 bytes). Per the README write order the GCM tag written to +1
    /// lands after the static-key memcpy, so the first 12 bytes of this view
    /// hold tag bytes 4..16 and only the key's bytes 12..64 survive (at
    /// token offsets +17..+70); see [`assemble_token`].
    pub static_pk: [u8; SERVER_PUBKEY_LEN],
    /// Ephemeral ECDH public key at +85 (65 bytes).
    pub ephemeral_pk: [u8; SERVER_PUBKEY_LEN],
    /// u32 payload length read at +150 (LE); equals
    /// `81 + cert_chain_len + app_id_len`.
    pub payload_len: u32,
    /// GCM ciphertext at +154..end (decrypts to the [`build_payload`]
    /// plaintext under the ECDH-derived key/IV).
    pub ciphertext: &'a [u8],
}

/// Parse a token back into its fields, validating the README layout
/// structurally: `len >= 235` (minimum: 154-byte header + 81-byte minimum
/// payload) and `len == 154 + payload_len`.
///
/// Fields are decoded as they appear in the persisted buffer; note the
/// documented overlaps ([`assemble_token`]): the tag at +1..+17 is intact,
/// the version byte at +0 is the surviving low byte of the README's u32
/// store, and `TokenView::static_pk`'s first 12 bytes hold tag bytes.
///
/// Returns [`TokenError::BufferTooSmall`] for tokens shorter than 235 bytes
/// and [`TokenError::InvalidPayload`] when the embedded payload length does
/// not match the actual ciphertext extent.
///
/// Source: andrd3v/dcdev README (devicecheckd RE), Chapter 3.
pub fn parse_token(token: &[u8]) -> Result<TokenView<'_>, TokenError> {
    if token.len() < TOKEN_MIN_LEN {
        return Err(TokenError::BufferTooSmall);
    }

    let version_byte = token[0];
    let tag = copy_into::<GCM_TAG_LEN>(&token[TOKEN_TAG_OFF..]);
    let static_pk = copy_into::<SERVER_PUBKEY_LEN>(&token[TOKEN_STATIC_PK_OFF..]);
    let ephemeral_pk = copy_into::<SERVER_PUBKEY_LEN>(&token[TOKEN_EPHEMERAL_PK_OFF..]);
    let payload_len = u32::from_le_bytes(copy_into::<4>(&token[TOKEN_PAYLOAD_LEN_OFF..]));

    if token.len() != TOKEN_HEADER_LEN + payload_len as usize {
        return Err(TokenError::InvalidPayload);
    }

    Ok(TokenView {
        version_byte,
        tag,
        static_pk,
        ephemeral_pk,
        payload_len,
        ciphertext: &token[TOKEN_CIPHERTEXT_OFF..],
    })
}
