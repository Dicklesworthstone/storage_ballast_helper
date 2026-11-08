//! Core types: errors, configuration, shared constants.

pub mod config;
pub mod errors;
pub(crate) mod path_serde;
pub mod paths;
pub mod update_cache;

/// User-Agent shared by outbound HTTP requests, including library notifications.
pub const HTTP_USER_AGENT: &str =
    "sbh (+https://github.com/Dicklesworthstone/storage_ballast_helper)";

/// Render bytes as lowercase hexadecimal without relying on digest display traits.
pub fn hex_lower(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}
