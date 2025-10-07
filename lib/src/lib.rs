//! Extracts and builds Nintendo DS ROMs.

#![feature(error_generic_member_access)]
#![warn(missing_docs)]
#![expect(dead_code)]
#![expect(mismatched_lifetime_syntaxes)]
#![expect(clippy::manual_is_multiple_of)]

/// Compression algorithms.
pub mod compress;
/// CRC checksum algorithms.
pub mod crc;
/// Encryption algorithms.
pub mod crypto;
pub(crate) mod io;
/// ROM structs.
pub mod rom;
/// String utilities.
pub mod str;
