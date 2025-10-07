//! Extracts and builds Nintendo DS ROMs.

#![feature(error_generic_member_access)]
#![warn(missing_docs)]
#![warn(clippy::disallowed_methods)]
#![expect(clippy::manual_is_multiple_of)]
#![allow(dead_code)]
#![allow(mismatched_lifetime_syntaxes)]

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
