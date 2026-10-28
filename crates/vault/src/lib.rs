//! vault — research S3 vault integration ("the research-s3").
//! Thin client for the research-vault service (20kiwy/research-vault-rs):
//! list / put (auto-chunk) / get / verify manifest sha256. The emulator
//! workspace uses it to pull research artifacts and push new verdicts.

pub mod client;
pub mod manifest;

pub use client::VaultClient;
