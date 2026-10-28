//! devices-db — Apple device database (ProductType -> boards -> CPID/BDID/platform/chip)
//! plus the ipsw.me firmware catalog client.
//!
//! Parity: see PARITY.md rows `devices-db`.
//! Source: blacktop/ipsw pkg/info/data/ipsw_db.json (db), internal/download/ipsw_me.go (client)

pub mod db;
pub mod ipsw_me;
