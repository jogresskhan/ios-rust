//! Boot verdict records.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BootVerdict {
    pub repo: String,
    pub stage: String,
    pub passed: bool,
    pub detail: String,
    pub timestamp: String,
}
