//! manifest.json reader for the vault (sha256 + size per object).

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VaultObject {
    pub key: String,
    #[serde(default)]
    #[serde(rename = "localPath")]
    pub local_path: Option<String>,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VaultManifest {
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
    pub vault: String,
    #[serde(rename = "objectCount")]
    pub object_count: u64,
    #[serde(rename = "totalHuman")]
    pub total_human: String,
    pub objects: Vec<VaultObject>,
}

pub fn parse(buf: &[u8]) -> Result<VaultManifest> {
    Ok(serde_json::from_slice(buf)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vault_manifest_shape() {
        let m: VaultManifest = serde_json::from_str(
            r#"{
              "generatedAt": "2026-10-28T00:00:00Z",
              "vault": "ios-research-vault",
              "objectCount": 1,
              "totalHuman": "1 B",
              "objects": [
                {"key": "research/reports/x.md", "sizeBytes": 3, "sha256": "abc"}
              ]
            }"#,
        )
        .unwrap();
        assert_eq!(m.objects[0].key, "research/reports/x.md");
        assert!(m.objects[0].local_path.is_none());
    }
}
