//! HTTP client against the research-vault service (RV_URL + RV_TOKEN).

use anyhow::{Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub struct VaultClient {
    pub base: String,
    pub token: String,
    pub chunk_mb: usize,
    http: reqwest::Client,
}

impl VaultClient {
    pub fn from_env() -> Result<Self> {
        let base = std::env::var("RV_URL").unwrap_or_else(|_| "http://127.0.0.1:3900".into());
        let token = std::env::var("RV_TOKEN").context("RV_TOKEN not set")?;
        Ok(Self::new(base, token))
    }

    pub fn new(base: String, token: String) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            token,
            chunk_mb: 64,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(900))
                .build()
                .expect("client"),
        }
    }

    fn auth(&self) -> String {
        format!("Bearer {}", self.token)
    }

    pub async fn health(&self) -> Result<Value> {
        Ok(self.http.get(format!("{}/healthz", self.base)).send().await?.json().await?)
    }

    pub async fn usage(&self) -> Result<Value> {
        let r = self
            .http
            .get(format!("{}/usage", self.base))
            .header("Authorization", self.auth())
            .send()
            .await?;
        Ok(r.json().await?)
    }

    pub async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let r = self
            .http
            .get(format!("{}/objects", self.base))
            .query(&[("prefix", prefix), ("limit", "5000")])
            .header("Authorization", self.auth())
            .send()
            .await?;
        let v: Value = r.json().await?;
        Ok(v["objects"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|o| o["key"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// GET with sha256 verification against the expected digest.
    pub async fn get_verified(&self, key: &str, expect_sha256: &str) -> Result<Vec<u8>> {
        let r = self
            .http
            .get(format!("{}/objects/{}", self.base, encode_key(key)))
            .header("Authorization", self.auth())
            .send()
            .await?;
        if !r.status().is_success() {
            anyhow::bail!("get {key}: HTTP {}", r.status());
        }
        let bytes = r.bytes().await?.to_vec();
        let mut h = Sha256::new();
        h.update(&bytes);
        let got = hex::encode(h.finalize());
        if got != expect_sha256 {
            anyhow::bail!("sha256 mismatch for {key}: got {got}");
        }
        Ok(bytes)
    }

    /// Raw GET without manifest verification (caller hashes).
    pub async fn raw_get(&self, key: &str) -> Result<reqwest::Response> {
        Ok(self
            .http
            .get(format!("{}/objects/{}", self.base, encode_key(key)))
            .header("Authorization", self.auth())
            .send()
            .await?)
    }

    /// PUT small objects (≤ chunk size); multipart for larger = ledger item.
    pub async fn put(&self, key: &str, data: Vec<u8>) -> Result<Value> {
        let mut h = Sha256::new();
        h.update(&data);
        let sha = hex::encode(h.finalize());
        let r = self
            .http
            .put(format!("{}/objects/{}", self.base, encode_key(key)))
            .header("Authorization", self.auth())
            .header("Content-Type", "application/octet-stream")
            .body(data)
            .send()
            .await?;
        let status = r.status();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            anyhow::bail!("put {key}: HTTP {status}: {v}");
        }
        let _ = sha;
        Ok(v)
    }
}

fn encode_key(key: &str) -> String {
    key.split('/')
        .map(|seg| {
            let mut out = String::new();
            for b in seg.bytes() {
                match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        out.push(b as char)
                    }
                    o => out.push_str(&format!("%{o:02X}")),
                }
            }
            out
        })
        .collect::<Vec<_>>()
        .join("/")
}
