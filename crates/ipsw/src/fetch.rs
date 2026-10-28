//! IPSW ranged fetch — HTTP Range requests against Apple/AutoFS-style IPSW
//! servers (the `ipsw.rs`/remotezip.py workbench pattern, Rust-ified).
//! Only the metadata probe + range reader; resume = ledger item.

use anyhow::Result;
use std::io::Read;

pub struct RangedFetch {
    pub url: String,
    pub client: reqwest::Client,
}

impl RangedFetch {
    pub fn new(url: String) -> Self {
        Self {
            url,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .expect("client"),
        }
    }

    /// Probe total size (HEAD Content-Length).
    pub async fn probe_size(&self) -> Result<u64> {
        let resp = self.client.head(&self.url).send().await?;
        Ok(resp.content_length().unwrap_or(0))
    }

    /// Read `len` bytes at `offset` (Range: bytes=offset-(offset+len-1)).
    pub async fn read_range(&self, offset: u64, len: u64) -> Result<Vec<u8>> {
        let end = offset + len.saturating_sub(1);
        let resp = self
            .client
            .get(&self.url)
            .header("Range", format!("bytes={offset}-{end}"))
            .send()
            .await?;
        if !resp.status().is_success() && resp.status() != reqwest::StatusCode::PARTIAL_CONTENT {
            anyhow::bail!("range fetch failed: HTTP {}", resp.status());
        }
        let bytes = resp.bytes().await?;
        let mut out = Vec::with_capacity(bytes.len());
        out.extend_from_slice(&bytes);
        Ok(out)
    }

    /// Locate a payload inside the file by reading a window and searching.
    /// (The workbench scans for IM4P magic inside the OTA/restore ramdisk.)
    pub async fn find_im4p_offsets(&self, window: u64) -> Result<Vec<u64>> {
        let size = self.probe_size().await?;
        let mut hits = Vec::new();
        let mut off = 0u64;
        while off < size {
            let len = window.min(size - off);
            let chunk = self.read_range(off, len).await?;
            let mut i = 0;
            while i + 4 <= chunk.len() {
                if &chunk[i..i + 4] == b"IM4P" {
                    hits.push(off + i as u64);
                }
                i += 1;
            }
            if size - off <= window {
                break;
            }
            off += window.saturating_sub(4); // overlap to avoid edge misses
        }
        Ok(hits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn find_magic_in_synthetic() {
        // Synthetic local test would need a server; keep unit-level:
        let buf = [0u8, b'I', b'M', b'4', b'P', 0u8];
        let hits: Vec<u64> = (0..buf.len() - 4)
            .filter(|&i| &buf[i..i + 4] == b"IM4P")
            .map(|i| i as u64)
            .collect();
        assert_eq!(hits, vec![1]);
        let _ = RangedFetch::new("http://127.0.0.1:1/nope.ipsw".into()); // construction only
    }
}
