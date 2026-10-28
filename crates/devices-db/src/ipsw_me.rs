//! ipsw_me — client for the ipsw.me firmware catalog (api.ipsw.me/v4).
//!
//! Maps the public REST API onto typed entries: device identity (CPID/BDID/board
//! config) plus per-device firmware builds with download URLs and checksums.
//!
//! Parity: blacktop/ipsw internal/download/ipsw_me.go
//! Source: https://api.ipsw.me/v4 (GET /devices, /device/{id}, /ipsw/{version}, /ipsw/{id}/{build})

use anyhow::Context;
use serde::Deserialize;

const BASE_URL: &str = "https://api.ipsw.me/v4";
const USER_AGENT: &str = "ios-rust (github.com/20kiwy/ios-rust)";

/// A firmware (IPSW) build as reported by ipsw.me.
#[derive(Debug, Clone, Deserialize)]
pub struct Firmware {
    pub identifier: String,
    pub version: String,
    #[serde(rename = "buildid")]
    pub build_id: String,
    #[serde(rename = "sha1sum")]
    pub sha1: String,
    #[serde(rename = "md5sum")]
    pub md5: String,
    #[serde(rename = "filesize")]
    pub file_size: u64,
    pub url: String,
    #[serde(rename = "releasedate")]
    pub release_date: String,
    #[serde(rename = "uploaddate")]
    pub upload_date: String,
    /// ipsw.me omits `signed` on some endpoints; treat missing as unsigned
    /// (matches the Go zero value in the upstream client).
    #[serde(default)]
    pub signed: bool,
}

/// A device entry: silicon identity plus its firmware catalog.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceEntry {
    pub name: String,
    pub identifier: String,
    /// Board config, e.g. "N104AP". ipsw.me serves this key lowercase; the alias
    /// keeps capitalized payloads from older API revisions working.
    #[serde(rename = "boardconfig", alias = "BoardConfig", default)]
    pub board_config: String,
    pub platform: String,
    #[serde(rename = "cpid")]
    pub cpid: i64,
    #[serde(rename = "bdid")]
    pub bdid: i64,
    /// Only populated by `/device/{id}`; `/devices` omits it entirely.
    #[serde(default)]
    pub firmwares: Vec<Firmware>,
}

/// HTTP client for api.ipsw.me/v4.
pub struct IpswMeClient {
    base: String,
    http: reqwest::Client,
}

impl Default for IpswMeClient {
    fn default() -> Self {
        Self::new()
    }
}

impl IpswMeClient {
    /// Client pointed at the public api.ipsw.me/v4 endpoint with the ios-rust
    /// User-Agent (ipsw.me asks for identifiable agents).
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .build()
            .expect("devices-db: building the reqwest client with static settings cannot fail");
        Self {
            base: BASE_URL.to_string(),
            http,
        }
    }

    /// GET /devices — the full device list (identity only, no firmware catalogs).
    pub async fn devices(&self) -> anyhow::Result<Vec<DeviceEntry>> {
        let url = format!("{}/devices", self.base);
        let list: Vec<DeviceEntry> = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?
            .error_for_status()
            .with_context(|| format!("GET {url}"))?
            .json()
            .await
            .with_context(|| format!("GET {url}: decoding device list"))?;
        Ok(list)
    }

    /// GET /device/{id} — one device including its firmware catalog.
    pub async fn device(&self, id: &str) -> anyhow::Result<DeviceEntry> {
        let url = format!("{}/device/{id}", self.base);
        self.http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?
            .error_for_status()
            .with_context(|| format!("GET {url}"))?
            .json()
            .await
            .with_context(|| format!("GET {url}: decoding device {id}"))
    }

    /// GET /ipsw/{version} — every firmware shipped in an iOS version.
    pub async fn ipsw_for_version(&self, version: &str) -> anyhow::Result<Vec<Firmware>> {
        let url = format!("{}/ipsw/{version}", self.base);
        let list: Vec<Firmware> = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?
            .error_for_status()
            .with_context(|| format!("GET {url}"))?
            .json()
            .await
            .with_context(|| format!("GET {url}: decoding firmwares for version {version}"))?;
        Ok(list)
    }

    /// GET /ipsw/{id}/{build} — one firmware for a device identifier + build id.
    pub async fn ipsw(&self, id: &str, build: &str) -> anyhow::Result<Firmware> {
        let url = format!("{}/ipsw/{id}/{build}", self.base);
        self.http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?
            .error_for_status()
            .with_context(|| format!("GET {url}"))?
            .json()
            .await
            .with_context(|| format!("GET {url}: decoding firmware {id} build {build}"))
    }

    /// Blocking variant of [`IpswMeClient::devices`] (spins a multi-thread runtime).
    pub fn devices_blocking(self) -> anyhow::Result<Vec<DeviceEntry>> {
        tokio::runtime::Runtime::new()?.block_on(self.devices())
    }

    /// Blocking variant of [`IpswMeClient::device`].
    pub fn device_blocking(self, id: &str) -> anyhow::Result<DeviceEntry> {
        tokio::runtime::Runtime::new()?.block_on(self.device(id))
    }

    /// Blocking variant of [`IpswMeClient::ipsw_for_version`].
    pub fn ipsw_for_version_blocking(self, version: &str) -> anyhow::Result<Vec<Firmware>> {
        tokio::runtime::Runtime::new()?.block_on(self.ipsw_for_version(version))
    }

    /// Blocking variant of [`IpswMeClient::ipsw`].
    pub fn ipsw_blocking(self, id: &str, build: &str) -> anyhow::Result<Firmware> {
        tokio::runtime::Runtime::new()?.block_on(self.ipsw(id, build))
    }
}
