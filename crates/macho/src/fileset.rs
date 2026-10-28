//! MH_FILESET kernelcache loading.
#[derive(Debug, Clone, Default)]
pub struct FilesetEntry {
    pub entry_id: String,
    pub vmaddr: u64,
    pub fileoff: u64,
}
