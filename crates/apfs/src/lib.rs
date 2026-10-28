//! apfs — reader + **writer** subset (X-row #5).
//!
//! Replaces the "APFS write operations" hole in the pure-Rust host: until
//! now every APFS path ran Apple's `apfs.fs` tools inside the ramdisk. This
//! crate brings the on-disk format into the workspace:
//!
//! * [`fletcher64_words`]/[`verify_block`]/[`compute_block_cksum`] — the APFS
//!   metadata checksum with the upstream sum-to-zero storage scheme
//!   (apfs-fuse `Util.cpp`: `Fletcher64(words[2..], 0)` chained with
//!   `Fletcher64(words[0..2], cs)` must be 0),
//! * `nx_superblock` / `apfs_superblock` / `omap_phys` parse+build
//!   (constants from apfs-fuse `ApfsLib/DiskStruct.h` — reference, not a
//!   code copy),
//! * B-tree nodes (`btree_node_phys_t`): fixed + variable KV tocs, keys
//!   measured from the block end, values after toc (+ btree_info in roots),
//! * omap `(oid, xid) → paddr` resolution,
//! * fs-tree records: drec / inode / file-extent (`j_*` structs),
//! * **writer** ([`ApfsBuilder`]): checksummed container images with
//!   create + replace (COW: new blocks, same oid),
//! * **reader** ([`Container`]): list directories, read files.
//!
//! Documented subset (honest ledger): no checkpoint descriptor area (objects
//! addressed physically), no spaceman (bump allocator), no snapshots /
//! case-folding / encryption / xfields / dir-stats, single-leaf trees.
//! Gate: mounting real Apple images (AES-XTS per-device key wall — see
//! parity.json `permanent_gaps`).

use std::collections::BTreeMap;
use std::io;

// ---------------------------------------------------------------------------
// constants (apfs-fuse DiskStruct.h naming)
// ---------------------------------------------------------------------------

pub const NX_MAGIC: u32 = u32::from_le_bytes(*b"NXSB"); // 0x4253584E
pub const APFS_MAGIC: u32 = u32::from_le_bytes(*b"APSB"); // 0x42535041

pub const OBJECT_TYPE_NX_SUPERBLOCK: u32 = 0x01;
pub const OBJECT_TYPE_BTREE: u32 = 0x02;
pub const OBJECT_TYPE_BTREE_NODE: u32 = 0x03;
pub const OBJECT_TYPE_OMAP: u32 = 0x0B;
pub const OBJECT_TYPE_FS: u32 = 0x0D;
pub const OBJECT_TYPE_FS_TREE: u32 = 0x0E;

pub const OBJ_TYPE_MASK: u64 = 0xF000_0000_0000_0000;
pub const OBJ_ID_MASK: u64 = 0x0FFF_FFFF_FFFF_FFFF;
pub const OBJ_TYPE_SHIFT: u32 = 60;

pub const APFS_TYPE_INODE: u64 = 3;
pub const APFS_TYPE_FILE_EXTENT: u64 = 8;
pub const APFS_TYPE_DIR_REC: u64 = 9;

/// drec flag types (`dir_rec_flags`, mask 0xF): file 0, dir 4, symlink 8.
pub const DREC_TYPE_FILE: u16 = 0;
pub const DREC_TYPE_DIR: u16 = 4;
pub const DREC_TYPE_SYMLINK: u16 = 8;
pub const DREC_TYPE_MASK: u16 = 0x000F;

pub const ROOT_DIR_PARENT: u64 = 1;
pub const ROOT_DIR_INO_NUM: u64 = 2;

pub const BTNODE_ROOT: u16 = 0x0001;
pub const BTNODE_LEAF: u16 = 0x0002;
pub const BTNODE_FIXED_KV_SIZE: u16 = 0x0004;

pub const BTREE_UINT64_KEYS: u32 = 0x0000_0001;
pub const BTREE_PHYSICAL: u32 = 0x0000_0010;

pub const NX_INCOMPAT_VERSION2: u64 = 2;

/// Node header ends here (obj_phys 40 + flags/level/nkeys 8 + 4 nlocs 16).
pub const NODE_HEADER_SIZE: usize = 64;
pub const BTREE_INFO_SIZE: usize = 40;

// container oids (subset namespace)
const OID_NX: u64 = 1;
const OID_OMAP: u64 = 2;
const OID_OMAP_TREE: u64 = 3;
const OID_VOLUME: u64 = 4;
const OID_FSROOT: u64 = 5;
/// First fs-tree inode id (0..3 reserved, 2 = root dir inode).
const FIRST_FILE_ID: u64 = 16;

// ---------------------------------------------------------------------------
// fletcher64
// ---------------------------------------------------------------------------

/// `Fletcher64` (apfs-fuse `Util.cpp`): chained u32-word sums mod 0xFFFFFFFF,
/// packed (sum2<<32)|sum1. `init` carries the previous chain result.
pub fn fletcher64_words(words: &[u32], init: u64) -> u64 {
    const M: u64 = 0xFFFF_FFFF;
    let mut sum1 = init & M;
    let mut sum2 = init >> 32;
    for &w in words {
        sum1 = (sum1 + w as u64) % M;
        sum2 = (sum2 + sum1) % M;
    }
    (sum2 << 32) | sum1
}

fn block_words(block: &[u8]) -> Vec<u32> {
    block
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// Compute the checksum to store in `o_cksum`: with the field zeroed, run
/// the payload (`p = F64(words[2..], 0)`), then solve for the two stored
/// words making the upstream verify chain sum to zero
/// (w0 ≡ −p1−p2, w1 ≡ p2 mod 0xFFFFFFFF).
pub fn compute_block_cksum(block: &[u8]) -> u64 {
    const M: u64 = 0xFFFF_FFFF;
    let words = block_words(block);
    let p = fletcher64_words(&words[2..], 0);
    let p1 = p & M;
    let p2 = p >> 32;
    let w0 = (M + M - (p1 + p2) % M) % M;
    let w1 = p2 % M;
    (w1 << 32) | w0
}

/// Upstream `VerifyBlock`: chained fletcher over the whole block (including
/// the stored checksum) must be 0.
pub fn verify_block(block: &[u8]) -> bool {
    let words = block_words(block);
    if words.len() < 3 {
        return false;
    }
    let cs = fletcher64_words(&words[2..], 0);
    fletcher64_words(&words[..2], cs) == 0
}

fn write_cksum(block: &mut [u8]) {
    block[0..8].copy_from_slice(&0u64.to_le_bytes()); // zero o_cksum first
    let stored = compute_block_cksum(block);
    block[0..8].copy_from_slice(&stored.to_le_bytes());
}

// ---------------------------------------------------------------------------
// little-endian helpers
// ---------------------------------------------------------------------------

fn get_u16(b: &[u8], off: usize) -> u64 {
    u16::from_le_bytes([b[off], b[off + 1]]) as u64
}
fn get_u32(b: &[u8], off: usize) -> u64 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as u64
}
fn get_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}
fn put_u16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn obj_header(buf: &mut [u8], oid: u64, xid: u64, otype: u32, subtype: u32) {
    put_u64(buf, 8, oid);
    put_u64(buf, 16, xid);
    put_u32(buf, 24, otype);
    put_u32(buf, 28, subtype);
}

// ---------------------------------------------------------------------------
// storage abstraction
// ---------------------------------------------------------------------------

/// Random-access block device (image in memory, file-backed later).
pub trait BlockDev {
    fn block_size(&self) -> u32;
    fn block_count(&self) -> u64;
    fn read_block(&mut self, paddr: u64, buf: &mut [u8]) -> io::Result<()>;
    fn write_block(&mut self, paddr: u64, data: &[u8]) -> io::Result<()>;
}

/// In-memory image — what the builder produces and tests consume.
#[derive(Clone)]
pub struct ApfsImage {
    pub blocks: Vec<Vec<u8>>,
}

impl ApfsImage {
    pub fn new(block_count: usize, block_size: usize) -> ApfsImage {
        ApfsImage {
            blocks: vec![vec![0u8; block_size]; block_count],
        }
    }
}

impl BlockDev for ApfsImage {
    fn block_size(&self) -> u32 {
        self.blocks[0].len() as u32
    }
    fn block_count(&self) -> u64 {
        self.blocks.len() as u64
    }
    fn read_block(&mut self, paddr: u64, buf: &mut [u8]) -> io::Result<()> {
        let b = self
            .blocks
            .get(paddr as usize)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "paddr out of range"))?;
        let n = buf.len().min(b.len());
        buf[..n].copy_from_slice(&b[..n]);
        Ok(())
    }
    fn write_block(&mut self, paddr: u64, data: &[u8]) -> io::Result<()> {
        let b = self
            .blocks
            .get_mut(paddr as usize)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "paddr out of range"))?;
        b[..data.len()].copy_from_slice(data);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// B-tree node parse (reader side)
// ---------------------------------------------------------------------------

struct BtreeNode {
    level: u16,
    fixed_kv: bool,
    is_root: bool,
    /// (key_off_from_block_end, key_len, val_off_from_value_area, val_len)
    toc: Vec<(usize, usize, usize, usize)>,
}

fn parse_toc(block: &[u8]) -> BtreeNode {
    let flags = get_u16(block, 40) as u16;
    let level = get_u16(block, 42) as u16;
    let nkeys = get_u32(block, 44) as usize;
    let table_len = get_u16(block, 50) as usize;
    let fixed_kv = flags & BTNODE_FIXED_KV_SIZE != 0;
    let is_root = flags & BTNODE_ROOT != 0;
    let toc_start = NODE_HEADER_SIZE;
    let entry_size = if fixed_kv { 4 } else { 8 };
    let bi = toc_start + table_len;
    let key_size = if fixed_kv && is_root {
        get_u32(block, bi + 8) as usize
    } else {
        0
    };
    let val_size = if fixed_kv && is_root {
        get_u32(block, bi + 12) as usize
    } else {
        0
    };
    let mut toc = Vec::with_capacity(nkeys);
    for i in 0..nkeys {
        let base = toc_start + i * entry_size;
        let (koff, klen, voff, vlen) = if fixed_kv {
            (
                get_u16(block, base) as usize,
                key_size,
                get_u16(block, base + 2) as usize,
                val_size,
            )
        } else {
            (
                get_u16(block, base) as usize,
                get_u16(block, base + 2) as usize,
                get_u16(block, base + 4) as usize,
                get_u16(block, base + 6) as usize,
            )
        };
        toc.push((koff, klen, voff, vlen));
    }
    BtreeNode {
        level,
        fixed_kv,
        is_root,
        toc,
    }
}

fn value_area_start(node: &BtreeNode) -> usize {
    let table_len = node.toc.len() * if node.fixed_kv { 4 } else { 8 };
    NODE_HEADER_SIZE + if node.is_root { BTREE_INFO_SIZE } else { 0 } + table_len
}

fn key_blob<'a>(block: &'a [u8], koff: usize, klen: usize) -> &'a [u8] {
    let end = block.len() - koff;
    &block[end - klen..end]
}

fn value_blob<'a>(block: &'a [u8], node: &BtreeNode, voff: usize, vlen: usize) -> &'a [u8] {
    let start = value_area_start(node) + voff;
    &block[start..start + vlen]
}

// ---------------------------------------------------------------------------
// parsed structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NxSuperblock {
    pub block_size: u32,
    pub block_count: u64,
    pub omap_oid: u64,
    pub fs_oids: Vec<u64>,
    pub next_oid: u64,
    pub next_xid: u64,
}

#[derive(Debug, Clone)]
pub struct VolumeSuperblock {
    pub fs_index: u32,
    pub omap_oid: u64,
    pub root_tree_oid: u64,
    pub num_files: u64,
    pub num_directories: u64,
    pub volname: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DirEntry {
    pub name: String,
    pub flags: u16,
    pub file_id: u64,
}

#[derive(Debug, Clone)]
struct Extent {
    logical_addr: u64,
    len: u64,
    phys_block: u64,
}

// ---------------------------------------------------------------------------
// reader (container)
// ---------------------------------------------------------------------------

/// A mounted (subset) APFS container.
pub struct Container {
    dev: Box<dyn BlockDev>,
    bs: usize,
    pub nx: NxSuperblock,
    pub volume: VolumeSuperblock,
}

impl Container {
    /// Mount an image (block 0 must be a checksummed NXSB superblock).
    pub fn open(mut dev: Box<dyn BlockDev>) -> Result<Container, String> {
        let bs = dev.block_size() as usize;
        let mut nx_buf = vec![0u8; bs];
        dev.read_block(0, &mut nx_buf)
            .map_err(|e| format!("apfs: read block 0: {e}"))?;
        if get_u32(&nx_buf, 40) != NX_MAGIC as u64 {
            return Err("apfs: block 0 is not an NXSB superblock".into());
        }
        if !verify_block(&nx_buf) {
            return Err("apfs: nx superblock checksum mismatch".into());
        }
        let nx = NxSuperblock {
            block_size: get_u32(&nx_buf, 44) as u32,
            block_count: get_u64(&nx_buf, 48),
            omap_oid: get_u64(&nx_buf, 168),
            fs_oids: (0..100)
                .map(|i| get_u64(&nx_buf, 192 + i * 8))
                .take_while(|oid| *oid != 0)
                .collect(),
            next_oid: get_u64(&nx_buf, 96),
            next_xid: get_u64(&nx_buf, 104),
        };
        let mut omap_buf = vec![0u8; bs];
        dev.read_block(nx.omap_oid, &mut omap_buf)
            .map_err(|e| format!("apfs: read omap: {e}"))?;
        if !verify_block(&omap_buf) {
            return Err("apfs: omap checksum mismatch".into());
        }
        if get_u32(&omap_buf, 40) != 0 {
            return Err("apfs: omap flags unsupported in subset".into());
        }
        if nx.fs_oids.is_empty() {
            return Err("apfs: container has no volumes".into());
        }
        let mut vol_buf = vec![0u8; bs];
        dev.read_block(nx.fs_oids[0], &mut vol_buf)
            .map_err(|e| format!("apfs: read volume sb: {e}"))?;
        if get_u32(&vol_buf, 40) != APFS_MAGIC as u64 {
            return Err("apfs: volume superblock magic mismatch".into());
        }
        if !verify_block(&vol_buf) {
            return Err("apfs: volume superblock checksum mismatch".into());
        }
        let volname_len = vol_buf[712..712 + 256]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(256);
        let volume = VolumeSuperblock {
            fs_index: get_u32(&vol_buf, 44) as u32,
            omap_oid: get_u64(&vol_buf, 136),
            root_tree_oid: get_u64(&vol_buf, 144),
            num_files: get_u64(&vol_buf, 192),
            num_directories: get_u64(&vol_buf, 200),
            volname: String::from_utf8_lossy(&vol_buf[712..712 + volname_len]).to_string(),
        };
        Ok(Container {
            dev,
            bs,
            nx,
            volume,
        })
    }

    /// omap lookup: (oid, newest xid ≤ xid) → physical block. In this subset
    /// only the volume sb and the fs tree are omap-tracked (xid 1).
    fn omap_lookup(&mut self, oid: u64, xid: u64) -> Result<u64, String> {
        let mut omap_buf = vec![0u8; self.bs];
        self.dev
            .read_block(self.nx.omap_oid, &mut omap_buf)
            .map_err(|e| format!("omap read: {e}"))?;
        let tree_paddr = get_u64(&omap_buf, 56);
        let (_, val) = self.btree_lookup(tree_paddr, &omap_key_bytes(oid, xid))?;
        if val.len() < 16 {
            return Err("omap: short value".into());
        }
        let flags = get_u32(&val, 0);
        if flags & 1 != 0 {
            return Err(format!("omap: oid {oid} deleted"));
        }
        Ok(get_u64(&val, 8))
    }

    /// Exact-match lookup in a B-tree (single-leaf in this subset; interior
    /// descent implemented for structure).
    fn btree_lookup(&mut self, root_paddr: u64, want: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let mut paddr = root_paddr;
        for _ in 0..8 {
            let mut block = vec![0u8; self.bs];
            self.dev
                .read_block(paddr, &mut block)
                .map_err(|e| format!("btree read: {e}"))?;
            if !verify_block(&block) {
                return Err("btree: node checksum mismatch".into());
            }
            let node = parse_toc(&block);
            if let Some(idx) = node
                .toc
                .iter()
                .position(|(koff, klen, _, _)| key_blob(&block, *koff, *klen) == want)
            {
                let (koff, klen, voff, vlen) = node.toc[idx];
                if node.level == 0 {
                    return Ok((
                        key_blob(&block, koff, klen).to_vec(),
                        value_blob(&block, &node, voff, vlen).to_vec(),
                    ));
                }
                // interior: value = child oid (btn_index_node_val_t)
                let v = value_blob(&block, &node, voff, vlen);
                if v.len() < 8 {
                    return Err("btree: short child pointer".into());
                }
                paddr = get_u64(v, 0);
                continue;
            }
            if node.level == 0 {
                return Err("btree: key not found".into());
            }
            let mut child = None;
            for (_i, (koff, klen, voff, vlen)) in node.toc.iter().enumerate() {
                let k = key_blob(&block, *koff, *klen);
                if k <= want {
                    let v = value_blob(&block, &node, *voff, *vlen);
                    if v.len() >= 8 {
                        child = Some(get_u64(v, 0));
                    }
                }
            }
            match child {
                Some(c) => paddr = c,
                None => return Err("btree: no covering child".into()),
            }
        }
        Err("btree: depth limit exceeded".into())
    }

    fn fs_root_paddr(&mut self) -> Result<u64, String> {
        match self.omap_lookup(self.volume.root_tree_oid, 1) {
            Ok(p) => Ok(p),
            Err(_) => self.omap_lookup(self.volume.root_tree_oid, self.nx.next_xid),
        }
    }

    /// List a directory (empty path = root).
    pub fn list_dir(&mut self, path: &str) -> Result<Vec<DirEntry>, String> {
        let root_paddr = self.fs_root_paddr()?;
        let parent = self.resolve_dir(root_paddr, path)?;
        let mut block = vec![0u8; self.bs];
        self.dev
            .read_block(root_paddr, &mut block)
            .map_err(|e| format!("fsroot read: {e}"))?;
        if !verify_block(&block) {
            return Err("fsroot: checksum mismatch".into());
        }
        let node = parse_toc(&block);
        let mut out = Vec::new();
        for (koff, klen, voff, vlen) in &node.toc {
            let key = key_blob(&block, *koff, *klen);
            if key.len() < 10 || get_u64(key, 0) >> OBJ_TYPE_SHIFT != APFS_TYPE_DIR_REC {
                continue;
            }
            if get_u64(key, 0) & OBJ_ID_MASK != parent {
                continue;
            }
            let name_len = get_u16(key, 8) as usize;
            let name =
                String::from_utf8_lossy(&key[10..10 + name_len.saturating_sub(1)]).to_string();
            let val = value_blob(&block, &node, *voff, *vlen);
            if val.len() < 18 {
                continue;
            }
            out.push(DirEntry {
                name,
                flags: (get_u16(val, 16) as u16) & DREC_TYPE_MASK,
                file_id: get_u64(val, 0),
            });
        }
        Ok(out)
    }

    fn resolve_dir(&mut self, root_paddr: u64, path: &str) -> Result<u64, String> {
        let mut current = ROOT_DIR_INO_NUM;
        for component in path.split('/').filter(|c| !c.is_empty()) {
            let entry = self
                .lookup_drec(root_paddr, current, component)?
                .ok_or_else(|| format!("apfs: no such entry {component:?}"))?;
            if entry.flags != DREC_TYPE_DIR {
                return Err(format!("apfs: {component:?} is not a directory"));
            }
            current = entry.file_id;
        }
        Ok(current)
    }

    fn lookup_drec(
        &mut self,
        root_paddr: u64,
        parent: u64,
        name: &str,
    ) -> Result<Option<DirEntry>, String> {
        let key = drec_key_bytes(parent, name);
        match self.btree_lookup(root_paddr, &key) {
            Ok((_, val)) => {
                if val.len() < 18 {
                    return Ok(None);
                }
                Ok(Some(DirEntry {
                    name: name.to_string(),
                    flags: (get_u16(&val, 16) as u16) & DREC_TYPE_MASK,
                    file_id: get_u64(&val, 0),
                }))
            }
            Err(e) if e.contains("not found") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Read a file's full content (extents concatenated by logical address).
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, String> {
        let root_paddr = self.fs_root_paddr()?;
        let dir = match path.rfind('/') {
            Some(0) | None => ROOT_DIR_INO_NUM,
            Some(pos) => self.resolve_dir(root_paddr, &path[..pos])?,
        };
        let name = path.rsplit('/').next().unwrap_or(path);
        let entry = self
            .lookup_drec(root_paddr, dir, name)?
            .ok_or_else(|| format!("apfs: no such file {path:?}"))?;
        if entry.flags == DREC_TYPE_DIR {
            return Err(format!("apfs: {path:?} is a directory"));
        }
        let mut extents: Vec<Extent> = Vec::new();
        let mut block = vec![0u8; self.bs];
        self.dev
            .read_block(root_paddr, &mut block)
            .map_err(|e| format!("fsroot read: {e}"))?;
        let node = parse_toc(&block);
        for (koff, klen, voff, vlen) in &node.toc {
            let key = key_blob(&block, *koff, *klen);
            if key.len() < 16 || get_u64(key, 0) >> OBJ_TYPE_SHIFT != APFS_TYPE_FILE_EXTENT {
                continue;
            }
            if get_u64(key, 0) & OBJ_ID_MASK != entry.file_id {
                continue;
            }
            let val = value_blob(&block, &node, *voff, *vlen);
            if val.len() < 24 {
                continue;
            }
            extents.push(Extent {
                logical_addr: get_u64(key, 8),
                len: get_u64(val, 0),
                phys_block: get_u64(val, 8),
            });
        }
        extents.sort_by_key(|e| e.logical_addr);
        let mut out = Vec::new();
        for e in &extents {
            let mut data = vec![0u8; self.bs];
            self.dev
                .read_block(e.phys_block, &mut data)
                .map_err(|err| format!("extent read: {err}"))?;
            let take = (e.len as usize).min(self.bs);
            out.extend_from_slice(&data[..take]);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// record encoders (writer side; readers decode the same bytes)
// ---------------------------------------------------------------------------

fn omap_key_bytes(oid: u64, xid: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(16);
    k.extend_from_slice(&oid.to_le_bytes());
    k.extend_from_slice(&xid.to_le_bytes());
    k
}

fn omap_val_bytes(flags: u32, size: u32, paddr: u64) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[0..4].copy_from_slice(&flags.to_le_bytes());
    v[4..8].copy_from_slice(&size.to_le_bytes());
    v[8..16].copy_from_slice(&paddr.to_le_bytes());
    v
}

fn j_key(obj_id: u64, obj_type: u64) -> u64 {
    (obj_type << OBJ_TYPE_SHIFT) | (obj_id & OBJ_ID_MASK)
}

fn drec_key_bytes(parent: u64, name: &str) -> Vec<u8> {
    let mut k = Vec::new();
    k.extend_from_slice(&j_key(parent, APFS_TYPE_DIR_REC).to_le_bytes());
    k.extend_from_slice(&((name.len() + 1) as u16).to_le_bytes()); // NUL included
    k.extend_from_slice(name.as_bytes());
    k.push(0);
    k
}

fn drec_val_bytes(file_id: u64, flags: u16) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&file_id.to_le_bytes());
    v.extend_from_slice(&0u64.to_le_bytes()); // date_added
    v.extend_from_slice(&flags.to_le_bytes());
    v
}

fn inode_key_bytes(id: u64) -> Vec<u8> {
    j_key(id, APFS_TYPE_INODE).to_le_bytes().to_vec()
}

/// `j_inode_val_t` — 92 bytes (no xfields).
fn inode_val_bytes(parent: u64, private_id: u64, mode: u16, nchildren: i32, size: u64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&parent.to_le_bytes());
    v.extend_from_slice(&private_id.to_le_bytes());
    for _ in 0..4 {
        v.extend_from_slice(&0u64.to_le_bytes()); // create/mod/change/access
    }
    v.extend_from_slice(&0u64.to_le_bytes()); // internal_flags
    v.extend_from_slice(&nchildren.to_le_bytes()); // nchildren / nlink union
    v.extend_from_slice(&0u32.to_le_bytes()); // default_protection_class
    v.extend_from_slice(&0u32.to_le_bytes()); // write_generation_counter
    v.extend_from_slice(&0u32.to_le_bytes()); // bsd_flags
    v.extend_from_slice(&0u32.to_le_bytes()); // owner
    v.extend_from_slice(&0u32.to_le_bytes()); // group
    v.extend_from_slice(&mode.to_le_bytes()); // mode
    v.extend_from_slice(&0u16.to_le_bytes()); // pad1
    v.extend_from_slice(&size.to_le_bytes()); // uncompressed_size @84
    v
}

fn extent_key_bytes(file_id: u64, logical_addr: u64) -> Vec<u8> {
    let mut k = Vec::new();
    k.extend_from_slice(&j_key(file_id, APFS_TYPE_FILE_EXTENT).to_le_bytes());
    k.extend_from_slice(&logical_addr.to_le_bytes());
    k
}

fn extent_val_bytes(len: u64, phys_block: u64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&len.to_le_bytes()); // len_and_flags
    v.extend_from_slice(&phys_block.to_le_bytes());
    v.extend_from_slice(&0u64.to_le_bytes()); // crypto_id
    v
}

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

fn split_path(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(0) => ("", &path[1..]),
        Some(pos) => (&path[..pos], &path[pos + 1..]),
        None => ("", path),
    }
}

// ---------------------------------------------------------------------------
// writer (builder)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum EntryKind {
    Dir,
    File,
}

struct Entry {
    kind: EntryKind,
    dir_id: u64,
    name: String,
    id: u64,
    content: Vec<u8>,
}

/// Builds a checksummed APFS container image (writer subset).
pub struct ApfsBuilder {
    block_size: usize,
    total_blocks: usize,
    volname: String,
    entries: Vec<Entry>,
    next_id: u64,
}

impl ApfsBuilder {
    pub fn new(total_blocks: usize, block_size: usize) -> ApfsBuilder {
        ApfsBuilder {
            block_size,
            total_blocks,
            volname: "ios-rust".into(),
            entries: Vec::new(),
            next_id: FIRST_FILE_ID,
        }
    }

    pub fn set_volname(&mut self, name: &str) -> &mut Self {
        self.volname = name.to_string();
        self
    }

    fn dir_id_of(&self, parent_path: &str) -> Result<u64, String> {
        match parent_path {
            "" => Ok(ROOT_DIR_INO_NUM),
            p => self
                .entries
                .iter()
                .find(|e| e.kind == EntryKind::Dir && dir_path_of(self, e) == p)
                .map(|e| e.id)
                .ok_or_else(|| format!("apfs builder: parent {p:?} missing")),
        }
    }

    /// Create a directory (parents must exist; "" is the root).
    pub fn mkdir(&mut self, path: &str) -> Result<&mut Self, String> {
        if path.is_empty() {
            return Ok(self);
        }
        let (parent_path, name) = split_path(path);
        let dir_id = self.dir_id_of(parent_path)?;
        if self
            .entries
            .iter()
            .any(|e| e.dir_id == dir_id && e.name == name)
        {
            return Err(format!("apfs builder: {path:?} already exists"));
        }
        let id = self.next_id;
        self.next_id += 1;
        self.entries.push(Entry {
            kind: EntryKind::Dir,
            dir_id,
            name: name.to_string(),
            id,
            content: Vec::new(),
        });
        Ok(self)
    }

    /// Stage a file (parent dirs must exist; restaging replaces content).
    pub fn create_file(&mut self, path: &str, content: Vec<u8>) -> Result<&mut Self, String> {
        let (parent_path, name) = split_path(path);
        let dir_id = self.dir_id_of(parent_path)?;
        if let Some(e) = self
            .entries
            .iter_mut()
            .find(|e| e.dir_id == dir_id && e.name == name)
        {
            if e.kind == EntryKind::Dir {
                return Err(format!("apfs builder: {path:?} is a directory"));
            }
            e.content = content;
            return Ok(self);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.entries.push(Entry {
            kind: EntryKind::File,
            dir_id,
            name: name.to_string(),
            id,
            content,
        });
        Ok(self)
    }

    /// Replace a staged file's content (COW at finish: new blocks, same oid).
    pub fn replace_file(&mut self, path: &str, content: Vec<u8>) -> Result<&mut Self, String> {
        let (parent_path, name) = split_path(path);
        let dir_id = self.dir_id_of(parent_path)?;
        self.entries
            .iter_mut()
            .find(|e| e.dir_id == dir_id && e.name == name && e.kind == EntryKind::File)
            .map(|e| e.content = content)
            .ok_or_else(|| format!("apfs builder: no staged file {path:?}"))?;
        Ok(self)
    }

    /// Materialize the image.
    pub fn finish(self) -> Result<ApfsImage, String> {
        let bs = self.block_size;
        let mut img = ApfsImage::new(self.total_blocks, bs);
        let mut next_paddr: u64 = 1; // block 0 is reserved for the nx superblock

        // 1. data blocks for every file (extents reference them directly)
        let mut extents_by_id: BTreeMap<u64, Vec<Extent>> = BTreeMap::new();
        for e in &self.entries {
            if e.kind != EntryKind::File || e.content.is_empty() {
                continue;
            }
            let mut exts = Vec::new();
            for (i, chunk) in e.content.chunks(bs).enumerate() {
                let paddr = next_paddr;
                next_paddr += 1;
                let mut data = vec![0u8; bs];
                data[..chunk.len()].copy_from_slice(chunk);
                img.write_block(paddr, &data).map_err(|er| er.to_string())?;
                exts.push(Extent {
                    logical_addr: (i * bs) as u64,
                    len: chunk.len() as u64,
                    phys_block: paddr,
                });
            }
            extents_by_id.insert(e.id, exts);
        }

        // 2. fs-tree records
        let mut records: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        let root_children = self
            .entries
            .iter()
            .filter(|e| e.dir_id == ROOT_DIR_INO_NUM)
            .count() as i32;
        records.insert(
            inode_key_bytes(ROOT_DIR_INO_NUM),
            inode_val_bytes(ROOT_DIR_PARENT, ROOT_DIR_INO_NUM, 0o40755, root_children, 0),
        );
        for e in &self.entries {
            match e.kind {
                EntryKind::Dir => {
                    records.insert(
                        inode_key_bytes(e.id),
                        inode_val_bytes(e.dir_id, e.id, 0o40755, 0, 0),
                    );
                    records.insert(
                        drec_key_bytes(e.dir_id, &e.name),
                        drec_val_bytes(e.id, DREC_TYPE_DIR),
                    );
                }
                EntryKind::File => {
                    records.insert(
                        drec_key_bytes(e.dir_id, &e.name),
                        drec_val_bytes(e.id, DREC_TYPE_FILE),
                    );
                    records.insert(
                        inode_key_bytes(e.id),
                        inode_val_bytes(e.dir_id, e.id, 0o100644, 1, e.content.len() as u64),
                    );
                    if let Some(exts) = extents_by_id.get(&e.id) {
                        for x in exts {
                            records.insert(
                                extent_key_bytes(e.id, x.logical_addr),
                                extent_val_bytes(x.len, x.phys_block),
                            );
                        }
                    }
                }
            }
        }

        // 3. metadata block placement
        let vol_paddr = next_paddr;
        let fsroot_paddr = next_paddr + 1;
        let omap_tree_paddr = next_paddr + 2;
        let omap_paddr = next_paddr + 3;

        // 4. fsroot B-tree root (variable KV, single leaf)
        {
            let mut block = vec![0u8; bs];
            obj_header(&mut block, OID_FSROOT, 1, OBJECT_TYPE_BTREE_NODE, OBJECT_TYPE_FS_TREE);
            let n = records.len();
            put_u16(&mut block, 40, BTNODE_ROOT | BTNODE_LEAF);
            put_u16(&mut block, 42, 0); // level 0 = leaf
            put_u32(&mut block, 44, n as u32);
            put_u16(&mut block, 48, 0); // table_space: toc right after header
            put_u16(&mut block, 50, (n * 8) as u16);
            let bi = NODE_HEADER_SIZE + n * 8;
            put_u32(&mut block, bi, BTREE_PHYSICAL);
            put_u32(&mut block, bi + 4, bs as u32);
            put_u32(&mut block, bi + 8, 0); // variable key size
            put_u32(&mut block, bi + 12, 0); // variable val size
            put_u64(&mut block, bi + 24, n as u64);
            put_u64(&mut block, bi + 32, 1);
            let value_area = bi + BTREE_INFO_SIZE;
            let mut voff_abs = value_area;
            let mut koff = 0usize;
            let mut used = 0usize;
            for (key, val) in &records {
                let klen = key.len();
                let vlen = val.len();
                if voff_abs + align8(vlen) > bs - koff - align8(klen) {
                    return Err(format!(
                        "apfs builder: fsroot overflow at {used}/{n} records (single-leaf subset)"
                    ));
                }
                let toc_base = NODE_HEADER_SIZE + used * 8;
                put_u16(&mut block, toc_base, koff as u16);
                put_u16(&mut block, toc_base + 2, klen as u16);
                put_u16(&mut block, toc_base + 4, (voff_abs - value_area) as u16);
                put_u16(&mut block, toc_base + 6, vlen as u16);
                let kstart = bs - koff - klen;
                block[kstart..kstart + klen].copy_from_slice(key);
                block[voff_abs..voff_abs + vlen].copy_from_slice(val);
                koff += align8(klen);
                voff_abs += align8(vlen);
                used += 1;
            }
            write_cksum(&mut block);
            img.write_block(fsroot_paddr, &block).map_err(|e| e.to_string())?;
        }

        // 5. volume superblock
        {
            let mut b = vec![0u8; bs];
            obj_header(&mut b, OID_VOLUME, 1, OBJECT_TYPE_FS, 0);
            put_u32(&mut b, 40, APFS_MAGIC);
            put_u32(&mut b, 44, 0); // fs_index
            put_u64(&mut b, 64, 0); // incompat: case-sensitive subset
            put_u64(&mut b, 96, next_paddr); // fs_alloc_count (rough)
            put_u32(&mut b, 124, OBJECT_TYPE_FS_TREE | (OBJECT_TYPE_BTREE << 16));
            put_u32(&mut b, 128, OBJECT_TYPE_FS_TREE | (OBJECT_TYPE_BTREE << 16));
            put_u32(&mut b, 132, OBJECT_TYPE_FS_TREE | (OBJECT_TYPE_BTREE << 16));
            put_u64(&mut b, 136, OID_OMAP);
            put_u64(&mut b, 144, OID_FSROOT);
            put_u64(&mut b, 184, 1000); // next_obj_id
            put_u64(
                &mut b,
                192,
                self.entries.iter().filter(|e| e.kind == EntryKind::File).count() as u64,
            );
            put_u64(
                &mut b,
                200,
                self.entries.iter().filter(|e| e.kind == EntryKind::Dir).count() as u64 + 1,
            );
            let name = self.volname.as_bytes();
            let n = name.len().min(255);
            b[712..712 + n].copy_from_slice(&name[..n]);
            write_cksum(&mut b);
            img.write_block(vol_paddr, &b).map_err(|e| e.to_string())?;
        }

        // 6. omap B-tree root (fixed 16B KV): volume + fsroot objects
        {
            let mut block = vec![0u8; bs];
            obj_header(&mut block, OID_OMAP_TREE, 1, OBJECT_TYPE_BTREE_NODE, OBJECT_TYPE_OMAP);
            let mut entries = vec![(OID_VOLUME, vol_paddr), (OID_FSROOT, fsroot_paddr)];
            entries.sort_by_key(|(oid, _)| *oid);
            let n = entries.len();
            put_u16(&mut block, 40, BTNODE_ROOT | BTNODE_LEAF | BTNODE_FIXED_KV_SIZE);
            put_u16(&mut block, 42, 0);
            put_u32(&mut block, 44, n as u32);
            put_u16(&mut block, 48, 0);
            put_u16(&mut block, 50, (n * 4) as u16); // kvoff toc
            let bi = NODE_HEADER_SIZE + n * 4;
            put_u32(&mut block, bi, BTREE_UINT64_KEYS | BTREE_PHYSICAL);
            put_u32(&mut block, bi + 4, bs as u32);
            put_u32(&mut block, bi + 8, 16);
            put_u32(&mut block, bi + 12, 16);
            put_u32(&mut block, bi + 16, 16);
            put_u32(&mut block, bi + 20, 16);
            put_u64(&mut block, bi + 24, n as u64);
            put_u64(&mut block, bi + 32, 1);
            let value_area = bi + BTREE_INFO_SIZE;
            let mut voff = 0usize;
            let mut koff = 0usize;
            for (i, (oid, paddr)) in entries.iter().enumerate() {
                let toc_base = NODE_HEADER_SIZE + i * 4;
                put_u16(&mut block, toc_base, koff as u16);
                put_u16(&mut block, toc_base + 2, voff as u16);
                let kstart = bs - koff - 16;
                block[kstart..kstart + 16].copy_from_slice(&omap_key_bytes(*oid, 1));
                let vstart = value_area + voff;
                block[vstart..vstart + 16].copy_from_slice(&omap_val_bytes(0, 0, *paddr));
                koff += 16;
                voff += 16;
            }
            write_cksum(&mut block);
            img.write_block(omap_tree_paddr, &block).map_err(|e| e.to_string())?;
        }

        // 7. omap object
        {
            let mut b = vec![0u8; bs];
            obj_header(&mut b, OID_OMAP, 1, OBJECT_TYPE_OMAP, OBJECT_TYPE_BTREE);
            put_u32(&mut b, 40, 0); // om_flags
            put_u32(&mut b, 44, 0); // snap count
            put_u32(&mut b, 48, OBJECT_TYPE_BTREE_NODE | (OBJECT_TYPE_OMAP << 16));
            put_u32(&mut b, 52, OBJECT_TYPE_BTREE_NODE | (OBJECT_TYPE_OMAP << 16));
            put_u64(&mut b, 56, omap_tree_paddr);
            put_u64(&mut b, 64, omap_tree_paddr);
            write_cksum(&mut b);
            img.write_block(omap_paddr, &b).map_err(|e| e.to_string())?;
        }

        // 8. nx superblock @0
        {
            let mut b = vec![0u8; bs];
            obj_header(&mut b, OID_NX, 1, OBJECT_TYPE_NX_SUPERBLOCK, 0);
            put_u32(&mut b, 40, NX_MAGIC);
            put_u32(&mut b, 44, bs as u32);
            put_u64(&mut b, 48, self.total_blocks as u64);
            put_u64(&mut b, 72, NX_INCOMPAT_VERSION2);
            let uuid = b"ios-rust-subset\0";
            b[80..80 + uuid.len()].copy_from_slice(uuid);
            put_u64(&mut b, 96, 6); // next_oid
            put_u64(&mut b, 104, 2); // next_xid
            put_u64(&mut b, 160, 0); // spaceman: subset has none
            put_u64(&mut b, 168, omap_paddr);
            put_u64(&mut b, 188, 100); // max_file_systems
            put_u64(&mut b, 192, vol_paddr); // fs_oid[0] (physical in subset)
            write_cksum(&mut b);
            img.write_block(0, &b).map_err(|e| e.to_string())?;
        }

        Ok(img)
    }
}

/// Root-relative path of a Dir entry (walks the parent chain).
fn dir_path_of(builder: &ApfsBuilder, dir: &Entry) -> String {
    let mut parts = vec![dir.name.clone()];
    let mut parent = dir.dir_id;
    loop {
        if parent == ROOT_DIR_INO_NUM {
            break;
        }
        match builder.entries.iter().find(|e| e.id == parent) {
            Some(e) => {
                parts.push(e.name.clone());
                parent = e.dir_id;
            }
            None => break,
        }
    }
    parts.reverse();
    parts.join("/")
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fletcher64_sum_to_zero_property() {
        // build a random-ish metadata block, store checksum, verify like
        // upstream VerifyBlock (chained over whole block == 0)
        let mut block = vec![0u8; 4096];
        for (i, b) in block.iter_mut().enumerate().skip(8) {
            *b = (i as u8).wrapping_mul(31).wrapping_add((i / 257) as u8);
        }
        let stored = compute_block_cksum(&block);
        block[0..8].copy_from_slice(&stored.to_le_bytes());
        assert!(verify_block(&block), "stored checksum must verify");
        // known self-consistency: recompute over zeroed field matches
        block[0..8].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(compute_block_cksum(&block), stored);
        // corruption must fail
        block[0..8].copy_from_slice(&stored.to_le_bytes());
        block[100] ^= 0xFF;
        assert!(!verify_block(&block));
    }

    #[test]
    fn fletcher64_matches_reference_shape() {
        // chain semantics: F64(words[2..], init=F64(words[..2])) == F64(all words)
        let words: Vec<u32> = (0u32..64).map(|i| i.wrapping_mul(0x9E37_79B1)).collect();
        let whole = fletcher64_words(&words, 0);
        let chained = fletcher64_words(&words[2..], fletcher64_words(&words[..2], 0));
        assert_eq!(whole, chained);
    }

    fn build_image() -> ApfsImage {
        let mut b = ApfsBuilder::new(256, 4096);
        b.set_volname("parity-test");
        b.mkdir("dir").unwrap();
        b.mkdir("dir/nested").unwrap();
        b.create_file("small.txt", b"hello apfs".to_vec()).unwrap();
        b.create_file("big.bin", (0u32..8000).map(|i| (i % 251) as u8).collect())
            .unwrap();
        b.create_file("dir/nested/leaf.bin", vec![0xAB; 4096]).unwrap();
        b.finish().unwrap()
    }

    #[test]
    fn build_then_mount_list_and_read() {
        let img = build_image();
        let mut c = Container::open(Box::new(img)).expect("mount");
        assert_eq!(c.volume.volname, "parity-test");
        assert_eq!(c.nx.block_size, 4096);

        let root = c.list_dir("").expect("list root");
        let names: Vec<&str> = root.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"small.txt"));
        assert!(names.contains(&"big.bin"));
        assert!(names.contains(&"dir"));
        let dir_entry = root.iter().find(|e| e.name == "dir").unwrap();
        assert_eq!(dir_entry.flags, DREC_TYPE_DIR);

        let nested = c.list_dir("dir").expect("list dir");
        assert!(nested.iter().any(|e| e.name == "nested"));

        assert_eq!(c.read_file("small.txt").unwrap(), b"hello apfs");
        let big = c.read_file("big.bin").unwrap();
        assert_eq!(big.len(), 8000); // spans 2 extents
        for (i, b) in big.iter().enumerate() {
            assert_eq!(*b, (i as u32 % 251) as u8);
        }
        let leaf = c.read_file("dir/nested/leaf.bin").unwrap();
        assert_eq!(leaf, vec![0xAB; 4096]);
    }

    #[test]
    fn replace_file_is_cow() {
        let mut b = ApfsBuilder::new(256, 4096);
        b.create_file("f.bin", vec![1u8; 5000]).unwrap();
        let img1 = b.finish().unwrap();
        let mut c1 = Container::open(Box::new(img1.clone())).unwrap();
        assert_eq!(c1.read_file("f.bin").unwrap(), vec![1u8; 5000]);

        // rebuild-from-builder path: replace staged content, finish again
        let mut b2 = ApfsBuilder::new(256, 4096);
        b2.create_file("f.bin", vec![1u8; 5000]).unwrap();
        b2.replace_file("f.bin", vec![2u8; 12345]).unwrap();
        let img2 = b2.finish().unwrap();
        let mut c2 = Container::open(Box::new(img2)).unwrap();
        assert_eq!(c2.read_file("f.bin").unwrap(), vec![2u8; 12345]);
        // original image untouched (COW semantics)
        assert_eq!(c1.read_file("f.bin").unwrap(), vec![1u8; 5000]);
    }

    #[test]
    fn corrupt_metadata_is_detected() {
        let mut img = build_image();
        // flip a byte in block 0 (nx superblock)
        img.blocks[0][200] ^= 0x01;
        assert!(
            Container::open(Box::new(img)).is_err(),
            "checksum must fail"
        );
    }

    #[test]
    fn missing_file_errors() {
        let img = build_image();
        let mut c = Container::open(Box::new(img)).unwrap();
        assert!(c.read_file("nope.txt").is_err());
        assert!(c.list_dir("nope").is_err());
        assert!(c.read_file("dir").is_err(), "reading a dir must fail");
    }

    #[test]
    fn all_metadata_blocks_checksummed() {
        let img = build_image();
        let mut c = Container::open(Box::new(img.clone())).expect("mount");
        // walk the real metadata chain and verify every block on it
        let bs = c.nx.block_size as usize;
        let mut nx_buf = vec![0u8; bs];
        c.dev.read_block(0, &mut nx_buf).unwrap();
        assert!(verify_block(&nx_buf));
        let omap_paddr = get_u64(&nx_buf, 168);
        let mut omap_buf = vec![0u8; bs];
        c.dev.read_block(omap_paddr, &mut omap_buf).unwrap();
        assert!(verify_block(&omap_buf));
        let tree_paddr = get_u64(&omap_buf, 56);
        let mut tree_buf = vec![0u8; bs];
        c.dev.read_block(tree_paddr, &mut tree_buf).unwrap();
        assert!(verify_block(&tree_buf));
        let fsroot_paddr = c.fs_root_paddr().expect("fsroot via omap");
        let mut fs_buf = vec![0u8; bs];
        c.dev.read_block(fsroot_paddr, &mut fs_buf).unwrap();
        assert!(verify_block(&fs_buf));
        // data blocks are NOT checksummed in this subset
        assert!(!verify_block(&img.blocks[1]));
    }
}
