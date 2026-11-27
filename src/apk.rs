//! Read-only access to the zip directory of an APK.
//!
//! Nothing is unpacked to disk: entries are decompressed in memory only when
//! they are needed, and every entry that contributes to the output is hashed so
//! the generated tree can be traced back to the exact APK that produced it.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use zip::ZipArchive;

pub struct Archive {
    zip: ZipArchive<BufReader<File>>,
    names: Vec<String>,
    sha256: String,
}

impl Archive {
    pub fn open(path: &Path) -> Result<Self> {
        let sha256 = hash_reader(&mut File::open(path).with_context(|| {
            format!("opening input APK {}", path.display())
        })?)?;
        let file = File::open(path)
            .with_context(|| format!("opening input APK {}", path.display()))?;
        let mut zip = ZipArchive::new(BufReader::new(file))
            .with_context(|| format!("reading the zip directory of {}", path.display()))?;
        let mut names = Vec::with_capacity(zip.len());
        for index in 0..zip.len() {
            names.push(zip.by_index(index)?.name()?.into_owned());
        }
        Ok(Self {
            zip,
            names,
            sha256,
        })
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Entry names in zip order.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Entry names with the given prefix, ignoring directories.
    pub fn under(&self, prefix: &str) -> Vec<String> {
        self.names
            .iter()
            .filter(|name| name.starts_with(prefix) && !name.ends_with('/'))
            .cloned()
            .collect()
    }

    pub fn read(&mut self, name: &str) -> Result<Vec<u8>> {
        let mut entry = self
            .zip
            .by_name(name)
            .with_context(|| format!("APK has no entry {name}"))?;
        let mut data = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut data)
            .with_context(|| format!("decompressing {name}"))?;
        Ok(data)
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hash_reader(reader: &mut impl Read) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let mut out = String::with_capacity(64);
    for byte in hasher.finalize() {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}
