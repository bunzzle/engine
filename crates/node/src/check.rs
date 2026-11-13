use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use tls::Certs;

use crate::{Config, parse};

const MAX_FILE: u64 = 1 << 20;

pub fn check(path: &Path) -> Result<Config, String> {
    load(path).map(|(config, _)| config)
}

pub fn load(path: &Path) -> Result<(Config, Certs), String> {
    let euid = sys::process::euid();
    if euid == 0 {
        return Err(String::from("must not run as root"));
    }
    let text = read(path)?;
    let text = String::from_utf8(text).map_err(|_| format!("{}: not UTF-8", path.display()))?;
    let config = parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let key = key_file(&config.tls.key, euid)?;
    let chain = read(&config.tls.chain)?;
    let certs = Certs::new(&chain, &key).map_err(|e| {
        format!(
            "{} and {}: {e}",
            config.tls.chain.display(),
            config.tls.key.display()
        )
    })?;
    Ok((config, certs))
}

pub fn key_file(path: &Path, owner: u32) -> Result<Vec<u8>, String> {
    let (mut file, meta) = open(path)?;
    if meta.uid() != owner {
        return Err(format!("{}: belongs to another user", path.display()));
    }
    if meta.mode() & 0o777 & !0o600 != 0 {
        return Err(format!("{}: must have mode 0600 or 0400", path.display()));
    }
    limited(&mut file, meta.len()).map_err(|e| format!("{}: {e}", path.display()))
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    let (mut file, meta) = open(path)?;
    limited(&mut file, meta.len()).map_err(|e| format!("{}: {e}", path.display()))
}

fn open(path: &Path) -> Result<(File, Metadata), String> {
    let fail = |message: String| format!("{}: {message}", path.display());
    let file = File::open(path).map_err(|e| fail(e.to_string()))?;
    let meta = file.metadata().map_err(|e| fail(e.to_string()))?;
    if !meta.is_file() {
        return Err(fail(String::from("is not a file")));
    }
    Ok((file, meta))
}

fn limited(file: &mut File, len: u64) -> Result<Vec<u8>, String> {
    if len > MAX_FILE {
        return Err(String::from("is too large"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_FILE {
        return Err(String::from("is too large"));
    }
    Ok(bytes)
}
