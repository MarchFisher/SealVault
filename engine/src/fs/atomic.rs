//! SealVault 原子写入工具。
//!
//! 提供「先写临时文件，成功后再替换目标文件」的写出语义，
//! 避免在写入失败时污染或截断目标文件。

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// 原子写文件。
///
/// 流程：
/// 1. 在目标目录创建临时文件；
/// 2. 调用 `write_fn` 写入完整内容；
/// 3. 写入成功后，使用 rename 原子替换目标文件。
pub fn write_atomic<F>(target: &Path, write_fn: F) -> io::Result<()>
where
    F: FnOnce(&mut File) -> io::Result<()>,
{
    let parent = target.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "目标路径没有父目录，无法执行原子写入",
        )
    })?;

    fs::create_dir_all(parent)?;

    let tmp_path = build_tmp_path(parent, target.file_name());
    let mut tmp_file = File::create(&tmp_path)?;

    if let Err(err) = write_fn(&mut tmp_file) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    tmp_file.sync_all()?;

    if target.exists() {
        fs::remove_file(target)?;
    }

    fs::rename(&tmp_path, target)?;

    Ok(())
}

fn build_tmp_path(parent: &Path, file_name: Option<&std::ffi::OsStr>) -> PathBuf {
    let base_name = file_name
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("sealvault-output");

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();

    let counter = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);

    parent.join(format!(
        ".{base_name}.tmp-{}-{timestamp}-{counter}",
        std::process::id()
    ))
}
