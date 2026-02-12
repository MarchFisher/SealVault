//! SealVault 文件加密/解密实现（非打包、非压缩）
//!
//! 设计要点：
//! - 递归遍历目录，保持相对路径结构。
//! - 文件逐个流式加/解密，避免整文件读入内存。
//! - 严格校验相对路径组件，防止路径穿越写出到目标目录之外。

use std::ffi::OsStr;
use std::io;
use std::path::{Component, Path, PathBuf};

use walkdir::WalkDir;

use crate::algorithm::AeadAlgorithm;
use crate::decrypt::decrypt_file;
use crate::encrypt::encrypt_file_with_algorithm;

const ENCRYPTED_EXT: &str = "svlt";

/// 将目录中的文件逐个加密到目标目录。
///
/// - 会递归创建目录结构。
/// - 普通文件会输出为同名 + `.svlt`。
/// - 使用现有文件流式加密逻辑，不重新实现算法。
pub fn encrypt_folder(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    algorithm: AeadAlgorithm,
) -> io::Result<()> {
    if !input_path.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input_path 不是目录",
        ));
    }

    std::fs::create_dir_all(output_path)?;

    for entry in WalkDir::new(input_path).follow_links(false) {
        let entry = entry.map_err(walkdir_to_io)?;
        let source_path = entry.path();

        let rel = source_path.strip_prefix(input_path).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("无法计算相对路径: {e}"))
        })?;

        let safe_rel = validate_relative_path(rel)?;

        if entry.file_type().is_dir() {
            let target_dir = safe_join(output_path, &safe_rel)?;
            std::fs::create_dir_all(target_dir)?;
            continue;
        }

        if entry.file_type().is_file() {
            let mut target_file_rel = safe_rel.clone();
            let name = source_path.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "文件名为空，无法加密")
            })?;

            let encrypted_name = append_svlt_suffix(name);
            target_file_rel.set_file_name(encrypted_name);

            let target_file_path = safe_join(output_path, &target_file_rel)?;
            if let Some(parent) = target_file_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            encrypt_file_with_algorithm(source_path, &target_file_path, password, algorithm)?;
        }
    }

    Ok(())
}

/// 将目录中的 `.svlt` 文件逐个解密到目标目录。
///
/// - 只处理 `.svlt` 文件。
/// - 解密后去掉 `.svlt` 后缀并恢复相对路径。
/// - 严格限制输出路径，防止路径穿越。
pub fn decrypt_folder(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    _algorithm: AeadAlgorithm,
) -> io::Result<()> {
    if !input_path.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input_path 不是目录",
        ));
    }

    std::fs::create_dir_all(output_path)?;

    for entry in WalkDir::new(input_path).follow_links(false) {
        let entry = entry.map_err(walkdir_to_io)?;
        let source_path = entry.path();

        let rel = source_path.strip_prefix(input_path).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("无法计算相对路径: {e}"))
        })?;

        let safe_rel = validate_relative_path(rel)?;

        if entry.file_type().is_dir() {
            let target_dir = safe_join(output_path, &safe_rel)?;
            std::fs::create_dir_all(target_dir)?;
            continue;
        }

        if entry.file_type().is_file() {
            // 仅处理 .svlt 文件，其余文件跳过（避免误解密）。
            if source_path.extension().and_then(OsStr::to_str) != Some(ENCRYPTED_EXT) {
                continue;
            }

            let target_file_rel = remove_svlt_extension(&safe_rel)?;
            let target_file_path = safe_join(output_path, &target_file_rel)?;

            if let Some(parent) = target_file_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            decrypt_file(source_path, &target_file_path, password)?;
        }
    }

    Ok(())
}

fn append_svlt_suffix(name: &OsStr) -> std::ffi::OsString {
    let mut s = name.to_os_string();
    s.push(".");
    s.push(ENCRYPTED_EXT);
    s
}

fn remove_svlt_extension(rel_path: &Path) -> io::Result<PathBuf> {
    let extension = rel_path
        .extension()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "待解密文件后缀不是 .svlt"))?;

    if extension != OsStr::new(ENCRYPTED_EXT) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "待解密文件后缀不是 .svlt",
        ));
    }

    let origin_name = rel_path
        .file_stem()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "无效文件名"))?;
    if origin_name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "去除 .svlt 后文件名为空",
        ));
    }

    let mut out = rel_path.to_path_buf();
    out.set_file_name(origin_name);
    Ok(out)
}

/// 校验相对路径仅包含安全组件，防止 `..`、绝对路径、盘符路径等穿越问题。
fn validate_relative_path(rel: &Path) -> io::Result<PathBuf> {
    let mut safe = PathBuf::new();
    for comp in rel.components() {
        match comp {
            Component::CurDir => {}
            Component::Normal(v) => safe.push(v),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("检测到不安全路径组件: {rel:?}"),
                ));
            }
        }
    }
    Ok(safe)
}

/// 在目标根目录下拼接已校验的相对路径，并再次校验结果不越界。
fn safe_join(root: &Path, rel: &Path) -> io::Result<PathBuf> {
    let joined = root.join(rel);
    if !joined.starts_with(root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("目标路径越界: {joined:?}"),
        ));
    }
    Ok(joined)
}

fn walkdir_to_io(err: walkdir::Error) -> io::Error {
    io::Error::other(err.to_string())
}
