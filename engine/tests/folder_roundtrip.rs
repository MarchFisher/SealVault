//! 目录加密/解密最小可运行测试

use std::fs;
use std::io::Write;

use tempfile::tempdir;

#[test]
fn encrypt_decrypt_folder_roundtrip() {
    let temp = tempdir().expect("create temp dir");
    let input_dir = temp.path().join("plain");
    let encrypted_dir = temp.path().join("encrypted");
    let decrypted_dir = temp.path().join("decrypted");

    fs::create_dir_all(input_dir.join("a/b")).expect("create input dir");

    let mut f1 = fs::File::create(input_dir.join("root.txt")).expect("create root file");
    f1.write_all(b"hello root").expect("write root file");

    let mut f2 = fs::File::create(input_dir.join("a/b/nested.log")).expect("create nested file");
    f2.write_all(b"hello nested").expect("write nested file");

    engine::encrypt_folder(
        &input_dir,
        &encrypted_dir,
        "folder-password",
        engine::AeadAlgorithm::XChaCha20Poly1305,
    )
    .expect("encrypt folder");

    assert!(encrypted_dir.join("root.txt.svlt").exists());
    assert!(encrypted_dir.join("a/b/nested.log.svlt").exists());

    engine::decrypt_folder(
        &encrypted_dir,
        &decrypted_dir,
        "folder-password",
        engine::AeadAlgorithm::XChaCha20Poly1305,
    )
    .expect("decrypt folder");

    assert_eq!(
        fs::read(decrypted_dir.join("root.txt")).expect("read root"),
        b"hello root"
    );
    assert_eq!(
        fs::read(decrypted_dir.join("a/b/nested.log")).expect("read nested"),
        b"hello nested"
    );
}

#[test]
fn decrypt_folder_with_wrong_password_fails() {
    let temp = tempdir().expect("create temp dir");
    let input_dir = temp.path().join("plain");
    let encrypted_dir = temp.path().join("encrypted");
    let decrypted_dir = temp.path().join("decrypted");

    fs::create_dir_all(&input_dir).expect("create input dir");
    fs::write(input_dir.join("data.txt"), b"secret folder payload").expect("write data");

    engine::encrypt_folder(
        &input_dir,
        &encrypted_dir,
        "right-password",
        engine::AeadAlgorithm::Aes256Gcm,
    )
    .expect("encrypt folder");

    let result = engine::decrypt_folder(
        &encrypted_dir,
        &decrypted_dir,
        "wrong-password",
        engine::AeadAlgorithm::Aes256Gcm,
    );

    assert!(result.is_err(), "expected wrong password to fail");
}

#[test]
fn folder_roundtrip_preserves_trailing_svlt_file_names() {
    let temp = tempdir().expect("create temp dir");
    let input_dir = temp.path().join("plain");
    let encrypted_dir = temp.path().join("encrypted");
    let decrypted_dir = temp.path().join("decrypted");

    fs::create_dir_all(&input_dir).expect("create input dir");
    fs::write(input_dir.join("report"), b"plain report").expect("write report");
    fs::write(
        input_dir.join("report.svlt"),
        b"report that already ends with svlt",
    )
    .expect("write report.svlt");

    engine::encrypt_folder(
        &input_dir,
        &encrypted_dir,
        "folder-password",
        engine::AeadAlgorithm::XChaCha20Poly1305,
    )
    .expect("encrypt folder");

    engine::decrypt_folder(
        &encrypted_dir,
        &decrypted_dir,
        "folder-password",
        engine::AeadAlgorithm::XChaCha20Poly1305,
    )
    .expect("decrypt folder");

    assert_eq!(
        fs::read(decrypted_dir.join("report")).expect("read report"),
        b"plain report"
    );
    assert_eq!(
        fs::read(decrypted_dir.join("report.svlt")).expect("read report.svlt"),
        b"report that already ends with svlt"
    );
}

#[cfg(unix)]
#[test]
fn folder_roundtrip_supports_non_utf8_file_names() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let temp = tempdir().expect("create temp dir");
    let input_dir = temp.path().join("plain");
    let encrypted_dir = temp.path().join("encrypted");
    let decrypted_dir = temp.path().join("decrypted");

    fs::create_dir_all(&input_dir).expect("create input dir");

    let original_name = OsString::from_vec(vec![0x66, 0x6f, 0x80, 0x2e, 0x73, 0x76, 0x6c, 0x74]);
    let plain_path = input_dir.join(&original_name);
    fs::write(&plain_path, b"non-utf8 name payload").expect("write non-utf8 file");

    engine::encrypt_folder(
        &input_dir,
        &encrypted_dir,
        "folder-password",
        engine::AeadAlgorithm::Aes256Gcm,
    )
    .expect("encrypt folder");

    engine::decrypt_folder(
        &encrypted_dir,
        &decrypted_dir,
        "folder-password",
        engine::AeadAlgorithm::Aes256Gcm,
    )
    .expect("decrypt folder");

    let decrypted_path = decrypted_dir.join(&original_name);
    assert!(decrypted_path.exists(), "decrypted non-utf8 path should exist");
    assert_eq!(
        fs::read(decrypted_path).expect("read non-utf8 file"),
        b"non-utf8 name payload"
    );
}