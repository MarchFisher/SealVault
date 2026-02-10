use std::fs;
use std::io::Write;

use tempfile::tempdir;

#[test]
fn encrypt_decrypt_roundtrip() {
    // 验证默认模式（XChaCha20-Poly1305）加密后再解密能够恢复原始内容。
    let temp_dir = tempdir().expect("create temp dir");
    let input_path = temp_dir.path().join("input.txt");
    let encrypted_path = temp_dir.path().join("output.svlt");
    let decrypted_path = temp_dir.path().join("decrypted.txt");

    let plaintext = b"sealvault test payload";
    {
        let mut input_file = fs::File::create(&input_path).expect("create input");
        input_file.write_all(plaintext).expect("write plaintext");
    }

    engine::encrypt(&input_path, &encrypted_path, "test-password").expect("encrypt file");
    engine::decrypt(&encrypted_path, &decrypted_path, "test-password").expect("decrypt file");

    let decrypted = fs::read(&decrypted_path).expect("read decrypted");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypt_decrypt_roundtrip_with_aes_256_gcm() {
    // 验证 AES-256-GCM 模式也能完成端到端 round-trip。
    let temp_dir = tempdir().expect("create temp dir");
    let input_path = temp_dir.path().join("input.txt");
    let encrypted_path = temp_dir.path().join("output_aes.svlt");
    let decrypted_path = temp_dir.path().join("decrypted.txt");

    let plaintext = b"sealvault aes mode payload";
    {
        let mut input_file = fs::File::create(&input_path).expect("create input");
        input_file.write_all(plaintext).expect("write plaintext");
    }

    engine::encrypt_with_algorithm(
        &input_path,
        &encrypted_path,
        "test-password",
        engine::AeadAlgorithm::Aes256Gcm,
    )
    .expect("encrypt file with aes");

    engine::decrypt(&encrypted_path, &decrypted_path, "test-password").expect("decrypt file");

    let decrypted = fs::read(&decrypted_path).expect("read decrypted");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn decrypt_with_wrong_password_fails() {
    // 错误密码必须导致认证失败并返回错误。
    let temp_dir = tempdir().expect("create temp dir");
    let input_path = temp_dir.path().join("input.txt");
    let encrypted_path = temp_dir.path().join("output.svlt");
    let decrypted_path = temp_dir.path().join("decrypted.txt");

    {
        let mut input_file = fs::File::create(&input_path).expect("create input");
        input_file
            .write_all(b"sealvault auth fail")
            .expect("write plaintext");
    }

    engine::encrypt(&input_path, &encrypted_path, "correct-password").expect("encrypt file");

    let result = engine::decrypt(&encrypted_path, &decrypted_path, "wrong-password");
    assert!(result.is_err(), "expected decrypt to fail");
}

#[test]
fn decrypt_rejects_invalid_header_magic() {
    // Header magic 不匹配时应立即拒绝解析。
    let temp_dir = tempdir().expect("create temp dir");
    let bad_path = temp_dir.path().join("bad.svlt");
    let output_path = temp_dir.path().join("output.txt");

    fs::write(&bad_path, b"not a sealvault file").expect("write bad file");

    let result = engine::decrypt(&bad_path, &output_path, "password");
    assert!(result.is_err(), "expected invalid header");
}
